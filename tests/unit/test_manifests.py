from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from shadowscan.connectors.code.manifests import (
    _LineIndex,
    is_manifest_name,
    manifest_comment_projection,
    parse_manifest,
    parse_requirements,
)
from shadowscan.signatures import SignatureIndex
from shadowscan.signatures import matcher as matcher_module
from shadowscan.signatures.loader import signature_from_dict
from shadowscan.signatures.matcher import MatchTimeoutError


def _deps(rel, text):
    res = parse_manifest(rel, text)
    assert res is not None
    return {(d.ecosystem, d.name) for d in res.deps}, res


def test_requirements_and_pyproject():
    deps, _ = _deps(
        "requirements.txt",
        "langchain>=0.3 # core\nlangchain-openai\n-r base.txt\ngit+https://github.com/openai/swarm.git#egg=swarm\ncrewai[tools]==0.80\n",
    )
    assert ("pypi", "langchain") in deps and ("pypi", "swarm") in deps and ("pypi", "crewai") in deps
    deps, _ = _deps(
        "pyproject.toml",
        '[project]\ndependencies=["google-adk>=1.0", "mcp"]\n[project.optional-dependencies]\ndev=["pytest"]\n[tool.poetry.dependencies]\npython="^3.11"\nstrands-agents="*"\n',
    )
    assert {("pypi", "google-adk"), ("pypi", "mcp"), ("pypi", "strands-agents")} <= deps


def test_package_json_go_cargo_maven_gradle_nuget():
    deps, _ = _deps(
        "package.json",
        '{"dependencies": {"@langchain/langgraph": "^0.2", "ai": "4"}, "devDependencies": {"typescript": "5"}, "scripts": {"mcp": "npx -y @modelcontextprotocol/server-filesystem ."}}',
    )
    assert {
        ("npm", "@langchain/langgraph"),
        ("npm", "ai"),
        ("npm", "@modelcontextprotocol/server-filesystem"),
    } <= deps
    deps, _ = _deps(
        "go.mod",
        "module x\nrequire (\n\tgithub.com/mark3labs/mcp-go v0.8.0\n)\nrequire github.com/tmc/langchaingo v0.1.12\n",
    )
    assert {("go", "github.com/mark3labs/mcp-go"), ("go", "github.com/tmc/langchaingo")} <= deps
    deps, _ = _deps(
        "Cargo.toml", '[dependencies]\nrig-core = "0.5"\ntokio = { version = "1", features = ["full"] }\n'
    )
    assert ("cargo", "rig-core") in deps
    deps, _ = _deps(
        "pom.xml",
        "<project><dependencies><dependency><groupId>dev.langchain4j</groupId><artifactId>langchain4j</artifactId><version>1.0</version></dependency></dependencies></project>",
    )
    assert ("maven", "dev.langchain4j:langchain4j") in deps
    deps, _ = _deps(
        "build.gradle.kts",
        'dependencies {\n    implementation("org.springframework.ai:spring-ai-openai-spring-boot-starter:1.0.0")\n}\n',
    )
    assert ("maven", "org.springframework.ai:spring-ai-openai-spring-boot-starter") in deps
    deps, _ = _deps(
        "Agent.csproj",
        '<Project><ItemGroup><PackageReference Include="Microsoft.Agents.AI" Version="1.0.0" /></ItemGroup></Project>',
    )
    assert ("nuget", "Microsoft.Agents.AI") in deps


@pytest.mark.parametrize(
    "section, dev",
    [
        ("dependencies", False),
        ("devDependencies", True),
        ("peerDependencies", False),
        ("optionalDependencies", False),
    ],
)
@pytest.mark.parametrize(
    "spec, target",
    [
        ("npm:@langchain/langgraph@^1.0", "@langchain/langgraph"),
        ("npm:@langchain/langgraph", "@langchain/langgraph"),
        ("npm:langchain@>=0.3 <1", "langchain"),
        ("npm:langchain", "langchain"),
        ("npm:lodash@latest", "lodash"),
        ("NPM:@langchain/langgraph@^1.0", "@langchain/langgraph"),
        ("npm:@_scope/foo@1", "@_scope/foo"),
        ("npm:@.scope/foo@1", "@.scope/foo"),
        ("npm:@scope/-foo@1", "@scope/-foo"),
        ("npm:foo!@1", "foo!"),
        ("npm:foo(bar)@1", "foo(bar)"),
    ],
)
def test_npm_alias_dependency_uses_target_identity(section, dev, spec, target):
    alias = "@langchain/langgraph" if target == "lodash" else "workflow-runtime"
    _, result = _deps("package.json", json.dumps({section: {alias: spec}}))
    assert not result.errors
    assert [(dep.ecosystem, dep.name, dep.spec, dep.dev) for dep in result.deps] == [
        ("npm", target, spec, dev)
    ]


@pytest.mark.parametrize(
    "spec",
    [
        "npm:",
        "npm:@scope",
        "npm:@scope/",
        "npm:../langchain",
        "npm:langchain/extra",
        "npm:@scope/.foo",
        "npm:_foo",
        "npm:-foo",
    ],
)
def test_malformed_npm_alias_does_not_fall_back_to_alias_name(spec):
    deps, result = _deps(
        "package.json", json.dumps({"dependencies": {"@langchain/langgraph": spec, "openai": "^4"}})
    )
    assert deps == {("npm", "openai")}
    assert result.errors == ["dependencies dependency has an invalid npm alias target"]


@pytest.mark.parametrize(
    "spec", ["^1.0", "workspace:*", "file:../runtime", "https://example.test/runtime.tgz"]
)
def test_non_alias_npm_dependencies_keep_declared_names(spec):
    deps, result = _deps("package.json", json.dumps({"dependencies": {"langchain": spec}}))
    assert deps == {("npm", "langchain")}
    assert not result.errors


def test_dockerfile_compose_and_terraform_artifacts():
    deps, res = _deps(
        "Dockerfile",
        "FROM ghcr.io/berriai/litellm:main\nENV OPENAI_API_KEY=x ANTHROPIC_API_KEY=y\nRUN pip install langchain openai && npm install -g @anthropic-ai/claude-code\n",
    )
    arts = {(a.kind, a.value) for a in res.artifacts}
    assert ("image", "ghcr.io/berriai/litellm:main") in arts and ("env", "OPENAI_API_KEY") in arts
    assert {("pypi", "langchain"), ("pypi", "openai"), ("npm", "@anthropic-ai/claude-code")} <= deps
    _, res = _deps(
        "docker-compose.yml",
        "services:\n  n8n:\n    image: n8nio/n8n\n    environment:\n      - N8N_API_KEY=abc\n",
    )
    arts = {(a.kind, a.value) for a in res.artifacts}
    assert ("image", "n8nio/n8n") in arts and ("env", "N8N_API_KEY") in arts
    _, res = _deps(
        "main.tf",
        'resource "aws_bedrockagent_agent" "ops" {\n  agent_name = "ops-provisioning-04"\n}\nresource "aws_s3_bucket" "b" {}\n',
    )
    iac = [a for a in res.artifacts if a.kind == "iac"]
    assert iac[0].value == "aws_bedrockagent_agent" and iac[0].extra["display_name"] == "ops-provisioning-04"


def test_env_file_and_cloudformation():
    _, res = _deps(".env", "OPENAI_API_KEY=sk-live\n# comment\nexport GEMINI_API_KEY='x'\n")
    names = {a.value for a in res.artifacts}
    assert {"OPENAI_API_KEY", "GEMINI_API_KEY"} <= names
    _, res = _deps(
        "template.yaml",
        "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  Agent:\n    Type: AWS::Bedrock::Agent\n",
    )
    assert ("iac", "AWS::Bedrock::Agent") in {(a.kind, a.value) for a in res.artifacts}


def _cfn_json(include_version: bool) -> str:
    template: dict = {
        "Metadata": {"notes": "x" * 8000},  # pushes any version key past a byte-prefix window
        "Parameters": {f"p{i}": {"Type": "String"} for i in range(50)},
        "Resources": {"Agent": {"Type": "AWS::Bedrock::Agent", "Properties": {"AgentName": "ops"}}},
    }
    if include_version:
        template = {"AWSTemplateFormatVersion": "2010-09-09", **template}
    # Real templates are pretty-printed; indent keeps "Type" at a line start for extraction
    # while the Metadata block still pushes any version key well past the old 4000-byte window.
    return json.dumps(template, indent=2)


@pytest.mark.parametrize("include_version", [True, False])
def test_cloudformation_json_is_recognized_from_its_structure(include_version):
    """Regression (October 15 review M3): .json CloudFormation was sniffed from text[:4000], so a
    leading Metadata/Parameters block (or an omitted optional version) hid AWS resources."""
    text = _cfn_json(include_version)
    result = parse_manifest("template.json", text, document=json.loads(text))
    assert result is not None
    assert ("iac", "AWS::Bedrock::Agent") in {(a.kind, a.value) for a in result.artifacts}


def test_arm_json_is_recognized_from_its_schema():
    text = json.dumps(
        {
            "Metadata": {"notes": "x" * 8000},
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "resources": [{"type": "Microsoft.MachineLearningServices/workspaces", "name": "ml"}],
        },
        indent=2,
    )
    result = parse_manifest("main.json", text, document=json.loads(text))
    assert result is not None and any(a.kind == "iac" for a in result.artifacts)


def test_ordinary_json_with_a_resources_key_is_not_cloudformation():
    text = json.dumps({"Resources": {"team": {"Type": "internal", "members": 3}}})
    assert parse_manifest("data.json", text, document=json.loads(text)) is None


def test_non_manifest_returns_none():
    assert parse_manifest("src/app.py", "print('hi')") is None


def test_parallel_manifest_parsing_preserves_all_artifacts():
    compose = "services:\n" + "".join(
        f"  agent{i}:\n    image: ghcr.io/acme/agent:1\n    environment:\n      OPENAI_API_KEY: placeholder\n"
        for i in range(100)
    )
    terraform = "\n".join(
        f'resource "aws_bedrockagent_agent" "agent{i}" {{\n  agent_name = "agent{i}"\n}}' for i in range(100)
    )
    jobs = [("compose.yaml", compose), ("main.tf", terraform)] * 18

    def scan(job):
        result = parse_manifest(*job)
        assert result is not None and not result.errors
        return [
            (artifact.kind, artifact.value, artifact.line, artifact.extra) for artifact in result.artifacts
        ]

    expected = [scan(job) for job in jobs[:2]]
    assert len(expected[0]) == 200 and len(expected[1]) == 100
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(scan, jobs))
    assert results == expected * 18


def test_yaml_artifacts_keep_source_lines_across_chunks():
    lines = ["services:"] + [f"  padding{i}: # {'x' * 55}" for i in range(120)]
    lines += [
        "  -",
        "    OPENAI_API_KEY: example",
        "    image: ghcr.io/acme/agent:1",
        "    uses: actions/checkout@v4",
        "    token: ${{ secrets.CI_TOKEN }}",
    ]
    result = parse_manifest("compose.yaml", "\n".join(lines) + "\n")
    assert result is not None and not result.errors
    assert {(artifact.kind, artifact.value, artifact.line) for artifact in result.artifacts} == {
        ("env", "OPENAI_API_KEY", 123),
        ("image", "ghcr.io/acme/agent:1", 124),
        ("action", "actions/checkout@v4", 125),
        ("secret_ref", "CI_TOKEN", 126),
    }


def _index(pattern="token"):
    return SignatureIndex(
        [
            signature_from_dict(
                {
                    "id": "custom.test",
                    "category": "framework",
                    "signals": [{"type": "code", "patterns": [pattern]}],
                }
            )
        ]
    )


def test_manifest_regex_respects_outer_input_deadline(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(matcher_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(matcher_module.time, "thread_time", lambda: clock[0])
    with pytest.raises(MatchTimeoutError, match="input execution budget"), _index().scan_budget(seconds=0.1):
        clock[0] = 0.2
        parse_manifest("Dockerfile", "FROM python:3.12\n")


@pytest.mark.parametrize("offset, expected", [(0, 1), (1, 1), (2, 2), (3, 2), (4, 3)])
def test_manifest_line_index_matches_original_source_offsets(offset, expected):
    assert _LineIndex("a\nb\nc").at(offset) == expected


def test_vcs_egg_fragments_and_editable_dependencies():
    result = parse_requirements(
        "git+https://github.com/acme/other.git#egg=crewai\n"
        "-e git+https://github.com/acme/other.git@main#egg=langgraph\n"
        "langchain>=0.3 # explanatory comment\n"
    )
    assert {(dep.name, dep.line) for dep in result.deps} == {
        ("crewai", 1),
        ("langgraph", 2),
        ("langchain", 3),
    }


@pytest.mark.parametrize(
    "rel",
    [
        "Directory.Build.props",
        "Directory.Build.targets",
        "Directory.Packages.props",
        "eng/common.props",
        "eng/Versions.PROPS",
        "src/App/Shared.targets",
    ],
)
def test_msbuild_props_and_targets_are_nuget_manifests(rel):
    name = rel.rsplit("/", 1)[-1]
    assert is_manifest_name(name)
    deps, result = _deps(
        rel,
        '<Project><ItemGroup><PackageReference Include="Microsoft.SemanticKernel" Version="1.0.0" />'
        '<PackageVersion Include="ModelContextProtocol" Version="0.2" /></ItemGroup></Project>',
    )
    assert deps == {("nuget", "Microsoft.SemanticKernel"), ("nuget", "ModelContextProtocol")}
    assert not result.errors


def test_central_package_management_props_declare_nuget_dependencies(fixtures):
    # Directory.Packages.props keeps the versions (PackageVersion), a shared
    # Directory.Build.props pins packages every project gets
    # (GlobalPackageReference) or overrides (PackageReference Update=...); a
    # project file referencing them carries no version of its own.
    root = fixtures / "code" / "dotnet_central"
    deps, result = _deps("Directory.Packages.props", (root / "Directory.Packages.props").read_text())
    assert not result.errors
    assert deps == {
        ("nuget", "Microsoft.Extensions.AI"),
        ("nuget", "OllamaSharp"),
        ("nuget", "Newtonsoft.Json"),
    }
    deps, result = _deps("Directory.Build.props", (root / "Directory.Build.props").read_text())
    assert not result.errors
    assert deps == {
        ("nuget", "Microsoft.SourceLink.GitHub"),
        ("nuget", "ModelContextProtocol"),
        ("nuget", "Microsoft.Extensions.AI.Ollama"),
    }
    versions = {d.name: d.spec for d in result.deps}
    assert versions["Microsoft.Extensions.AI.Ollama"] == "9.3.0-preview.1.25161.3"


def test_central_package_management_establishes_the_project_technologies(fixtures, run_connector):
    findings, ctx = run_connector(
        "code.filesystem", path=str(fixtures / "code" / "dotnet_central"), use_git=False
    )
    assert not ctx.stats.errors and not ctx.stats.incomplete
    project = next(f for f in findings if f.resource_type == "project")
    assert {"framework.microsoft-extensions-ai", "protocol.mcp"} <= set(project.frameworks)
    assert "provider.ollama" in project.model_providers
    assert "nuget:OllamaSharp" in project.metadata["dependencies_matched"]


@pytest.mark.parametrize("name", ["Directory.Build.targets", "common.props"])
def test_msbuild_entity_declarations_are_rejected_not_expanded(name):
    bomb = (
        '<!DOCTYPE lolz [<!ENTITY lol0 "lol"><!ENTITY lol1 "&lol0;&lol0;&lol0;&lol0;&lol0;&lol0;&lol0;">]>'
        '<Project><ItemGroup><PackageReference Include="&lol1;" /></ItemGroup></Project>'
    )
    result = parse_manifest(name, bomb)
    assert result is not None and result.deps == []
    assert result.errors == ["NuGet DTD/entity declarations are unsupported"]


@pytest.mark.parametrize(
    "reference",
    [
        "openai-agents @ https://example.org/distributions/agents-0.1.0.tar.gz",
        "openai-agents[voice] @ https://example.org/downloads/other.whl#sha256=abc123",
        "openai-agents @ git+https://github.com/example/other.git@main#subdirectory=python",
        "openai-agents @ file:///opt/packages/other.whl",
    ],
)
def test_named_requirement_urls_preserve_declared_identity(reference):
    result = parse_requirements("# installation\n" + reference + "\n")
    assert not result.errors
    assert [(dep.ecosystem, dep.name, dep.spec, dep.line) for dep in result.deps] == [
        ("pypi", "openai-agents", reference, 2)
    ]


def test_gradle_comments_and_example_strings_do_not_declare_dependencies():
    text = (
        '// implementation "dev.langchain4j:langchain4j:1.0.0"\n'
        '/* implementation("dev.langchain4j:langchain4j:1.0.0")\n'
        '   platform("dev.langchain4j:langchain4j-bom:1.0.0") */\n'
        "def example = '''implementation \"dev.langchain4j:langchain4j:1.0.0\"\n"
        "// this is still inside the example'''\n"
        'def mirror = "https://example.invalid/maven"; '
        'implementation /* comment */ ("org.springframework.ai:spring-ai-core:1.0.0")\n'
        'testImplementation("dev.langchain4j:langchain4j:1.0.0") // active dependency\n'
    )
    deps, result = _deps("build.gradle", text)
    assert not result.errors
    assert deps == {
        ("maven", "org.springframework.ai:spring-ai-core"),
        ("maven", "dev.langchain4j:langchain4j"),
    }
    assert [(dep.line, dep.dev) for dep in result.deps] == [(6, False), (7, True)]


def test_gradle_dollar_slashy_string_preserves_following_dependencies():
    deps, result = _deps(
        "build.gradle",
        "def mirror = $/https://example.invalid/maven/$; "
        'implementation("dev.langchain4j:langchain4j:1.0.0")\n',
    )
    assert not result.errors
    assert deps == {("maven", "dev.langchain4j:langchain4j")}


@pytest.mark.parametrize(
    "filename, example",
    [
        ("build.gradle", "def example = /it's/\n"),
        ("build.gradle", "def pattern = /https?:\\/\\/example/\n"),
        ("build.gradle.kts", 'val path = """C:\\"""\n'),
    ],
)
def test_gradle_raw_string_delimiters_do_not_consume_following_declarations(filename, example):
    deps, result = _deps(
        filename,
        example + 'dependencies { implementation("dev.langchain4j:langchain4j:1.0.0") }\n',
    )
    assert not result.errors
    assert deps == {("maven", "dev.langchain4j:langchain4j")}
    assert result.deps[0].line == 2


def test_kotlin_nested_comments_do_not_hide_following_dependencies():
    deps, result = _deps(
        "build.gradle.kts",
        '/* outer /* nested */ implementation("dev.langchain4j:langchain4j:1.0.0") */\n'
        'implementation("org.springframework.ai:spring-ai-core:1.0.0")\n',
    )
    assert not result.errors
    assert deps == {("maven", "org.springframework.ai:spring-ai-core")}
    assert result.deps[0].line == 2


def test_unterminated_gradle_comment_reports_incomplete_parsing():
    deps, result = _deps("build.gradle", '/* implementation("dev.langchain4j:langchain4j:1.0.0")\n')
    assert not deps
    assert result.errors == ["unterminated Gradle comment or string"]


def test_docker_comments_preserve_real_commands_quoted_hashes_and_source_lines():
    deps, result = _deps(
        "Dockerfile",
        "# pip install openai-agents\n"
        "FROM python:3.12\n"
        "RUN pip install langgraph # pip install crewai\n"
        'RUN echo "https://example.invalid/#fragment" && npm install @langchain/langgraph '
        "# npm install ai\n"
        "RUN echo \\# && uv pip install mcp\n",
    )
    assert not result.errors
    assert deps == {("pypi", "langgraph"), ("npm", "@langchain/langgraph"), ("pypi", "mcp")}
    assert {(dep.name, dep.line) for dep in result.deps} == {
        ("langgraph", 3),
        ("@langchain/langgraph", 4),
        ("mcp", 5),
    }


@pytest.mark.parametrize(
    "instruction",
    [
        "ENV NOTE literal # OPENAI_API_KEY",
        "ARG NOTE=literal # OPENAI_API_KEY",
        'LABEL note="literal" # OPENAI_API_KEY',
        "COPY files/#fragment /app/",
        'RUN ["echo", "literal # OPENAI_API_KEY"]',
        'RUN --mount=type=cache,target=/tmp ["echo", "literal # OPENAI_API_KEY"]',
        'CMD ["echo", "literal # OPENAI_API_KEY"]',
        'ENTRYPOINT ["echo", "literal # OPENAI_API_KEY"]',
    ],
)
def test_docker_non_shell_hashes_are_literal_data(instruction):
    text = instruction + "\n"
    assert manifest_comment_projection("Dockerfile", text) == text


def test_docker_shell_projection_keeps_quoted_hash_and_masks_inline_comment():
    text = 'RUN echo "# literal" && pip install langgraph # pip install crewai\n'
    projected = manifest_comment_projection("Dockerfile", text)
    assert len(projected) == len(text) and projected.count("\n") == text.count("\n")
    assert 'echo "# literal"' in projected and "pip install langgraph" in projected
    assert "crewai" not in projected


@pytest.mark.parametrize("escape", ["\\", "`"])
def test_docker_continuations_and_intervening_comments(escape):
    deps, result = _deps(
        "Dockerfile",
        f"# escape={escape}\nFROM python:3.12\nRUN pip install {escape}\n"
        "    # pip install crewai\n    openai-agents\n",
    )
    assert not result.errors
    assert deps == {("pypi", "openai-agents")}
    assert result.deps[0].line == 3


@pytest.mark.parametrize("escape", ["\\", "`"])
def test_docker_continuation_is_joined_before_shell_comment_detection(escape, tmp_path, run_connector):
    prefix = f"# escape={escape}\nFROM python:3.12\n"
    disabled = prefix + f"RUN echo ready # disabled install {escape}\n    pip install langgraph\n"
    active = prefix + f"RUN echo ready && {escape}\n    pip install langgraph\n"
    path = tmp_path / "Dockerfile"
    for text, expected in ((disabled, False), (active, True)):
        deps, result = _deps("Dockerfile", text)
        assert not result.errors
        assert deps == ({("pypi", "langgraph")} if expected else set())
        projection = manifest_comment_projection("Dockerfile", text)
        assert len(projection) == len(text) and projection.count("\n") == text.count("\n")
        assert ("pip install langgraph" in projection) == expected
        path.write_text(text)
        findings, ctx = run_connector("code.filesystem", path=str(tmp_path))
        assert ctx.stats is not None and not ctx.stats.incomplete
        assert bool(findings) == expected


@pytest.mark.parametrize(
    "header",
    [
        "# build image for the support bot\n# escape=`\n",
        "\n# escape=`\n",
        "# syntax=docker/dockerfile:1\n# unknown=value\n# escape=`\n",
        "FROM scratch AS base\n# escape=`\n",
    ],
    ids=["after-comment", "after-blank-line", "after-unknown-directive", "after-instruction"],
)
def test_docker_escape_directive_is_read_only_from_the_leading_directives(header, tmp_path, run_connector):
    # BuildKit stops reading parser directives at the first line that is not a
    # known directive. A later "# escape=`" is a plain comment, so a trailing
    # backtick continues nothing and the next RUN runs; it used to be joined
    # into the shell comment before it and masked.
    text = (
        header + "FROM python:3.12-slim\nRUN apt-get update # refresh `\n"
        "RUN pip install langchain-openai crewai\n"
    )
    deps, result = _deps("Dockerfile", text)
    assert not result.errors
    assert {("pypi", "langchain-openai"), ("pypi", "crewai")} <= deps
    assert "RUN pip install langchain-openai crewai" in manifest_comment_projection("Dockerfile", text)
    (tmp_path / "Dockerfile").write_text(text)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path))
    assert ctx.stats is not None and not ctx.stats.incomplete
    assert {"framework.crewai", "framework.langchain"} <= {fw for f in findings for fw in f.frameworks}


@pytest.mark.parametrize(
    "directive", ["# escape=`", "#escape=`", "#  ESCAPE = ` ", "\t# escape=`", "# syntax=x\n# escape=`"]
)
def test_docker_escape_directive_spellings_are_honoured(directive):
    deps, _ = _deps("Dockerfile", f"{directive}\nFROM python:3.12\nRUN pip install `\n    openai-agents\n")
    assert deps == {("pypi", "openai-agents")}


@pytest.mark.parametrize(
    "filename, declaration, signature",
    [
        (
            "requirements.txt",
            "openai-agents @ https://example.org/distributions/agents-0.1.0.tar.gz",
            "framework.openai-agents-sdk",
        ),
        ("build.gradle", 'implementation "dev.langchain4j:langchain4j:1.0.0"', "framework.langchain4j"),
        ("Dockerfile", "RUN pip install openai-agents", "framework.openai-agents-sdk"),
    ],
)
def test_comment_and_active_dependency_discovery_pair(
    tmp_path, run_connector, filename, declaration, signature
):
    path = tmp_path / filename
    comment = "// " if filename.endswith(".gradle") else "# "
    path.write_text(comment + declaration + "\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path))
    assert not findings and ctx.stats is not None and not ctx.stats.incomplete
    path.write_text(declaration + "\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path))
    assert ctx.stats is not None and not ctx.stats.incomplete
    assert len(findings) == 1 and findings[0].frameworks == [signature]


def test_containerfile_is_parsed_like_a_dockerfile():
    text = "FROM ghcr.io/berriai/litellm:main-latest\nENV OPENAI_API_KEY=\n"
    assert is_manifest_name("Containerfile")
    assert [(a.kind, a.value) for a in parse_manifest("Containerfile", text).artifacts] == [
        (a.kind, a.value) for a in parse_manifest("Dockerfile", text).artifacts
    ]


def test_manifest_line_index_and_dockerfile_dedupe():
    result = parse_manifest("Dockerfile", "FROM python:3.12\nENV OPENAI_API_KEY=\nENV AA=1 BB=2\n")
    assert result is not None
    env = [(a.value, a.line) for a in result.artifacts if a.kind == "env"]
    assert env == [("OPENAI_API_KEY", 2), ("AA", 3), ("BB", 3)]
    values = "".join(f"APP_SETTING_{i}: value\n" for i in range(4000))
    started = time.monotonic()
    result = parse_manifest("values.yaml", values)
    assert time.monotonic() - started < 5
    assert result is not None and not result.errors
    env = [a for a in result.artifacts if a.kind == "env"]
    assert len(env) == 4000 and env[-1].line == 4000


def test_shared_document_equals_a_fresh_parse_and_is_refused_for_jsonc(tmp_path, run_connector):
    from shadowscan.utils.jsonc import load_json_lenient_marked

    text = json.dumps({"dependencies": {"openai": "^4.0.0"}, "scripts": {"mcp": "npx -y @scope/server"}})
    document, strict = load_json_lenient_marked(text)
    assert strict
    for name in ("package.json", "composer.json"):
        assert parse_manifest(name, text, document) == parse_manifest(name, text)
    # Comments are tolerated by the shared parse but not by the manifest
    # parser: the connector never hands such a document over.
    commented = "// generated\n" + text
    assert load_json_lenient_marked(commented) == (document, False)
    assert parse_manifest("package.json", commented).errors == ["invalid JSON"]
    (tmp_path / "package.json").write_text(commented)
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    # An input defect: reported per file and the scan stays incomplete (exit 3).
    assert not ctx.stats.errors
    assert ctx.stats.warnings == ["code.filesystem: package.json: input defect: invalid JSON"]
    assert ctx.stats.incomplete


@pytest.mark.parametrize("name", ["uv.lock", "poetry.lock", "pnpm-lock.yaml", "Cargo.lock"])
def test_lockfile_inventory_fixtures(name):
    from pathlib import Path

    source = Path("tests/fixtures/code/lockfiles") / name
    result = parse_manifest(name, source.read_text())
    assert result and not result.errors and result.lockfile
    assert is_manifest_name(name)
    inventory = result.lockfile
    packages = {p.name: p for p in inventory.packages}
    if name == "uv.lock":
        assert packages["wrapper"].relationship == "direct"
        assert packages["crewai"].relationship == "transitive"
        assert inventory.roots_known
    elif name == "pnpm-lock.yaml":
        assert packages["@langchain/langgraph"].relationship == "transitive"
    else:
        assert all(p.relationship == "unknown" for p in inventory.packages)
    assert all("http" not in p.source for p in inventory.packages)


def _lockfile_reasons():
    """Every fixed LockfileError reason in lockfiles.py."""
    import re
    from pathlib import Path

    source = Path("shadowscan/connectors/code/lockfiles.py").read_text()
    return frozenset(re.findall(r'LockfileError\("([^"]+)"\)', source))


_LOCKFILE_REASONS = _lockfile_reasons()


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("uv.lock", "version = true"),
        ("uv.lock", "version = 999"),
        ("uv.lock", "version = 1\npackage = {}"),
        ("uv.lock", "version = 1\npackage = [42]"),
        ("uv.lock", 'version = 1\n[[package]]\nname="example"\nversion="1"\ndependencies=[42]'),
        ("uv.lock", 'version = 1\n[[package]]\nname="example"\nversion="https://example.invalid"'),
        ("Cargo.lock", "version = 2"),
        ("Cargo.lock", "version = 3.0"),
        ("poetry.lock", '[metadata]\nlock-version="99"'),
        ("pnpm-lock.yaml", "lockfileVersion: 5.4"),
        ("pnpm-lock.yaml", "lockfileVersion: 9.0\npackages: []"),
        ("pnpm-lock.yaml", "lockfileVersion: 9.0\npackages: {invalid: {}}"),
        (
            "pnpm-lock.yaml",
            "lockfileVersion: 9.0\npackages: {x@1: {}}\nsnapshots: {x@1: {dependencies: {y: 2}}}",
        ),
        ("pnpm-lock.yaml", "lockfileVersion: 9.0\nimporters: {.: {dependencies: {x: {version: 1}}}}"),
        ("pnpm-lock.yaml", "lockfileVersion: 9.0\nlockfileVersion: 9.0"),
    ],
)
def test_malformed_or_unsupported_lockfiles_are_explicit(name, text):
    from shadowscan.connectors.code import lockfiles

    result = parse_manifest(name, text)
    assert result is not None and result.lockfile is None and not result.deps
    # A fixed reason from lockfiles.py; the filesystem connector scopes it.
    assert result.lockfile_issue
    assert result.lockfile_issue == lockfiles._MALFORMED or result.lockfile_issue in _LOCKFILE_REASONS


def test_lockfile_cycles_ambiguous_versions_and_aliases():
    from shadowscan.connectors.code.lockfiles import parse_lockfile

    text = """version = 1
[[package]]
name = "root"
version = "1"
source = {editable = "."}
dependencies = [{name="crewai"}]
[[package]]
name = "crewai"
version = "1"
dependencies = [{name="root"}]
[[package]]
name = "crewai"
version = "2"
"""
    result = parse_lockfile("uv.lock", text)
    assert all(p.relationship == "unknown" for p in result.packages)
    text = """lockfileVersion: '6.0'
dependencies:
  agent-alias: {specifier: 'npm:crewai@1.0', version: 'crewai@1.0'}
  local: {specifier: 'workspace:*', version: 'link:../local'}
packages:
  /crewai@1.0:
    dependencies: {local: 'workspace:*', crewai: '1.0'}
"""
    result = parse_lockfile("pnpm-lock.yaml", text)
    assert result.packages[0].name == "crewai"
    assert result.packages[0].relationship == "direct"


def test_lockfile_parser_resource_limits(monkeypatch):
    from shadowscan.connectors.code import lockfiles

    with pytest.raises(ValueError, match="unsupported"):
        lockfiles.parse_lockfile("unknown.lock", "")
    with pytest.raises(ValueError, match="byte limit"):
        lockfiles.parse_lockfile("uv.lock", " " * (lockfiles.MAX_LOCKFILE_BYTES + 1))
    monkeypatch.setattr(lockfiles, "MAX_PACKAGES", 1)
    result = parse_manifest(
        "uv.lock", 'version=1\n[[package]]\nname="a"\nversion="1"\n[[package]]\nname="b"\nversion="1"'
    )
    assert result and result.lockfile_issue == "lockfile package limit exceeded"
    monkeypatch.setattr(lockfiles, "MAX_STRUCTURE_NODES", 2)
    result = parse_manifest("uv.lock", "version=1\npackage=[]")
    assert result and result.lockfile_issue == "lockfile structure limit exceeded"


@pytest.mark.parametrize(
    ("name", "text", "reason"),
    [
        ("uv.lock", "version = [", "lockfile is not valid TOML"),
        ("pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages: [unclosed", "lockfile is not valid YAML"),
        ("pnpm-lock.yaml", "a: &a [*a]", "lockfile YAML exceeds safety limits"),
        ("Cargo.lock", "version = 4\npackage = [" + "[" * 2000 + "]" * 2000 + "]", None),
        # Regression (#220 verifier): an integer past Python's digit limit was "not valid YAML".
        pytest.param(
            "uv.lock",
            "version = 1\nsize = " + "9" * 5000,
            "lockfile is not valid TOML",
            id="uv-integer-digits",
        ),
        pytest.param(
            "poetry.lock", "size = " + "9" * 5000, "lockfile is not valid TOML", id="poetry-integer-digits"
        ),
        pytest.param(
            "Cargo.lock", "version = " + "9" * 5000, "lockfile is not valid TOML", id="cargo-integer-digits"
        ),
    ],
)
def test_lockfile_parser_errors_become_fixed_reasons(name, text, reason):
    """Regression (#220 review F6): parser messages, which can quote input, are never passed on."""
    from shadowscan.connectors.code.lockfiles import LockfileError, parse_lockfile

    with pytest.raises(LockfileError) as raised:
        parse_lockfile(name, text)
    assert str(raised.value) in _LOCKFILE_REASONS | {"malformed lockfile content"}
    if reason is not None:
        assert str(raised.value) == reason


def test_pnpm_peer_snapshots_cannot_union_transitive_reachability():
    from shadowscan.connectors.code.lockfiles import parse_lockfile

    text = """lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      wrapper: {version: '1.0.0(peer@1.0.0)'}
packages:
  wrapper@1.0.0: {}
  '@langchain/langgraph@0.2.0': {}
snapshots:
  wrapper@1.0.0(peer@1.0.0): {}
  wrapper@1.0.0(peer@2.0.0):
    dependencies: {'@langchain/langgraph': 0.2.0}
  '@langchain/langgraph@0.2.0': {}
"""
    inventory = parse_lockfile("pnpm-lock.yaml", text)
    graph = next(p for p in inventory.packages if p.name == "@langchain/langgraph")
    assert graph.relationship == "unknown"


_PNPM_NON_REGISTRY = {
    "v9-codeload": """lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      is-positive:
        specifier: github:kevva/is-positive
        version: https://codeload.github.com/kevva/is-positive/tar.gz/97edff6f525f192a3f83cea1944765f769ae2678
      openai: {specifier: ^4.0.0, version: 4.0.0}
packages:
  is-positive@https://codeload.github.com/kevva/is-positive/tar.gz/97edff6f525f192a3f83cea1944765f769ae2678:
    resolution: {tarball: https://codeload.github.com/kevva/is-positive/tar.gz/97edff6f525f192a3f83cea1944765f769ae2678}
    version: 3.1.0
  openai@4.0.0:
    resolution: {integrity: sha512-x}
snapshots:
  is-positive@https://codeload.github.com/kevva/is-positive/tar.gz/97edff6f525f192a3f83cea1944765f769ae2678: {}
  openai@4.0.0: {}
""",
    "v9-git-ssh": """lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      helper: {specifier: 'git+ssh://git@github.com/example/helper.git', version: 'git+ssh://git@github.com/example/helper.git#abc123'}
      openai: {specifier: ^4.0.0, version: 4.0.0}
packages:
  helper@git+ssh://git@github.com/example/helper.git#abc123:
    resolution: {commit: abc123, repo: 'git@github.com:example/helper.git', type: git}
    version: 1.0.0
  openai@4.0.0:
    resolution: {integrity: sha512-x}
snapshots:
  helper@git+ssh://git@github.com/example/helper.git#abc123:
    dependencies: {openai: 4.0.0}
  openai@4.0.0: {}
""",
    "v9-tarball": """lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      helper: {specifier: 'https://example.invalid/helper-1.0.0.tgz', version: 'https://example.invalid/helper-1.0.0.tgz'}
      openai: {specifier: ^4.0.0, version: 4.0.0}
packages:
  helper@https://example.invalid/helper-1.0.0.tgz:
    resolution: {tarball: 'https://example.invalid/helper-1.0.0.tgz'}
    version: 1.0.0
  openai@4.0.0:
    resolution: {integrity: sha512-x}
snapshots:
  helper@https://example.invalid/helper-1.0.0.tgz: {}
  openai@4.0.0: {}
""",
    "v6-git": """lockfileVersion: '6.0'
dependencies:
  is-positive:
    specifier: github:kevva/is-positive
    version: github.com/kevva/is-positive/97edff6f525f192a3f83cea1944765f769ae2678
  openai: {specifier: ^4.0.0, version: 4.0.0}
packages:
  github.com/kevva/is-positive/97edff6f525f192a3f83cea1944765f769ae2678:
    resolution: {tarball: https://codeload.github.com/kevva/is-positive/tar.gz/97edff6f525f192a3f83cea1944765f769ae2678}
    name: is-positive
    version: 3.1.0
    dependencies: {openai: 4.0.0}
  /openai@4.0.0:
    resolution: {integrity: sha512-x}
""",
}


_PNPM_NON_REGISTRY_PACKAGE = {
    "v9-codeload": ("is-positive", "tarball"),
    "v9-git-ssh": ("helper", "git"),
    "v9-tarball": ("helper", "tarball"),
    "v6-git": ("is-positive", "tarball"),
}


@pytest.mark.parametrize("case", sorted(_PNPM_NON_REGISTRY))
def test_pnpm_git_and_tarball_entries_are_inventoried_by_name_not_fatal(case):
    """Regression (#220 verifier, security220-1): a git or tarball entry neither rejects the file nor vanishes."""
    from shadowscan.connectors.code.lockfiles import parse_lockfile

    inventory = parse_lockfile("pnpm-lock.yaml", _PNPM_NON_REGISTRY[case])
    packages = {(p.name, p.version): p for p in inventory.packages if not p.root}
    name, source = _PNPM_NON_REGISTRY_PACKAGE[case]
    assert set(packages) == {("openai", "4.0.0"), (name, None)}
    assert packages[("openai", "4.0.0")].relationship == "direct"
    # The source kind is kept, its URL is not, and its edges stay unresolved.
    assert packages[(name, None)].source == source
    assert packages[(name, None)].relationship == "unknown"
    assert any(
        "1 pnpm package(s) from git, tarball, URL or local sources are inventoried by name without a version"
        in item
        for item in inventory.limitations
    )
    assert "example.invalid" not in str(inventory) and "kevva" not in str(inventory)


_PNPM_SOURCE_ONLY_AI = """lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      openai:
        specifier: github:example/openai-node
        version: https://codeload.github.com/example/openai-node/tar.gz/0123456789abcdef0123456789abcdef01234567
      zod: {specifier: ^3.23.8, version: 3.23.8}
packages:
  openai@https://codeload.github.com/example/openai-node/tar.gz/0123456789abcdef0123456789abcdef01234567:
    resolution: {tarball: https://codeload.github.com/example/openai-node/tar.gz/0123456789abcdef0123456789abcdef01234567}
    version: 4.56.0
  zod@3.23.8:
    resolution: {integrity: sha512-x}
snapshots:
  openai@https://codeload.github.com/example/openai-node/tar.gz/0123456789abcdef0123456789abcdef01234567: {}
  zod@3.23.8: {}
"""

_PNPM_TRANSITIVE_SOURCE_AI = """lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      wrapper: {specifier: 1.0.0, version: 1.0.0}
packages:
  wrapper@1.0.0:
    resolution: {integrity: sha512-x}
  '@langchain/core@https://example.invalid/langchain-core-0.2.0.tgz':
    resolution: {tarball: 'https://example.invalid/langchain-core-0.2.0.tgz'}
    version: 0.2.0
snapshots:
  wrapper@1.0.0:
    dependencies:
      '@langchain/core': https://example.invalid/langchain-core-0.2.0.tgz
  '@langchain/core@https://example.invalid/langchain-core-0.2.0.tgz': {}
"""


def test_pnpm_ai_package_from_a_tarball_is_not_hidden_by_a_complete_scan(tmp_path, run_connector):
    """Regression (security220-1): the only AI package, locked from a tarball, left an empty complete scan."""
    (tmp_path / "pnpm-lock.yaml").write_text(_PNPM_SOURCE_ONLY_AI)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete and not ctx.stats.errors
    (finding,) = [f for f in findings if f.resource_type == "lockfile-inventory"]
    assert "provider.openai" in finding.frameworks
    inventory = finding.metadata["lockfile_inventory"]
    assert inventory["matched_packages"] == [
        {
            "ecosystem": "npm",
            "name": "openai",
            "version": None,
            "source_type": "tarball",
            "relationship": "unknown",
        }
    ]
    assert any("without a version" in item for item in inventory["limitations"])
    assert "codeload" not in str(finding.to_dict())


def test_pnpm_transitive_ai_package_from_a_tarball_is_inventoried(tmp_path, run_connector):
    """Regression (security220-1): a transitive AI package from a tarball vanished beside a non-AI manifest."""
    (tmp_path / "package.json").write_text('{"name": "app", "dependencies": {"wrapper": "1.0.0"}}')
    (tmp_path / "pnpm-lock.yaml").write_text(_PNPM_TRANSITIVE_SOURCE_AI)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete and not ctx.stats.errors
    (finding,) = [f for f in findings if f.resource_type == "lockfile-inventory"]
    (package,) = finding.metadata["lockfile_inventory"]["matched_packages"]
    assert (package["name"], package["version"], package["source_type"]) == (
        "@langchain/core",
        None,
        "tarball",
    )
    assert "example.invalid" not in str(finding.to_dict())


@pytest.mark.parametrize(
    ("key", "entry", "expected"),
    [
        # A v6 host-path key carries no name; pnpm records it in `name`.
        (
            "github.com/example/helper/abc123",
            "{name: openai, resolution: {type: git, repo: x}}",
            ("openai", "git"),
        ),
        ("'@example.invalid/helper-1.0.0.tgz'", "{name: '@langchain/core'}", ("@langchain/core", "url")),
        (
            "helper@file:../helper",
            "{resolution: {type: directory, directory: ../helper}}",
            ("helper", "local"),
        ),
        ("'@scope/pkg@git+https://example.invalid/pkg.git#abc'", "{}", ("@scope/pkg", "git")),
    ],
)
def test_pnpm_source_entry_names_come_from_the_key_or_the_name_field(key, entry, expected):
    from shadowscan.connectors.code.lockfiles import parse_lockfile

    inventory = parse_lockfile("pnpm-lock.yaml", f"lockfileVersion: '9.0'\npackages:\n  {key}: {entry}\n")
    assert [(p.name, p.version, p.source) for p in inventory.packages] == [(*expected[:1], None, expected[1])]


@pytest.mark.parametrize(
    "key",
    [
        "github.com/example/helper/abc123",
        "'git@github.com:example/helper.git'",
        "'@example.invalid/helper.tgz'",
    ],
)
def test_pnpm_source_entry_without_a_name_is_still_malformed(key, tmp_path, run_connector):
    """A non-registry entry whose name cannot be told stays a lockfile gap, never a silent skip."""
    from shadowscan.connectors.code.lockfiles import LockfileError, parse_lockfile

    text = f"lockfileVersion: '9.0'\npackages:\n  {key}: {{resolution: {{tarball: x}}}}\n"
    with pytest.raises(LockfileError, match="^unsupported pnpm package key$"):
        parse_lockfile("pnpm-lock.yaml", text)
    (tmp_path / "pnpm-lock.yaml").write_text(text)
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete
    assert any(
        "pnpm-lock.yaml" in error and "unsupported pnpm package key" in error for error in ctx.stats.errors
    )


def test_pnpm_lockfile_with_a_git_dependency_is_inventoried_by_the_scan(tmp_path, run_connector):
    (tmp_path / "pnpm-lock.yaml").write_text(_PNPM_NON_REGISTRY["v9-codeload"])
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete and not ctx.stats.errors
    (finding,) = [f for f in findings if f.resource_type == "lockfile-inventory"]
    assert [p["name"] for p in finding.metadata["lockfile_inventory"]["matched_packages"]] == ["openai"]


def test_uv_package_without_a_version_is_inventoried_without_one():
    """Regression (#220 verifier): a workspace member or dynamic version rejected the whole uv.lock."""
    from shadowscan.connectors.code.lockfiles import LockfileError, parse_lockfile

    text = """version = 1
[[package]]
name = "agent-app"
source = { editable = "." }
dependencies = [{ name = "openai" }]
[[package]]
name = "openai"
version = "1.40.0"
source = { registry = "https://pypi.org/simple" }
"""
    inventory = parse_lockfile("uv.lock", text)
    packages = {p.name: p for p in inventory.packages}
    assert packages["agent-app"].version is None and packages["agent-app"].root
    assert packages["openai"].version == "1.40.0" and packages["openai"].relationship == "direct"
    assert any("without a version" in item for item in inventory.limitations)
    with pytest.raises(LockfileError, match="invalid locked package version"):
        parse_lockfile("poetry.lock", '[metadata]\nlock-version="2.0"\n[[package]]\nname="openai"\n')
