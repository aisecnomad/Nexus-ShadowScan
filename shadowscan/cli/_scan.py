"""scan, run, code, and gateway commands."""

from __future__ import annotations

from typing import Any

import click
import yaml

from shadowscan.cli import (
    ScanOptions,
    _warn_argv_secret,
    available_connectors,
    main,
    scan_options,
)
from shadowscan.config import (
    ConfigValidationError,
    ConnectorSpec,
    MinConfidenceError,
    ScanConfig,
    argv_credential_keys,
    parse_set_options,
    validate_connector_config,
)


# ---------------------------------------------------------------------- scan
@main.command()
@click.option(
    "--config",
    "-c",
    "config_path",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="shadowscan.yaml",
)
@click.option("--only", multiple=True, help="run only these connector names / labels (repeatable)")
@scan_options
def scan(config_path: str, only: tuple[str, ...], opts: ScanOptions) -> None:
    """Run every connector defined in a config file."""
    try:
        cfg = ScanConfig.from_yaml(config_path)
    except MinConfidenceError as exc:
        # The same threshold is a command line option: report it as a usage error.
        raise click.BadParameter(str(exc), param_hint="--config") from None
    except ConfigValidationError as exc:
        raise click.ClickException(f"invalid scan configuration: {exc}") from None
    except (ValueError, TypeError, AttributeError, OSError, yaml.YAMLError):
        raise click.ClickException(
            "invalid scan configuration; check YAML structure and option types"
        ) from None
    cfg.inventory.extend(opts.inventory)
    cfg.signature_dirs.extend(opts.signature_dirs)
    cfg.min_confidence = max(cfg.min_confidence, opts.min_confidence)
    cfg.fail_on = opts.fail_on or cfg.fail_on
    cfg.dump_records = opts.dump_records or cfg.dump_records
    if opts.incremental is not None:
        cfg.incremental = opts.incremental
    if opts.state_dir is not None:
        cfg.state_dir = opts.state_dir
    import shadowscan.cli as _cli_pkg

    _cli_pkg._run_scan(cfg, opts, only=list(only) or None)


# ----------------------------------------------------------------------- run
@main.command(short_help="Run a single connector by name, configured with --set")
@click.argument("connector")
@click.option(
    "--input",
    "input_path",
    type=click.Path(exists=True),
    help="offline export (file or directory) instead of the live API",
)
@click.option(
    "--set",
    "-S",
    "settings",
    multiple=True,
    help="connector option key=value (repeatable; lists as a,b,c)",
)
@scan_options
def run(connector: str, input_path: str | None, settings: tuple[str, ...], opts: ScanOptions) -> None:
    """Run a single connector, e.g. `shadowscan run identity.okta --set org_url=https://acme.okta.com`."""
    if connector not in available_connectors():
        raise click.BadParameter(f"unknown connector {connector!r}; see `shadowscan connectors`")
    try:
        conf = parse_set_options(list(settings))
    except (ValueError, TypeError):
        raise click.BadParameter("--set expects key=value pairs") from None
    if input_path:
        conf["input"] = input_path
    try:
        validate_connector_config(connector, conf)
    except ConfigValidationError as exc:
        raise click.BadParameter(str(exc), param_hint="--set") from None
    exposed = argv_credential_keys({k: v for k, v in conf.items() if k != "input"})
    if exposed:
        _warn_argv_secret(f"--set {', '.join(exposed)}", "a ${ENV_VAR} reference in a scan configuration")
    import shadowscan.cli as _cli_pkg

    _cli_pkg._run_scan(opts.config([ConnectorSpec(name=connector, config=conf)]), opts)


# ---------------------------------------------------------------------- code
@main.command()
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("--github-org", help="scan every repository of a GitHub organisation (GITHUB_TOKEN)")
@click.option("--github-repo", multiple=True, help="owner/name (repeatable)")
@click.option("--gitlab-group", help="scan every project of a GitLab group (GITLAB_TOKEN)")
@click.option(
    "--mode",
    type=click.Choice(["clone", "api"]),
    default=None,
    help="remote fetch mode for --github-org, --github-repo or --gitlab-group",
)
@click.option("--exclude", multiple=True, help="extra directory names / globs to skip")
@click.option(
    "--no-default-excludes",
    is_flag=True,
    help="also scan the directories skipped by default (bin, build, dist, vendor, node_modules, .git, ...)",
)
@click.option("--no-secrets", is_flag=True, help="skip credential detection")
@click.option(
    "--strict-coverage",
    is_flag=True,
    help="record incomplete file and symlink coverage as errors (exit 3 in either mode)",
)
@click.option(
    "--include-tests",
    is_flag=True,
    help="let test and fixture code establish agents at full weight",
)
@click.option(
    "--triage",
    is_flag=True,
    help="fast subset scan (manifests, MCP/agent configs, flows, IaC); always exits incomplete",
)
@click.option(
    "--profile",
    type=click.Choice(["default", "ci"]),
    default=None,
    help=(
        "ci: declare oversize files, unread links and analysis limits under test, fixture, documentation, "
        "example and generated paths as omissions (warnings the report counts) instead of gaps, so a "
        "complete source scan exits 0; every other gap still exits 3"
    ),
)
@click.option(
    "--diff-base",
    default=None,
    help=(
        "local PATHS only: git ref to diff against; only committed changes are scanned (plus manifests and "
        ".env for context), and the report cannot resolve findings in `shadowscan diff`"
    ),
)
@scan_options
def code(
    paths: tuple[str, ...],
    github_org: str | None,
    github_repo: tuple[str, ...],
    gitlab_group: str | None,
    mode: str | None,
    exclude: tuple[str, ...],
    no_default_excludes: bool,
    no_secrets: bool,
    strict_coverage: bool,
    include_tests: bool,
    triage: bool,
    profile: str | None,
    diff_base: str | None,
    opts: ScanOptions,
) -> None:
    """Scan local directories and/or remote repositories for agent code, MCP, coding agents, IaC and
    secrets."""
    specs: list[ConnectorSpec] = []
    common: dict[str, Any] = {"exclude": list(exclude), "scan_secrets": not no_secrets}
    if no_default_excludes:
        common["default_excludes"] = False
    if strict_coverage:
        common["strict_coverage"] = True
    if include_tests:
        common["include_tests"] = True
    if triage:
        common["triage"] = True
    if profile:
        if strict_coverage and profile == "ci":
            raise click.UsageError("--profile ci and --strict-coverage conflict; pass one of them")
        common["profile"] = profile
    if diff_base and not paths:
        raise click.UsageError("--diff-base applies only to local PATHS")
    if mode and not (github_org or github_repo or gitlab_group):
        raise click.UsageError("--mode applies only to --github-org, --github-repo or --gitlab-group")
    if paths:
        local: dict[str, Any] = {"paths": list(paths), **common}
        if diff_base:
            # Remote repositories in the same run are always scanned in full.
            local["diff_base"] = diff_base
        specs.append(ConnectorSpec(name="code.filesystem", config=local))
    if github_org or github_repo:
        gh: dict[str, Any] = {**common}
        if github_org:
            gh["org"] = github_org
        if github_repo:
            gh["repos"] = list(github_repo)
        if mode:
            gh["mode"] = mode
        specs.append(ConnectorSpec(name="code.github", config=gh))
    if gitlab_group:
        gl: dict[str, Any] = {"group": gitlab_group, **common}
        if mode:
            gl["mode"] = mode
        specs.append(ConnectorSpec(name="code.gitlab", config=gl))
    if not specs:
        raise click.UsageError("give at least one PATH, --github-org/--github-repo or --gitlab-group")
    import shadowscan.cli as _cli_pkg

    _cli_pkg._run_scan(opts.config(specs), opts)


# ------------------------------------------------------------------- gateway
GATEWAY_LOG_FORMATS = [
    "auto",
    "litellm",
    "portkey",
    "kong",
    "cloudflare",
    "helicone",
    "langfuse",
    "bedrock",
    "azure-openai",
    "vertex",
    "openai-usage",
    "anthropic-usage",
    "access-log",
    "generic",
]


@main.command()
@click.argument("logs", nargs=-1, required=True, type=click.Path(exists=True))
@click.option(
    "--log-format",
    type=click.Choice(GATEWAY_LOG_FORMATS),
    default="auto",
    show_default=True,
    help="log format; auto detects it from the content",
)
@click.option(
    "--min-events",
    type=int,
    default=1,
    show_default=True,
    help="ignore callers with fewer requests",
)
@click.option(
    "--all-hosts",
    is_flag=True,
    help="for access logs, keep traffic to every host (default: LLM/agent hosts only)",
)
@click.option(
    "--internal-model-host",
    "internal_model_hosts",
    multiple=True,
    help="exact internal model-server hostname to count as model traffic (repeatable)",
)
@click.option("--label", help="gateway name used as the findings' account/provider")
@scan_options
def gateway(
    logs: tuple[str, ...],
    log_format: str,
    min_events: int,
    all_hosts: bool,
    internal_model_hosts: tuple[str, ...],
    label: str | None,
    opts: ScanOptions,
) -> None:
    """Analyse LLM gateway / provider / proxy logs and reconstruct the callers."""
    specs = []
    for i, path in enumerate(logs):
        conf: dict[str, Any] = {"input": path, "min_events": min_events, "llm_hosts_only": not all_hosts}
        if log_format != "auto":
            conf["format"] = log_format
        if internal_model_hosts:
            # Set only when given: an unset option keeps the source's finding ids.
            conf["internal_model_hosts"] = list(internal_model_hosts)
        if label:
            conf["label"] = label
        instance = f"gateway.logs#{i + 1}" if len(logs) > 1 else None
        specs.append(ConnectorSpec(name="gateway.logs", config=conf, label=instance))
    import shadowscan.cli as _cli_pkg

    _cli_pkg._run_scan(opts.config(specs), opts)
