"""SaaS-surface families: Slack workspace apps and GitHub App installations.

Rubric. ``agent``: an installed app whose publisher's product is an AI agent
(coding agents, AI reviewers that write, agent platforms) or whose own
description states autonomous AI behaviour, holding scopes or permissions that
let it act (write). ``llm``: an app from an AI vendor whose product is not
agentic (chat assistant, notetaker, transcription) or an AI app limited to
read scopes. ``none``: no AI, including CI, dependency, monitoring and
productivity apps and apps whose names merely contain agent-like words.
"""

from __future__ import annotations

from typing import Any

from tools.benchmark.common import Rand
from tools.shadowbench.contract import TruthEntity
from tools.shadowbench.families import Draft, email, iso

SLACK_AGENT_APPS = (
    ("Claude", "claude.ai", "Anthropic", "Chat with Claude, delegate tasks and take actions in Slack."),
    ("Zapier AI Agents", "zapier.com", "Zapier", "Agents that complete tasks across your tools."),
    ("Glean", "glean.com", "Glean", "Enterprise search and AI agents."),
    ("Agentforce", "salesforce.com", "Salesforce", "Autonomous agents for sales and service."),
    ("Devin", "devin.ai", "Cognition", "Your AI software engineer, available in Slack."),
    ("Lindy", "lindy.ai", "Lindy", "AI assistants that run your workflows."),
)
SLACK_LLM_APPS = (
    ("ChatGPT", "openai.com", "OpenAI", "ChatGPT for Slack: summaries and drafting."),
    ("Otter.ai", "otter.ai", "Otter.ai", "Meeting notes and transcription."),
    ("Read.ai", "read.ai", "Read AI", "Meeting summaries delivered to Slack."),
    ("Fireflies.ai", "fireflies.ai", "Fireflies", "AI notetaker."),
    ("Perplexity", "perplexity.ai", "Perplexity", "Ask Perplexity from Slack."),
)
SLACK_PLAIN_APPS = (
    ("Jira Cloud", "atlassian.com", "Atlassian", "Jira notifications and issue creation."),
    ("GitHub", "github.com", "GitHub", "Subscribe to repository activity."),
    ("Polly", "polly.ai", "Polly", "Polls and surveys."),
    ("Giphy", "giphy.com", "Giphy", "GIFs."),
    ("PagerDuty", "pagerduty.com", "PagerDuty", "Incident alerts."),
    ("Google Drive", "google.com", "Google", "File notifications."),
    ("Zoom", "zoom.us", "Zoom", "Start meetings."),
    ("Datadog", "datadoghq.com", "Datadog", "Monitoring alerts."),
)
SLACK_DECOY_APPS = (
    ("Field Agent Dispatch", "fieldops.acme.example", "Acme IT", "Dispatch board for field technicians."),
    ("Travel Agent Desk", "travel.acme.example", "Acme Travel", "Human travel desk requests."),
    ("Bedrock Alerts", "mc.acme.example", "Acme Gaming", "Minecraft server status."),
    ("Secret Agent Trivia", "trivia.example", "Fun Apps", "Spy-themed trivia game."),
)
WRITE_SCOPES = ("chat:write", "files:write", "reactions:write", "channels:manage", "im:write")
READ_SCOPES = (
    "channels:history",
    "channels:read",
    "users:read",
    "users:read.email",
    "im:history",
    "files:read",
)


def _app(
    rd: Rand, name: str, domain: str, publisher: str, desc: str, scopes: list[str], internal: bool = False
) -> dict[str, Any]:
    app_id = "A0" + "".join(rd.choice("ABCDEFGHJKLMNPQRSTUVWXYZ0123456789") for _ in range(9))
    return {
        "app": {
            "id": app_id,
            "name": name,
            "description": desc,
            "help_url": f"https://{domain}/help",
            "privacy_policy_url": f"https://{domain}/privacy",
            "app_homepage_url": f"https://{domain}",
            "app_directory_url": f"https://slack.com/apps/{app_id}",
            "is_app_directory_approved": not internal,
            "is_internal": internal,
            "additional_info": publisher,
        },
        "scopes": [
            {"name": s, "description": s, "is_sensitive": s.endswith("history"), "token_type": "bot"}
            for s in scopes
        ],
        "date_updated": 1757_000_000 + rd.randint(0, 3_000_000),
        "last_resolved_by": {"actor_id": "U0" + rd.hexid(8).upper(), "actor_type": "user"},
    }


def _bot_user(rd: Rand, app_id: str, name: str) -> dict[str, Any]:
    return {
        "id": "U0" + rd.hexid(8).upper(),
        "name": name.lower().replace(" ", "").replace(".", "")[:20],
        "real_name": name,
        "is_bot": True,
        "is_app_user": False,
        "deleted": False,
        "profile": {"api_app_id": app_id, "real_name": name, "bot_id": "B0" + rd.hexid(8).upper()},
        "updated": 1757_000_000 + rd.randint(0, 3_000_000),
    }


def _slack_draft(
    rd: Rand,
    family: str,
    label: str,
    difficulty: str,
    spec: tuple[str, str, str, str],
    scopes: list[str],
    evidence: str,
    internal: bool = False,
) -> Draft:
    name, domain, publisher, desc = spec
    app = _app(rd, name, domain, publisher, desc, scopes, internal)
    records: dict[str, list[dict[str, Any]]] = {"approved_apps": [app]}
    if rd.chance(0.8):
        records["members"] = [_bot_user(rd, app["app"]["id"], name)]
    expected = (
        [TruthEntity("app", f"app:{app['app']['id']}", label, {"platform": "slack", "name": name}, evidence)]
        if label != "none"
        else []
    )
    return Draft(family, label, difficulty, f"Slack app {name}: {desc}", records, expected=expected)


def slack_agent_app(rd: Rand) -> Draft:
    spec = rd.choice(SLACK_AGENT_APPS)
    scopes = rd.sample(READ_SCOPES, 3) + rd.sample(WRITE_SCOPES, 2) + ["app_mentions:read"]
    return _slack_draft(
        rd,
        "slack-agent-app",
        "agent",
        "easy",
        spec,
        scopes,
        f"app_homepage_url {spec[1]}: AI agent product; "
        f"write scopes {', '.join(s for s in scopes if s in WRITE_SCOPES)}",
    )


def slack_internal_ai_bot(rd: Rand) -> Draft:
    team = rd.choice(("Support", "Sales", "Platform", "People"))
    spec = (
        f"{team} Assistant",
        "acme.example",
        "Acme Engineering",
        f"GPT-4o powered assistant that answers {team.lower()} questions and files tickets on request.",
    )
    scopes = ["chat:write", "channels:history", "app_mentions:read", "users:read"]
    return _slack_draft(
        rd,
        "slack-internal-ai-bot",
        "agent",
        "medium",
        spec,
        scopes,
        "internal app whose description states an LLM-powered assistant that files tickets (acts)",
        internal=True,
    )


def slack_llm_app(rd: Rand) -> Draft:
    spec = rd.choice(SLACK_LLM_APPS)
    scopes = rd.sample(READ_SCOPES, 3) + ["chat:write"]
    return _slack_draft(
        rd,
        "slack-llm-app",
        "llm",
        "easy",
        spec,
        scopes,
        f"app_homepage_url {spec[1]}: AI chat or transcription product without agentic action",
    )


def slack_plain_app(rd: Rand) -> Draft:
    spec = rd.choice(SLACK_PLAIN_APPS)
    return _slack_draft(
        rd, "slack-plain-app", "none", "easy", spec, rd.sample(READ_SCOPES, 2) + ["chat:write"], ""
    )


def slack_decoy_app(rd: Rand) -> Draft:
    spec = rd.choice(SLACK_DECOY_APPS)
    return _slack_draft(
        rd, "slack-decoy-app", "none", "hard", spec, ["chat:write", "commands"], "", internal=rd.chance(0.5)
    )


def slack_app_request(rd: Rand) -> Draft:
    """A pending install request for an AI app: not installed, so not expected."""
    name, domain, publisher, desc = rd.choice(SLACK_LLM_APPS + SLACK_AGENT_APPS)
    req = {
        "id": "Ar0" + rd.hexid(8).upper(),
        "app": {
            "id": "A0" + rd.hexid(9).upper(),
            "name": name,
            "description": desc,
            "app_homepage_url": f"https://{domain}",
            "is_app_directory_approved": True,
        },
        "user": {"id": "U0" + rd.hexid(8).upper(), "name": email(rd).split("@")[0], "email": email(rd)},
        "message": rd.choice(("need meeting notes", "for the sales team", "please approve")),
        "scopes": [{"name": "channels:history"}, {"name": "chat:write"}],
        "date_created": 1757_000_000 + rd.randint(0, 3_000_000),
    }
    return Draft(
        "slack-app-request",
        "none",
        "hard",
        f"Pending (not installed) request for {name}; tolerated, not expected.",
        {"requests": [req]},
        tolerated=[f"app:{req['app']['id']}"],
    )


SLACK_AGENT = (slack_agent_app, slack_internal_ai_bot)
SLACK_LLM = (slack_llm_app,)
SLACK_NONE = (slack_plain_app, slack_decoy_app, slack_app_request)


# --- GitHub App installations -------------------------------------------------

GH_AGENT_APPS = (
    ("claude", "Claude", "Anthropic coding agent and PR reviewer"),
    ("copilot-swe-agent", "Copilot coding agent", "GitHub Copilot coding agent"),
    ("coderabbitai", "CodeRabbit", "AI code reviews that post comments and suggested changes"),
    ("devin-ai-integration", "Devin", "Cognition's AI software engineer"),
    ("cursor", "Cursor", "Cursor background agents"),
    ("chatgpt-codex-connector", "Codex", "OpenAI Codex cloud agent"),
    ("google-labs-jules", "Jules", "Google Jules coding agent"),
    ("sweep-ai", "Sweep", "AI junior developer"),
    ("ellipsis-dev", "Ellipsis", "AI code review and fixes"),
    ("qodo-merge-pro", "Qodo Merge", "AI PR agent"),
)
GH_LLM_APPS = (
    ("greptile-apps", "Greptile", "AI codebase Q&A"),
    ("ai-release-notes", "AI Release Notes", "Generates release notes with an LLM"),
    ("pr-summary-ai", "PR Summary AI", "Summarises pull requests"),
)
GH_PLAIN_APPS = (
    ("renovate", "Renovate", "Dependency updates"),
    ("dependabot", "Dependabot", "Dependency updates"),
    ("codecov", "Codecov", "Coverage reports"),
    ("sonarcloud", "SonarCloud", "Static analysis"),
    ("vercel", "Vercel", "Deploy previews"),
    ("netlify", "Netlify", "Deploy previews"),
    ("allcontributors", "All Contributors", "Contributor credits"),
    ("semantic-pull-requests", "Semantic Pull Requests", "PR title checks"),
    ("buildkite", "Buildkite", "CI pipelines"),
)
GH_DECOY_APPS = (
    ("agent-health-monitor", "Agent Health Monitor", "Uptime checks for build agents"),
    ("bedrock-ci", "Bedrock CI", "CI for the Minecraft Bedrock plugin"),
    ("mcp-status", "MCP Status", "Reports Minecraft Coder Pack mapping status"),
    ("copilot-seats", "Copilot Seats", "Seat usage reporting"),
)


def _install(rd: Rand, slug: str, app_id: int, write: bool) -> dict[str, Any]:
    perms: dict[str, str] = {"metadata": "read", "contents": "write" if write else "read"}
    if write:
        perms["pull_requests"] = "write"
        perms["issues"] = rd.choice(("write", "read"))
        if rd.chance(0.4):
            perms["actions"] = "write"
    else:
        perms["pull_requests"] = "read"
    return {
        "id": rd.randint(10_000_000, 99_999_999),
        "app_id": app_id,
        "app_slug": slug,
        "client_id": "Iv1." + rd.hexid(16),
        "target_id": 4_000_000 + rd.randint(0, 999_999),
        "target_type": "Organization",
        "account": {"login": "acme", "type": "Organization"},
        "repository_selection": rd.choice(("all", "selected")),
        "permissions": perms,
        "events": ["pull_request", "issue_comment", "push"] if write else ["push"],
        "created_at": iso(rd, 2025),
        "updated_at": iso(rd),
        "suspended_at": None,
        "html_url": "https://github.com/organizations/acme/settings/installations/"
        + str(rd.randint(10_000_000, 99_999_999)),
    }


def _gh_draft(
    rd: Rand, family: str, label: str, difficulty: str, spec: tuple[str, str, str], write: bool, evidence: str
) -> Draft:
    slug, name, desc = spec
    inst = _install(rd, slug, rd.randint(100_000, 1_500_000), write)
    expected = (
        [TruthEntity("app", f"app:{slug}", label, {"platform": "github", "name": name}, evidence)]
        if label != "none"
        else []
    )
    return Draft(
        family,
        label,
        difficulty,
        f"GitHub App {name} ({slug}): {desc}",
        {"installations": [inst]},
        expected=expected,
    )


def gh_agent_app(rd: Rand) -> Draft:
    spec = rd.choice(GH_AGENT_APPS)
    return _gh_draft(
        rd,
        "github-agent-app",
        "agent",
        "easy",
        spec,
        True,
        f"app_slug {spec[0]}: coding agent or AI reviewer; contents and pull_requests write",
    )


def gh_llm_app(rd: Rand) -> Draft:
    spec = rd.choice(GH_LLM_APPS)
    return _gh_draft(
        rd,
        "github-llm-app",
        "llm",
        "medium",
        spec,
        False,
        f"app_slug {spec[0]}: AI app limited to read permissions",
    )


def gh_plain_app(rd: Rand) -> Draft:
    return _gh_draft(rd, "github-plain-app", "none", "easy", rd.choice(GH_PLAIN_APPS), rd.chance(0.6), "")


def gh_decoy_app(rd: Rand) -> Draft:
    return _gh_draft(rd, "github-decoy-app", "none", "hard", rd.choice(GH_DECOY_APPS), rd.chance(0.5), "")


GITHUB_AGENT = (gh_agent_app,)
GITHUB_LLM = (gh_llm_app,)
GITHUB_NONE = (gh_plain_app, gh_decoy_app)
