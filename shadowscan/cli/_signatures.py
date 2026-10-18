"""signatures group (list, show, test)."""

from __future__ import annotations

import json
from collections.abc import Callable

import click
import yaml
from rich.markup import escape
from rich.table import Table
from rich.text import Text

import shadowscan.cli as _cli
from shadowscan.cli import _log_masked_failure, main
from shadowscan.errors import SetupError
from shadowscan.signatures import Match, SignatureIndex, get_index
from shadowscan.signatures.loader import VALID_CATEGORIES
from shadowscan.utils.output import terminal_text
from shadowscan.utils.redaction import REDACTED, sanitize_text

SIGNATURE_KINDS = [
    "dependency",
    "domain",
    "user-agent",
    "model",
    "name",
    "env",
    "scope",
    "image",
    "iac",
    "file",
    "text",
    "secret",
]


_ALLOW_OVERRIDE_HELP = "allow a reviewed pack to replace built-in signatures"


def _load_index(signature_dirs: tuple[str, ...], allow_override: bool) -> SignatureIndex:
    """Load packs for a signatures command; pack diagnostics print verbatim, other failures are masked."""
    try:
        return get_index(extra_dirs=list(signature_dirs) or None, allow_override=allow_override)
    except SetupError as exc:
        raise click.ClickException(str(exc)) from None
    except Exception as exc:  # noqa: BLE001 - third-party exception text may echo pack content
        _log_masked_failure("signature pack loading failed", exc)
        raise click.ClickException(
            f"could not load signature packs ({type(exc).__name__}); check the pack directories"
        ) from None


# ---------------------------------------------------------------- signatures
@main.group()
def signatures() -> None:
    """Inspect and test the detection signature packs."""


@signatures.command("list")
@click.option(
    "--category",
    type=click.Choice(sorted(VALID_CATEGORIES)),
    help="show only this signature category",
)
@click.option("--signatures", "-s", "signature_dirs", multiple=True, help="extra signature pack directory")
@click.option("--json", "as_json", is_flag=True, help="print JSON instead of the human-readable output")
@click.option("--allow-signature-override", is_flag=True, help=_ALLOW_OVERRIDE_HELP)
def signatures_list(
    category: str | None,
    signature_dirs: tuple[str, ...],
    as_json: bool,
    allow_signature_override: bool,
) -> None:
    """List loaded signatures."""
    idx = _load_index(signature_dirs, allow_signature_override)
    sigs = sorted(idx.signatures.values(), key=lambda s: (s.category, s.id))
    if category:
        sigs = [s for s in sigs if s.category == category]
    if as_json:
        click.echo(
            json.dumps(
                [
                    {
                        "id": s.id,
                        "name": s.name,
                        "category": s.category,
                        "vendor": s.vendor,
                        "signals": len(s.signals),
                        "agent_indicator": s.agent_indicator,
                        "capabilities": s.capabilities,
                    }
                    for s in sigs
                ],
                indent=2,
            )
        )
        return
    table = Table(title=f"{len(sigs)} signatures", header_style="bold")
    table.add_column("Id", no_wrap=True)
    table.add_column("Name")
    table.add_column("Category", no_wrap=True)
    table.add_column("Vendor")
    table.add_column("Signals", justify="right")
    table.add_column("Agent?", justify="center")
    for s in sigs:
        agent = "✓" if s.agent_indicator else ""
        # A custom signature pack is untrusted: strip terminal control sequences from its fields.
        table.add_row(
            Text(terminal_text(s.id)),
            Text(terminal_text(s.name)),
            Text(terminal_text(s.category)),
            Text(terminal_text(s.vendor or "")),
            str(len(s.signals)),
            agent,
        )
    _cli.console.print(table)


@signatures.command("show")
@click.argument("signature_id")
@click.option("--signatures", "-s", "signature_dirs", multiple=True, help="extra signature pack directory")
@click.option("--allow-signature-override", is_flag=True, help=_ALLOW_OVERRIDE_HELP)
def signatures_show(
    signature_id: str,
    signature_dirs: tuple[str, ...],
    allow_signature_override: bool,
) -> None:
    """Print one signature as YAML."""
    idx = _load_index(signature_dirs, allow_signature_override)
    sig = idx.get(signature_id)
    if not sig:
        raise click.BadParameter(f"unknown signature {signature_id!r}")
    signals = []
    for s in sig.signals:
        fields_ = {
            "type": s.type,
            "weight": s.weight,
            "ecosystem": s.ecosystem,
            "languages": s.languages,
            "names": s.names,
            "prefixes": s.prefixes,
            "patterns": s.patterns,
            "globs": s.globs,
            "values": s.values,
            "capabilities": s.capabilities,
            "agent_indicator": s.agent_indicator,
        }
        signals.append({k: v for k, v in fields_.items() if v not in (None, [], False)})
    data = {
        "id": sig.id,
        "name": sig.name,
        "category": sig.category,
        "vendor": sig.vendor,
        "homepage": sig.homepage,
        "description": sig.description,
        "capabilities": sig.capabilities,
        "agent_indicator": sig.agent_indicator,
        "risk_notes": sig.risk_notes,
        "source": sig.source,
        "signals": signals,
    }
    click.echo(yaml.safe_dump(data, sort_keys=False, allow_unicode=True))


@signatures.command("test", short_help="Show which signatures a value matches")
@click.argument("value")
@click.option(
    "--kind",
    type=click.Choice(["auto", *SIGNATURE_KINDS]),
    default="auto",
    show_default=True,
    help="signal kind to test; auto tries every kind",
)
@click.option(
    "--ecosystem",
    default="any",
    show_default=True,
    help="for dependency: pypi | npm | go | cargo | maven | nuget | rubygems | composer; 'any' tries every"
    " ecosystem in the loaded packs",
)
@click.option("--signatures", "-s", "signature_dirs", multiple=True, help="extra signature pack directory")
@click.option("--allow-signature-override", is_flag=True, help=_ALLOW_OVERRIDE_HELP)
def signatures_test(
    value: str,
    kind: str,
    ecosystem: str,
    signature_dirs: tuple[str, ...],
    allow_signature_override: bool,
) -> None:
    """Test what a value matches, e.g. `shadowscan signatures test langchain-openai --kind dependency`.

    Dependency signals are ecosystem specific. With --ecosystem any (the
    default, also used by --kind auto) the value is tried as a package name
    in every ecosystem the loaded packs declare, and each ecosystem hit is
    reported once.
    """
    idx = _load_index(signature_dirs, allow_signature_override)
    kinds = [kind] if kind != "auto" else SIGNATURE_KINDS
    declared = sorted(
        {
            (s.ecosystem or "any").lower()
            for sig in idx.signatures.values()
            for s in sig.signals
            if s.type == "dependency"
        }
    )
    if ecosystem.lower() == "any":
        ecosystems = declared
    elif ecosystem.lower() in declared:
        ecosystems = [ecosystem]
    else:
        raise click.BadParameter(
            f"unknown ecosystem {ecosystem!r}; the loaded packs declare {', '.join(declared)} (or 'any')",
            param_hint="--ecosystem",
        )

    def match_dependency(v: str) -> list[Match]:
        out: list[Match] = []
        seen: set[tuple[str, int]] = set()
        for eco in ecosystems:
            for m in idx.match_dependency(eco, v):
                # Ecosystem-agnostic signals match under every ecosystem; report each signal once.
                if (m.signature_id, id(m.signal)) not in seen:
                    seen.add((m.signature_id, id(m.signal)))
                    out.append(m)
        return out

    def match_text(v: str) -> list[Match]:
        return (
            idx.match_code(v)
            + idx.match_imports(v, None)
            + idx.match_domains_in_text(v)
            + idx.match_envs_in_text(v)
        )

    matchers: dict[str, Callable[[str], list[Match]]] = {
        "dependency": match_dependency,
        "domain": idx.match_domain,
        "user-agent": idx.match_user_agent,
        "model": idx.match_model,
        "name": idx.match_name,
        "env": idx.match_env,
        "scope": idx.match_scope,
        "image": idx.match_image,
        "iac": idx.match_iac,
        "file": idx.match_file,
        "text": match_text,
        "secret": idx.match_secrets,
    }
    found = False
    for k in kinds:
        for m in matchers[k](value):
            found = True
            # Secret signatures keep raw match values so the scanner can
            # fingerprint them before producing sanitized findings. Never
            # reflect those values in terminal output or captured CI logs.
            shown = REDACTED if k == "secret" else sanitize_text(m.value)[:80]
            if k == "dependency":
                shown += f" ({m.signal.ecosystem or 'any'})"
            agent = "yes" if m.agent_indicator else "no "
            caps = ",".join(m.capabilities()) or "-"
            _cli.console.print(
                f"[bold]{k:11}[/bold] {m.signature_id:40} weight={m.weight:.2f} agent={agent} caps={caps}"
                f"  ← {escape(shown)}"
            )
    if not found:
        _cli.console.print("[dim]no match[/dim]")
