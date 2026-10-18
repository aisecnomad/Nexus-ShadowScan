"""ShadowScan command line interface.

The CLI is a Click group split by subcommand. This module holds the shared
infrastructure (logging, options, ``ScanOptions``, ``_run_scan``, the
``main`` group) and registers every subcommand module on import.
"""

from __future__ import annotations

import functools
import logging
import os
import sys
import traceback
from collections.abc import Callable, Sequence
from dataclasses import dataclass, fields
from typing import IO, Any, NoReturn, TypeVar

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.markup import escape
from rich.text import Text

from shadowscan import __version__
from shadowscan.comparison import MAX_REPORT_BYTES, load_report
from shadowscan.config import (
    ConfigValidationError,
    ConnectorSpec,
    ScanConfig,
    validate_connector_timeout,
    validate_job_deadline_seconds,
    validate_min_confidence,
)
from shadowscan.connectors import (
    available_connectors,
    plugin_registry_errors,
)
from shadowscan.coverage import validate_max_coverage_gap
from shadowscan.engine import Engine
from shadowscan.errors import SetupError
from shadowscan.models import ScanResult, ScanStats
from shadowscan.reporters import FORMATS, render
from shadowscan.reporters.table import incomplete_reasons_text, print_table
from shadowscan.signatures import SignatureIndex
from shadowscan.utils.deadline import JobDeadline, arm_job_deadline
from shadowscan.utils.git import terminate_active_clones, terminate_clones_on_signal
from shadowscan.utils.output import (
    encodable_text,
    terminal_report_text,
    terminal_text,
    write_private_text,
)
from shadowscan.utils.platform import UnsupportedPlatformError, require_supported_platform

console = Console(width=None if sys.stdout.isatty() else 200)


err_console = Console(stderr=True)


log = logging.getLogger("shadowscan.cli")


LEVELS = ["critical", "high", "medium", "low", "info"]


SETUP_FAILED = "scan setup failed; check connector configuration, signature packs and inventory"


_JOB_DEADLINE_CONTEXT_KEY = "shadowscan.cli.job_deadline_watchdog"


# Without a job deadline, nothing else bounds report output and clone cleanup
# once a timed-out connector worker has been abandoned.
_ABANDONED_WORKER_EXIT_GRACE_SECONDS = 30.0


_ABANDONED_WORKER_EXIT_MESSAGE = (
    f"report output did not finish within {_ABANDONED_WORKER_EXIT_GRACE_SECONDS:g} seconds after a"
    " connector timed out; exiting (scan coverage is incomplete; the report may be missing or"
    " truncated, and an existing output file may not have been replaced)"
)


F = TypeVar("F", bound=Callable[..., Any])


def _load_report(path: str) -> dict[str, Any]:
    """Turn strict, bounded report import failures into a CLI usage error."""
    try:
        return load_report(path)
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        raise click.ClickException(
            "could not read a ShadowScan JSON report (regular file, at most "
            f"{MAX_REPORT_BYTES // (1024 * 1024)} MiB)"
        ) from None


def _setup_logging(verbose: int, quiet: bool) -> None:
    level = logging.WARNING
    if quiet:
        level = logging.ERROR
    elif verbose == 1:
        level = logging.INFO
    elif verbose >= 2:
        level = logging.DEBUG
    handler = RichHandler(console=err_console, show_path=False, show_time=verbose >= 2, rich_tracebacks=False)
    logging.basicConfig(level=level, format="%(message)s", handlers=[handler], force=True)
    # urllib3 logs the full request URL (path and pagination cursor, which can name users) in
    # a WARNING when an upstream returns malformed headers; SECURITY.md promises paths and
    # queries stay out of diagnostics, so keep its records at ERROR.
    logging.getLogger("urllib3").setLevel(logging.ERROR)
    logging.getLogger("botocore").setLevel(logging.WARNING)


def _emit(
    result: ScanResult,
    fmt: str,
    output: str | None,
    verbose: bool,
    max_rows: int | None,
    index: SignatureIndex | None = None,
) -> None:
    if fmt == "table" and not output:
        try:
            print_table(result, console=console, verbose=verbose, max_rows=max_rows)
        except (OverflowError, RecursionError, TypeError, ValueError):
            raise click.ClickException("could not render report; result data is invalid") from None
        return
    try:
        text = render(result, "json" if fmt == "table" else fmt, index)
    except (OverflowError, RecursionError, TypeError, ValueError):
        # Reporter exceptions can contain attacker-controlled values. Invalid
        # plugin output (including NaN/Infinity) must fail before stdout or an
        # existing report receives any partial, non-standard serialization.
        raise click.ClickException("could not render report; result data is invalid") from None
    if output:
        try:
            write_private_text(output, text)
        except (OSError, ValueError):
            raise click.ClickException("could not write report; check output path and permissions") from None
        written = fmt if fmt != "table" else "json"
        note = f"wrote {written} report to {output}"
        if fmt == "table":
            note += " (the table format saves JSON to a file; pass --format for another file type)"
        err_console.print(Text(terminal_text(note), style="green"))
        if fmt == "table":
            try:
                print_table(result, console=console, verbose=verbose, max_rows=max_rows)
            except (OverflowError, RecursionError, TypeError, ValueError):
                raise click.ClickException("could not render report; result data is invalid") from None
    else:
        click.echo(encodable_text(terminal_report_text(text, fmt)))


def _exit_code(result: ScanResult, fail_on: str | None) -> int:
    if not result.complete:
        return 3
    if not fail_on:
        return 0
    threshold = LEVELS.index(fail_on)
    worst = min((LEVELS.index(f.risk.level.value) for f in result.findings), default=len(LEVELS))
    return 2 if worst <= threshold else 0


def _incomplete_explanation(result: ScanResult) -> str:
    """Why the scan exits 3, by reason category; the diagnostics themselves stay in the report.

    The categories come from the connectors' own message vocabulary and name no path or value,
    so they can go to a terminal or a CI log that the private report does not reach.
    """
    summary = result.summary()
    reasons = summary["incomplete_reasons"]
    if reasons:
        detail = incomplete_reasons_text(reasons)
    else:
        detail = "a connector was skipped or recorded no diagnostic"
    note = f"scan incomplete (exit 3): {detail}; see the report's warnings, errors and stats"
    if summary["declared_omissions"]:
        note += f"; {summary['declared_omissions']} declared omission(s) did not count"
    if summary["tolerated_gaps"]:
        note += f"; {summary['tolerated_gaps']} coverage gap(s) within budget did not count"
    return note


def _explain_incomplete(result: ScanResult) -> None:
    """Print the exit-3 explanation on stderr, best effort: a closed stream must not change the exit."""
    try:
        err_console.print(Text(terminal_text(_incomplete_explanation(result)), style="yellow"))
    except Exception:  # noqa: BLE001, S110 - output streams may already be closed; the exit code must not change
        pass


def _abandoned_exit_message(result: ScanResult, code: int, abandoned: int) -> str:
    """The notice for leaving timed-out workers behind; with exit 3 it leads with the reasons."""
    message = f"[yellow]exiting without waiting for {abandoned} timed-out connector worker(s)[/yellow]"
    if code == 3:
        message = f"[yellow]{escape(terminal_text(_incomplete_explanation(result)))}[/yellow]\n{message}"
    return message


def _exit_abandoned_workers(code: int, message: str) -> NoReturn:
    """Best-effort output must not prevent the CLI leaving blocked workers."""
    try:
        try:
            err_console.print(message)
        except Exception:  # noqa: BLE001, S110 - output streams may already be closed
            pass
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.flush()
            except Exception:  # noqa: BLE001, S110 - still try the other stream and exit
                pass
    finally:
        # An abandoned worker may still be waiting to stop its own clone.
        terminate_active_clones()
        os._exit(code)


def _plugin_registry_problems() -> tuple[str, ...]:
    """Rescan plugin metadata and return its collision and validity diagnostics as printable lines."""
    available_connectors()
    return tuple(str(problem) for problem in plugin_registry_errors())


def _log_masked_failure(stage: str, exc: BaseException) -> None:
    """Debug-log a masked failure as its type and frame locations; never its text or source lines."""
    frames = " <- ".join(
        f"{os.path.basename(frame.filename)}:{frame.lineno} {frame.name}"
        for frame in reversed(traceback.extract_tb(exc.__traceback__))
    )
    log.debug("%s (%s) at %s", stage, type(exc).__name__, frames or "unknown location")


def _run_and_emit(
    cfg: ScanConfig,
    fmt: str,
    output: str | None,
    verbose: int,
    max_rows: int | None,
    only: list[str] | None = None,
    *,
    extra_stats: list[ScanStats] | None = None,
) -> None:
    # Reuse a CLI-option watchdog already running during command preparation;
    # YAML-only and direct callers arm a local watchdog for engine/output work.
    try:
        cfg.validate_security_options()
    except SetupError as exc:
        raise click.ClickException(str(exc)) from None
    ctx = click.get_current_context(silent=True)
    watchdog: JobDeadline | None = ctx.meta.get(_JOB_DEADLINE_CONTEXT_KEY) if ctx is not None else None
    if watchdog is None and cfg.job_deadline_seconds is not None:
        watchdog = arm_job_deadline(cfg.job_deadline_seconds)
    owned_deadline = ctx is None or ctx.meta.get(_JOB_DEADLINE_CONTEXT_KEY) is None
    job_deadline = watchdog.expires_at if watchdog is not None else None
    try:
        _run_and_emit_with_deadline(cfg, fmt, output, verbose, max_rows, only, extra_stats, job_deadline)
    finally:
        if watchdog is not None and owned_deadline:
            watchdog.cancel()


def _run_and_emit_with_deadline(
    cfg: ScanConfig,
    fmt: str,
    output: str | None,
    verbose: int,
    max_rows: int | None,
    only: list[str] | None = None,
    extra_stats: list[ScanStats] | None = None,
    job_deadline: float | None = None,
) -> None:
    """Run the scan and emit its report; ``extra_stats`` (command-level diagnostics) join its stats.

    ``job_deadline`` is the armed watchdog's ``time.monotonic()`` expiry, if any.
    """

    def progress(cid: str, msg: str) -> None:
        err_console.print(Text(terminal_text(f"{cid}: {msg}"), style="dim"))

    for problem in _plugin_registry_problems():
        log.warning("plugin registry: %s", problem)
    try:
        engine = Engine(cfg, progress=progress if verbose else None)
        # Connectors run on worker threads, which cannot install signal
        # handlers: a termination signal must stop live clones from here.
        with terminate_clones_on_signal():
            # The engine ends LLM triage early enough to emit the report before the watchdog fires.
            result = engine.run(only=only, job_deadline=job_deadline)
    except SetupError as exc:
        # SetupError messages are credential-free by contract (shadowscan.errors).
        raise click.ClickException(str(exc)) from None
    except ConfigValidationError as exc:
        # Policy rejections (for example a code scan selected alongside a live
        # credentialed connector) never echo configured values, so the reason
        # can be shown instead of a generic setup failure the operator cannot act on.
        raise click.ClickException(f"invalid scan configuration: {exc}") from None
    except Exception as exc:  # noqa: BLE001 - third-party exception text may echo credentials
        _log_masked_failure("scan setup failed", exc)
        raise click.ClickException(f"{SETUP_FAILED} ({type(exc).__name__})") from None
    result.stats.extend(extra_stats or [])
    # With abandoned workers, arm a bounded exit watchdog so the process cannot
    # hang indefinitely during report emission or clone cleanup. An armed job
    # deadline already bounds both, and its report time must not be cut short.
    exit_guard: JobDeadline | None = None
    if engine.abandoned_workers and job_deadline is None:
        exit_guard = arm_job_deadline(
            _ABANDONED_WORKER_EXIT_GRACE_SECONDS, message=_ABANDONED_WORKER_EXIT_MESSAGE
        )
    try:
        try:
            # The scan's own index names custom-pack signatures in the CycloneDX output.
            index = getattr(engine, "index", None)
            _emit(result, fmt, output, verbose=bool(verbose), max_rows=max_rows, index=index)
        except Exception:  # any emission failure must still release an abandoned CLI worker
            if engine.abandoned_workers:
                _exit_abandoned_workers(
                    1,
                    "[red]could not emit the incomplete report; exiting without waiting for timed-out"
                    " workers[/red]",
                )
            raise
        code = _exit_code(result, cfg.fail_on)
        if engine.abandoned_workers:
            # A timed-out connector's thread may still be blocked in an SDK call.
            # Python joins worker threads at interpreter exit, which would hold the
            # process (and its CI job) open indefinitely. The report is written.
            # One diagnostic carries the exit-3 explanation with the notice.
            _exit_abandoned_workers(
                code, _abandoned_exit_message(result, code, len(engine.abandoned_workers))
            )
        if code == 3:
            _explain_incomplete(result)
        sys.exit(code)
    except KeyboardInterrupt:
        # Interpreter exit would join the blocked workers, so keep an exit
        # armed. The callers cancel any job deadline while this unwinds.
        if engine.abandoned_workers and exit_guard is None:
            arm_job_deadline(_ABANDONED_WORKER_EXIT_GRACE_SECONDS, message=_ABANDONED_WORKER_EXIT_MESSAGE)
        raise
    except BaseException:
        # With abandoned workers, only a replaced hard exit (tests, in-process
        # callers) returns here: disarm the watchdog so it cannot exit the
        # process after the call.
        if exit_guard is not None:
            exit_guard.cancel()
        raise


def _min_confidence_option(ctx: click.Context, param: click.Parameter, value: float) -> float:
    try:
        return validate_min_confidence(value)
    except ValueError as exc:
        raise click.BadParameter(str(exc)) from exc


def _connector_timeout_option(
    ctx: click.Context, param: click.Parameter, value: float | None
) -> float | None:
    if value is None:
        return None
    try:
        return validate_connector_timeout(value)
    except ValueError as exc:
        raise click.BadParameter(str(exc)) from exc


def _max_coverage_gap_option(ctx: click.Context, param: click.Parameter, value: float | None) -> float | None:
    if value is None:
        return None
    try:
        return validate_max_coverage_gap(value)
    except ValueError as exc:
        raise click.BadParameter(str(exc)) from exc


def _job_deadline_option(ctx: click.Context, param: click.Parameter, value: float | None) -> float | None:
    try:
        seconds = validate_job_deadline_seconds(value)
    except ValueError as exc:
        raise click.BadParameter(str(exc)) from exc
    if seconds is not None:
        # Click parses a child context without cleanup, so a later usage error
        # can discard that child before it is entered. Its already-open root
        # context still closes, including when subcommand parsing fails.
        watchdog = arm_job_deadline(seconds)
        ctx.meta[_JOB_DEADLINE_CONTEXT_KEY] = watchdog
        ctx.find_root().call_on_close(watchdog.cancel)
    return seconds


# Deadline, credential, plugin and destination approvals for scanning commands.
security_options = [
    click.option(
        "--job-deadline-seconds",
        type=float,
        callback=_job_deadline_option,
        is_eager=True,
        help="CLI process deadline, including setup and output; exits 3 on expiry (default: disabled);"
        " use an external supervisor to reap subprocesses",
    ),
    click.option(
        "--allow-instance-credentials/--deny-instance-credentials",
        default=None,
        help="explicitly allow cloud instance or managed-identity credentials",
    ),
    click.option(
        "--allow-credential-mixing/--deny-credential-mixing",
        default=None,
        help="allow reviewed source inputs alongside live credentialed connectors",
    ),
    click.option(
        "--connector-timeout-seconds",
        "--connector-timeout",
        "connector_timeout_seconds",
        type=float,
        callback=_connector_timeout_option,
        help="per-connector completion deadline in seconds (default: 120); --connector-timeout is a"
        " deprecated alias; thread workers use cooperative cancellation",
    ),
    click.option(
        "--max-coverage-gap",
        "max_coverage_gap",
        type=float,
        default=None,
        callback=_max_coverage_gap_option,
        help="share of examined entries that may be left unread before a scan reports itself"
        " incomplete (default: 0.02); 0 fails on any gap. A gap the scanner cannot bound"
        " (an early stop, a refused page) always fails closed, whatever this allows",
    ),
    click.option(
        "--plugin-execution",
        type=click.Choice(["thread", "process"]),
        default=None,
        help="third-party connector execution backend (default: process); process enables worker termination",
    ),
    click.option(
        "--allow-plugin",
        multiple=True,
        help="allow one reviewed third-party connector: NAME, or NAME=module:Class to pin its target,"
        " optionally with @distribution==version (repeatable)",
    ),
    click.option(
        "--allow-signature-override/--deny-signature-override",
        default=None,
        help="explicitly allow a reviewed custom pack to replace built-in signatures",
    ),
    click.option(
        "--allow-private-origin/--deny-private-origin",
        default=None,
        help="allow private HTTPS endpoints for this scan; origin restrictions still apply;"
        " --deny-private-origin also overrides every connector-level allow_private_origin",
    ),
]


# Incremental state, report output, inventory, signature and gating options.
report_options = [
    click.option(
        "--incremental/--no-incremental",
        default=None,
        help="reuse completed scans when input content and signatures are unchanged",
    ),
    click.option(
        "--state-dir",
        type=click.Path(file_okay=False),
        help="private incremental state directory, outside scanned repositories",
    ),
    click.option(
        "--format",
        "-f",
        "fmt",
        type=click.Choice(FORMATS),
        default="table",
        show_default=True,
        help="output format",
    ),
    click.option(
        "--output",
        "-o",
        type=click.Path(dir_okay=False),
        help="write the report to a file (table format also prints to the terminal)",
    ),
    click.option(
        "--inventory",
        "-i",
        multiple=True,
        help="sanctioned inventory: Agent Capability Cards dir/file, agents.yaml or CSV (repeatable)",
    ),
    click.option(
        "--signatures",
        "-s",
        "signature_dirs",
        multiple=True,
        help="extra signature pack directory (repeatable)",
    ),
    click.option(
        "--min-confidence",
        type=float,
        default=0.0,
        show_default=True,
        callback=_min_confidence_option,
        help="drop findings below this confidence (finite 0–1)",
    ),
    click.option(
        "--fail-on",
        type=click.Choice(LEVELS),
        help="exit 2 if any finding reaches this risk level",
    ),
    click.option("--max-rows", type=int, default=None, help="limit rows printed in table mode"),
    click.option(
        "--dump-records",
        type=click.Path(file_okay=False),
        help="directory for sanitized connector records (JWTs are never exported)",
    ),
]


def add_options(options: Sequence[Callable[[Any], Any]]) -> Callable[[F], F]:
    """Apply click option decorators so that help lists them in the given order."""

    def _wrap(fn: F) -> F:
        for opt in reversed(options):
            fn = opt(fn)
        return fn

    return _wrap


@dataclass(frozen=True)
class ScanOptions:
    """The options every scanning command shares, parsed by :func:`scan_options`."""

    job_deadline_seconds: float | None
    allow_instance_credentials: bool | None
    allow_credential_mixing: bool | None
    connector_timeout_seconds: float | None
    max_coverage_gap: float | None
    allow_plugin: tuple[str, ...]
    plugin_execution: str | None
    allow_signature_override: bool | None
    allow_private_origin: bool | None
    incremental: bool | None
    state_dir: str | None
    fmt: str
    output: str | None
    inventory: tuple[str, ...]
    signature_dirs: tuple[str, ...]
    min_confidence: float
    fail_on: str | None
    max_rows: int | None
    dump_records: str | None

    def config(self, connectors: list[ConnectorSpec]) -> ScanConfig:
        """Configure a scan of connectors that a command built from its own arguments."""
        return ScanConfig(
            connectors=connectors,
            inventory=list(self.inventory),
            signature_dirs=list(self.signature_dirs),
            min_confidence=self.min_confidence,
            fail_on=self.fail_on,
            dump_records=self.dump_records,
            incremental=bool(self.incremental),
            state_dir=self.state_dir,
        )


_SCAN_OPTION_NAMES = tuple(field.name for field in fields(ScanOptions))


def scan_options(command: Callable[..., None]) -> Callable[..., None]:
    """Add the shared security and report options, passed to ``command`` as one ``opts``."""

    @functools.wraps(command)
    def invoke(*args: Any, **kwargs: Any) -> None:
        shared = {name: kwargs.pop(name) for name in _SCAN_OPTION_NAMES}
        command(*args, opts=ScanOptions(**shared), **kwargs)

    return add_options([*security_options, *report_options])(invoke)


def _apply_security_options(cfg: ScanConfig, opts: ScanOptions) -> None:
    """Command-line approvals and deadlines override the configuration when given."""
    cfg.plugins = list(dict.fromkeys([*cfg.plugins, *opts.allow_plugin]))
    if opts.plugin_execution is not None:
        cfg.plugin_execution = opts.plugin_execution
    if opts.allow_signature_override is not None:
        cfg.allow_signature_override = opts.allow_signature_override
    if opts.allow_private_origin is not None:
        cfg.allow_private_origin = opts.allow_private_origin
        # --deny-private-origin also overrides connector-level grants.
        cfg.deny_private_origin = not opts.allow_private_origin
    if opts.allow_instance_credentials is not None:
        cfg.allow_instance_credentials = opts.allow_instance_credentials
    if opts.allow_credential_mixing is not None:
        cfg.allow_credential_mixing = opts.allow_credential_mixing
    if opts.connector_timeout_seconds is not None:
        cfg.connector_timeout_seconds = opts.connector_timeout_seconds
    if opts.max_coverage_gap is not None:
        cfg.max_coverage_gap = opts.max_coverage_gap
    if opts.job_deadline_seconds is not None:
        cfg.job_deadline_seconds = opts.job_deadline_seconds


def _run_scan(
    cfg: ScanConfig,
    opts: ScanOptions,
    only: list[str] | None = None,
    *,
    extra_stats: list[ScanStats] | None = None,
) -> None:
    """Apply the shared security options, then run the scan and emit its report."""
    _apply_security_options(cfg, opts)
    verbose: int = main.verbose  # type: ignore[attr-defined]
    _run_and_emit(cfg, opts.fmt, opts.output, verbose, opts.max_rows, only=only, extra_stats=extra_stats)


def _warn_argv_secret(what: str, instead: str) -> None:
    # Never echo the value: the warning names only where the secret was given.
    err_console.print(
        Text(
            f"warning: {what} on the command line can be read from process listings and "
            f"shell history; pass credentials with {instead} instead",
            style="yellow",
        )
    )


class _UsageError(click.UsageError):
    """A Click usage error, shown unchanged, that exits 1 instead of 2.

    Exit 2 means a complete scan reached ``--fail-on``. A mistyped option,
    invalid value or missing file stops the command before it scans anything,
    like a configuration error, so a CI gate must not read it as a policy result.
    """

    exit_code = 1

    def __init__(self, error: click.UsageError) -> None:
        super().__init__(error.message, error.ctx)
        self.error = error

    def format_message(self) -> str:
        return self.error.format_message()

    def __str__(self) -> str:
        return str(self.error)

    def show(self, file: IO[Any] | None = None) -> None:
        self.error.show(file)


_GLOBAL_OPTIONS = frozenset({"-v", "--verbose", "-q", "--quiet"})


def _with_placement_hint(error: click.UsageError) -> click.UsageError:
    """Say where -v/-q go when they were typed after the command, the natural place."""
    if isinstance(error, click.NoSuchOption) and error.option_name in _GLOBAL_OPTIONS:
        hint = " (-v/--verbose and -q/--quiet go before the command: shadowscan -v <command> ...)"
        return click.NoSuchOption(error.option_name, message=error.format_message() + hint, ctx=error.ctx)
    return error


class _MainGroup(click.Group):
    """Root group: usage errors of every command, raised while parsing or running, exit 1."""

    def make_context(
        self,
        info_name: str | None,
        args: list[str],
        parent: click.Context | None = None,
        **extra: Any,
    ) -> click.Context:
        try:
            return super().make_context(info_name, args, parent, **extra)
        except click.UsageError as exc:
            raise _UsageError(_with_placement_hint(exc)) from None

    def invoke(self, ctx: click.Context) -> Any:
        # Subcommand parsing and callbacks run inside the root invocation.
        try:
            return super().invoke(ctx)
        except click.UsageError as exc:
            raise _UsageError(_with_placement_hint(exc)) from None


@click.group(cls=_MainGroup, context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="shadowscan")
@click.option("-v", "--verbose", count=True, help="-v info, -vv debug")
@click.option("-q", "--quiet", is_flag=True, help="errors only")
def main(verbose: int, quiet: bool) -> None:
    """ShadowScan — discover shadow AI agents across code, identity, gateways, low-code, SaaS,
    cloud, endpoints, network logs and running processes.
    """
    # Click answers --help and --version before this callback runs, so those
    # still work everywhere; every command fails closed on a host that cannot
    # enforce the documented path confinement (Windows, no O_NOFOLLOW).
    try:
        require_supported_platform()
    except UnsupportedPlatformError as exc:
        raise click.ClickException(str(exc)) from None
    _setup_logging(verbose, quiet)
    main.verbose = verbose  # type: ignore[attr-defined]


# Register subcommand modules — each adds its commands to ``main``.
from shadowscan.cli import (  # noqa: E402, F401
    _connectors,
    _controls,
    _dashboard,
    _diff,
    _endpoint,
    _inventory,
    _jwt,
    _mcp_registry,
    _merge,
    _scan,
    _signatures,
)

# Backward-compat re-exports: tests monkeypatch these via "shadowscan.cli.<name>".
from shadowscan.reporters.dashboard import render_dashboard as render_dashboard  # noqa: E402

# The click commands were importable from the single cli.py module, so a script
# that invokes one directly (``from shadowscan.cli import scan``) keeps working.
# They are looked up on first use rather than imported here: the command
# modules import this package, and an import back from them would be a cycle.
_COMMAND_MODULES = {
    "code": "_scan",
    "controls_command": "_controls",
    "dashboard_command": "_dashboard",
    "diff": "_diff",
    "endpoint": "_endpoint",
    "gateway": "_scan",
    "inventory": "_inventory",
    "inventory_check": "_inventory",
    "inventory_stubs": "_inventory",
    "jwt": "_jwt",
    "list_connectors": "_connectors",
    "mcp_registry": "_mcp_registry",
    "mcp_registry_snapshot": "_mcp_registry",
    "merge_command": "_merge",
    "run": "_scan",
    "scan": "_scan",
    "signatures": "_signatures",
    "signatures_list": "_signatures",
    "signatures_show": "_signatures",
    "signatures_test": "_signatures",
}


def __getattr__(name: str) -> Any:
    module = _COMMAND_MODULES.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(sys.modules[f"{__name__}.{module}"], name)
