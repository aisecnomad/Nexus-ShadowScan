"""Bounded cross-file source orchestration for the filesystem scanner.

This collaborator indexes already-read Python/JavaScript snapshots and binds
queued consumers only once the walk has observed project modules/configuration.
The FileScanner retains file reads, ordinary matching, redaction and evidence
recording; this coordinator never opens or executes scanned source.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from shadowscan.connectors.code.javascript_project_tools import has_ai_sdk_import, has_local_tool_import
from shadowscan.connectors.code.python_dispatch import DispatchLimitError, has_dispatch_import
from shadowscan.connectors.code.python_reexports import ReexportLimitError, has_local_import, project_path
from shadowscan.connectors.code.scan_records import _local_module_predicate, _MatchedSource, _SourceFile
from shadowscan.connectors.code.source_semantics import SourceBudgetExceeded
from shadowscan.connectors.code.walk import isolated, scan_timeout_for_size
from shadowscan.signatures.matcher import WALL_BUDGET_FACTOR

if TYPE_CHECKING:
    from shadowscan.connectors.code.file_scan import FileScanner
    from shadowscan.connectors.code.filesystem import _ScanState


class CrossFileSources:
    """Coordinates bounded snapshot indexes through the file scanner's evidence methods."""

    def __init__(self, scanner: FileScanner) -> None:
        self.scanner = scanner

    def index(self, scan: _ScanState, file: _SourceFile, text: str) -> None:
        """Retain bounded cross-file descriptors without preventing ordinary source analysis."""
        if self.scanner.triage:
            return
        try:
            scan.javascript_tools.add(file.proj_root, file.rel, text, file.ext)
            if file.ext == ".py":
                scan.python_dispatches.add(file.proj_root, file.rel, text)
        except SourceBudgetExceeded as exc:
            self.scanner.ctx.error(
                f"code.filesystem: {file.rel}: {exc}; analysis incomplete", reason="analysis-limit"
            )

    def defer(self, scan: _ScanState, source: _MatchedSource, *, max_files: int, max_bytes: int) -> bool:
        """Keep cross-file consumers within one fixed memory and file budget."""
        file = source.file
        if file.lang == "javascript":
            candidate = has_ai_sdk_import(source.text)
            # If the queue or deadline is exhausted, fallback evidence must not
            # pretend configuration was checked before trusting an SDK name.
            file.vercel_sdk_unresolved = candidate
        elif file.ext == ".py":
            scan.reexports.add(file.proj_root, file.rel, file.text)
            local = _local_module_predicate(scan.root, file.path, file.proj_root)
            root_reexport = len(project_path(file.proj_root, file.rel).parts) == 1 and has_local_import(
                file.text, local
            )
            # Root-flat shims retain their existing behavior. Nested dispatch
            # consumers additionally need SDK import evidence: ordinary local
            # imports cannot produce provider loops and need no queued pass
            # (or the eager excerpt redaction that queued sources require).
            provider_imported = any(
                match.signature.category == "provider" or match.signature_id == "platform.litellm"
                for match in source.imports
            )
            candidate = root_reexport or provider_imported and has_dispatch_import(file.text, local)
        else:
            candidate = False
        if not candidate:
            return False
        size = len(file.text.encode("utf-8"))
        if len(scan.reexport_files) >= max_files or scan.reexport_bytes + size > max_bytes:
            analysis = self.analysis(source).removesuffix(" analysis")
            self.scanner.ctx.error(
                f"code.filesystem: {file.rel}: {analysis} source budget exceeded",
                reason="analysis-limit",
            )
            return False
        scan.reexport_files.append(source)
        scan.reexport_bytes += size
        file.reexport_pending = True
        return True

    def resolve(self, scan: _ScanState) -> None:
        """Bind queued consumers after all shim snapshots have been read safely.

        The walk already matched their imports and code patterns. Each binder
        starts under the walk's own rule: only while its matching budget and
        the walk's margin fit before the connector deadline, so the findings
        already collected are still emitted in time. A consumer left unbound is
        named, keeps its lexical evidence and makes the results incomplete.
        """
        deadline = self.scanner.ctx.deadline
        for position, source in enumerate(scan.reexport_files):
            file = source.file
            analysis = self.analysis(source)
            size = len(file.text.encode("utf-8"))
            budget = scan_timeout_for_size(self.scanner.scan_timeout, size)
            wall_cap = budget * WALL_BUDGET_FACTOR
            if deadline is not None:
                remaining = deadline - time.monotonic()
                # As in the walk, the binder's wall cap never runs into the deadline's margin.
                wall_cap = max(budget, min(wall_cap, remaining - scan.margin))
                if remaining < budget + scan.margin:
                    if remaining > scan.margin + self.scanner.scan_timeout:
                        self.scanner.ctx.error(
                            f"code.filesystem: {file.rel}: {analysis} skipped; the remaining "
                            f"connector deadline cannot cover its {budget:.0f}s matching budget; "
                            "lexical evidence retained",
                        )
                        self._retain([source], deadline - scan.margin / 2)
                        continue
                    others = len(scan.reexport_files) - position - 1
                    queued = f" and {others} other queued files" if others else ""
                    self.scanner.ctx.error(
                        f"code.filesystem: connector deadline reached before {analysis} of "
                        f"{file.rel}{queued}; results incomplete",
                    )
                    self._retain(scan.reexport_files[position:], deadline - scan.margin / 2)
                    break
            with (
                isolated(self.scanner.walker, file.rel, analysis),
                self.scanner.index.scan_budget(seconds=budget, chars=size, wall_seconds=wall_cap),
            ):
                try:
                    self._bind(scan, source)
                except (ReexportLimitError, DispatchLimitError, SourceBudgetExceeded) as exc:
                    self.scanner.ctx.error(
                        f"code.filesystem: {file.rel}: {exc}; analysis incomplete", reason="analysis-limit"
                    )
                    self.scanner._bind_source(source)
        # The walk redacted every queued consumer (see scan_file), so settling
        # only cuts the excerpts its matches asked for, reached or not.
        for source in scan.reexport_files:
            self.scanner._settle_excerpts(source.file)
        scan.reexport_files.clear()

    @staticmethod
    def analysis(source: _MatchedSource) -> str:
        return (
            "JavaScript tool-import analysis"
            if source.file.lang == "javascript"
            else "Python re-export analysis"
        )

    def _bind(self, scan: _ScanState, source: _MatchedSource) -> None:
        """Resolve cross-file evidence solely from the walk's confined snapshots."""
        file = source.file
        if file.lang == "javascript":
            file.vercel_sdk_unresolved = not scan.javascript_tools.ai_sdk_is_external(
                file.proj_root, file.rel
            )
            if scan.javascript_tools.full:
                raise SourceBudgetExceeded("JavaScript SDK module resolution catalog limit exceeded")
            extra = (
                scan.javascript_tools.matches(
                    self.scanner.index, file.proj_root, file.rel, source.text, source.ignored
                )
                if not file.vercel_sdk_unresolved and has_local_tool_import(source.text)
                else []
            )
            self.scanner._bind_source(source, extra_bound=extra)
        else:
            resolver = scan.reexports.resolver(file.proj_root, source.is_local_module)
            self.scanner._bind_source(
                source,
                resolve_import=resolver,
                resolve_dispatch=scan.python_dispatches.resolver(file.proj_root, file.rel),
            )

    def _retain(self, sources: list[_MatchedSource], until: float) -> None:
        """Record the walk's lexical evidence for queued consumers the binder cannot read.

        As for a file over the binder's budget, the lexical matches stand in for
        the whole file. Recording stops at ``until``, like the walk's own final
        count, so the findings collected so far are still emitted in time.
        """
        for source in sources:
            if time.monotonic() >= until:
                return
            with isolated(self.scanner.walker, source.file.rel, self.analysis(source)):
                self.scanner._record_source(source, [], [(0, len(source.text))])
