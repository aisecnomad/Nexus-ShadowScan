"""CLI for the estate benchmark: validate, freeze, run, score, report."""

from __future__ import annotations

import argparse
import json
import posixpath
import sys
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path

from tools.discovery_benchmark.adapters import ToolConfig
from tools.discovery_benchmark.runner import RunPolicy
from tools.shadowbench.estate import report as report_mod
from tools.shadowbench.estate import runner as runner_mod
from tools.shadowbench.estate import score as score_mod
from tools.shadowbench.estate.corpus import (
    FREEZE_SCHEMA,
    CorpusError,
    EstateCorpus,
    EstateTree,
    UnsafeEstateError,
    freeze_digests,
    freeze_drift,
    load_corpus,
    load_freeze,
    open_regular,
    unit_dir,
    walk_estate,
)


def _decoded_jwt_payloads(text: str) -> str:
    """Base64url-decoded segments of JWT-shaped tokens found in `text`.

    Anchors of token entities are claim values, which live inside the encoded
    artifact; decoding keeps the grounded-anchor rule meaningful for them.
    """
    import base64
    import re

    decoded: list[str] = []
    for match in re.finditer(r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*", text):
        for segment in match.group(0).split(".")[:2]:
            padded = segment + "=" * (-len(segment) % 4)
            try:
                decoded.append(base64.urlsafe_b64decode(padded).decode("utf-8", "ignore").lower())
            except ValueError:
                continue
    return "\n".join(decoded)


def _artifact_files(artifact: str, tree: EstateTree) -> list[str] | None:
    """The estate files an artifact path covers (a file, or every file below a directory)."""
    rel = posixpath.normpath(artifact)
    if rel == ".":
        return list(tree.files)
    if rel in tree.files:
        return [rel]
    if rel in tree.dirs:
        return [path for path in tree.files if path.startswith(rel + "/")]
    return None


def _anchor_collisions(
    corpus: EstateCorpus,
    tree: EstateTree,
    owned: dict[str, set[str]],
    haystack: Callable[[str], str],
) -> list[str]:
    """Anchors that also occur in estate files outside their own entity's artifacts.

    A tool reporting something from such a file can carry the anchor and be
    attributed to the wrong entity. Each file is searched with its estate
    path, because tools echo paths. These are warnings: some are deliberate
    (the agent registry names registered entities, the live-sim services
    file names the runtime entities it mirrors).
    """
    owners: dict[str, list[str]] = defaultdict(list)
    for entity in corpus.entities:
        for rel in owned[entity.id]:
            owners[rel].append(entity.id)
    lines: list[str] = []
    for entity in corpus.entities:
        for anchor in entity.anchors:
            hits = [rel for rel in tree.files if rel not in owned[entity.id] and anchor in haystack(rel)]
            if not hits:
                continue
            places = []
            for rel in hits:
                others = sorted(owners.get(rel, []))
                if not others:
                    places.append(f"{rel} (no entity)")
                    continue
                more = f" and {len(others) - 3} more" if len(others) > 3 else ""
                places.append(f"{rel} (artifact of {', '.join(others[:3])}{more})")
            lines.append(f"{entity.id}: anchor {anchor!r} also occurs in {'; '.join(places)}")
    return lines


def cmd_validate(corpus_path: Path, estate: Path, *, strict: bool = False) -> int:
    corpus = load_corpus(corpus_path)
    tree = walk_estate(estate)
    problems = [f"symlink or special file in estate: {rel}" for rel in tree.rejected]
    raw: dict[str, str] = {}
    searchable: dict[str, str] = {}

    def raw_text(rel: str) -> str:
        if rel not in raw:
            with open_regular(estate / rel) as handle:
                raw[rel] = handle.read().decode("utf-8", errors="replace")
        return raw[rel]

    def haystack(rel: str) -> str:
        if rel not in searchable:
            text = raw_text(rel)
            searchable[rel] = f"{rel}\n{text}{_decoded_jwt_payloads(text)}".lower()
        return searchable[rel]

    owned: dict[str, set[str]] = {}
    for entity in corpus.entities:
        texts: list[str] = []
        owned[entity.id] = set()
        for artifact in entity.artifacts:
            members = _artifact_files(artifact, tree)
            if members is None:
                problems.append(f"{entity.id}: missing artifact {artifact}")
                continue
            owned[entity.id].update(members)
            texts.extend(raw_text(rel) for rel in members)
        joined_raw = "\n".join(texts)
        # Base64url is case-sensitive: decode JWT payloads from the raw text,
        # then lowercase everything for the anchor search.
        joined = (joined_raw + _decoded_jwt_payloads(joined_raw)).lower()
        primary = entity.anchors[0]
        in_artifacts = primary in joined or primary in "/".join(entity.artifacts).lower()
        # A composite anchor (host:user:tool) is grounded when every part appears.
        if not in_artifacts and ":" in primary:
            # Parts under 4 characters are connector-synthesized abbreviations
            # (e.g. "mcp" in a resource id), not artifact content.
            in_artifacts = all(part in joined for part in primary.split(":") if len(part) >= 4)
        # Empty artifacts ground nothing: the anchor must still be found.
        if not in_artifacts:
            problems.append(f"{entity.id}: primary anchor {primary!r} not found in its artifacts")
        directory = unit_dir(entity.unit)
        if directory is not None and directory not in tree.dirs:
            problems.append(f"{entity.id}: unit {entity.unit} has no directory {directory} in the estate")
    collisions = _anchor_collisions(corpus, tree, owned, haystack)
    for collision in collisions:
        print(f"WARN {collision}")
    if strict and collisions:
        problems.append(f"{len(collisions)} anchor collisions (--strict)")
    if problems:
        for problem in problems:
            print(f"PROBLEM {problem}")
        return 1
    print(
        f"OK {len(corpus.entities)} entities "
        f"({len(corpus.by_class('positive'))} positive, "
        f"{len(corpus.by_class('control'))} control, "
        f"{len(corpus.by_class('nearmiss'))} near-miss)"
        + (f", {len(collisions)} anchor collision warnings" if collisions else "")
    )
    return 0


def _current_freeze(corpus_path: Path, estate: Path) -> dict[str, str] | None:
    """The digests a freeze records, or None (with the reasons printed) for an unsafe estate."""
    try:
        return freeze_digests(corpus_path, estate)
    except UnsafeEstateError as exc:
        for entry in exc.entries:
            print(f"PROBLEM symlink or special file in estate: {entry}")
        return None


def cmd_freeze(corpus_path: Path, estate: Path, out: Path) -> int:
    files = _current_freeze(corpus_path, estate)
    if files is None:
        return 1
    out.write_text(json.dumps({"schema": FREEZE_SCHEMA, "sha256": files}, indent=1) + "\n", encoding="utf-8")
    print(f"froze {len(files)} files -> {out}")
    return 0


def cmd_verify_freeze(corpus_path: Path, estate: Path, freeze_path: Path) -> int:
    recorded = load_freeze(freeze_path)
    current = _current_freeze(corpus_path, estate)
    if current is None:
        return 1
    drift = freeze_drift(recorded, current)
    if drift:
        for name in drift:
            print(f"DRIFT {name}")
        return 1
    print(f"OK {len(current)} files match the freeze manifest")
    return 0


def _adapters() -> list[object]:
    from tools.shadowbench.estate.adapters.registry import all_adapters

    return list(all_adapters())


def cmd_run(args: argparse.Namespace) -> int:
    corpus = load_corpus(args.corpus)
    cfg = ToolConfig.load(args.tools)
    extra_path = tuple(p for p in cfg.setting("extra_path").split(":") if p)
    policy = RunPolicy(
        timeout=args.timeout,
        as_user=args.as_user,
        extra_path=extra_path,
        keep_network=args.keep_network,
    )
    adapters = _adapters()
    only = set(args.only.split(",")) if args.only else None
    runner_mod.run_matrix(
        corpus,
        adapters,  # type: ignore[arg-type]
        cfg,
        args.estate.resolve(),
        args.out,
        policy,
        workers=args.workers,
        only=only,
    )
    print(f"wrote {args.out / 'runs.json'}")
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    corpus = load_corpus(args.corpus)
    manifest = json.loads(args.runs.read_text(encoding="utf-8"))
    specs = {
        adapter.spec.id: {  # type: ignore[attr-defined]
            "name": adapter.spec.name,  # type: ignore[attr-defined]
            "surfaces": sorted(adapter.spec.surfaces),  # type: ignore[attr-defined]
        }
        for adapter in _adapters()
    }
    metrics = score_mod.score_all(corpus, manifest, specs)
    args.out.write_text(json.dumps(metrics, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    corpus = load_corpus(args.corpus)
    metrics = json.loads(args.metrics.read_text(encoding="utf-8"))
    args.out.write_text(report_mod.render(metrics, corpus, title=args.title), encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m tools.shadowbench.estate")
    sub = parser.add_subparsers(dest="command", required=True)

    default_corpus = Path("benchmarks/shadowbench/estate/corpus.json")
    default_estate = Path("benchmarks/shadowbench/estate/artifacts")
    default_freeze = Path("benchmarks/shadowbench/estate/FREEZE.json")

    p_validate = sub.add_parser("validate", help="validate the corpus and anchor presence")
    p_validate.add_argument("--corpus", type=Path, default=default_corpus)
    p_validate.add_argument("--estate", type=Path, default=default_estate)
    p_validate.add_argument(
        "--strict", action="store_true", help="fail on anchor collisions instead of warning"
    )

    p_freeze = sub.add_parser("freeze", help="write the sha256 freeze manifest")
    p_freeze.add_argument("--corpus", type=Path, default=default_corpus)
    p_freeze.add_argument("--estate", type=Path, default=default_estate)
    p_freeze.add_argument("--out", type=Path, default=default_freeze)

    p_verify = sub.add_parser("verify-freeze", help="check the estate against the freeze manifest")
    p_verify.add_argument("--corpus", type=Path, default=default_corpus)
    p_verify.add_argument("--estate", type=Path, default=default_estate)
    p_verify.add_argument("--freeze", type=Path, default=default_freeze)

    p_run = sub.add_parser("run", help="run every adapter against its estate units")
    p_run.add_argument("--corpus", type=Path, default=default_corpus)
    p_run.add_argument("--estate", type=Path, default=default_estate)
    p_run.add_argument("--tools", type=Path, required=True)
    p_run.add_argument("--out", type=Path, required=True)
    p_run.add_argument("--workers", type=int, default=4)
    p_run.add_argument("--timeout", type=int, default=900)
    p_run.add_argument("--as-user", default=None)
    p_run.add_argument("--keep-network", action="store_true")
    p_run.add_argument("--only", default="")

    p_score = sub.add_parser("score", help="score runs.json against the corpus")
    p_score.add_argument("--corpus", type=Path, default=default_corpus)
    p_score.add_argument("--runs", type=Path, required=True)
    p_score.add_argument("--out", type=Path, required=True)

    p_report = sub.add_parser("report", help="render metrics.json as Markdown")
    p_report.add_argument("--corpus", type=Path, default=default_corpus)
    p_report.add_argument("--metrics", type=Path, required=True)
    p_report.add_argument("--out", type=Path, required=True)
    p_report.add_argument("--title", default="ShadowBench: shadow AI agent discovery estate benchmark")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "validate":
            return cmd_validate(args.corpus, args.estate, strict=args.strict)
        if args.command == "freeze":
            return cmd_freeze(args.corpus, args.estate, args.out)
        if args.command == "verify-freeze":
            return cmd_verify_freeze(args.corpus, args.estate, args.freeze)
        if args.command == "run":
            return cmd_run(args)
        if args.command == "score":
            return cmd_score(args)
        if args.command == "report":
            return cmd_report(args)
    except CorpusError as exc:
        print(f"corpus error: {exc}", file=sys.stderr)
        return 2
    raise AssertionError("unreachable")


if __name__ == "__main__":
    raise SystemExit(main())
