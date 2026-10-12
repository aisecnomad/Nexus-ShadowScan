"""CLI for the estate benchmark: validate, freeze, run, score, report."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from tools.discovery_benchmark.adapters import ToolConfig
from tools.discovery_benchmark.runner import RunPolicy
from tools.shadowbench.estate import report as report_mod
from tools.shadowbench.estate import runner as runner_mod
from tools.shadowbench.estate import score as score_mod
from tools.shadowbench.estate.corpus import CorpusError, load_corpus


def _estate_files(estate: Path) -> list[Path]:
    return sorted(path for path in estate.rglob("*") if path.is_file())


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def cmd_validate(corpus_path: Path, estate: Path) -> int:
    corpus = load_corpus(corpus_path)
    problems: list[str] = []
    for entity in corpus.entities:
        texts: list[str] = []
        for artifact in entity.artifacts:
            path = estate / artifact
            if not path.exists():
                problems.append(f"{entity.id}: missing artifact {artifact}")
                continue
            if path.is_dir():
                texts.extend(f.read_text(encoding="utf-8", errors="replace") for f in _estate_files(path))
            else:
                texts.append(path.read_text(encoding="utf-8", errors="replace"))
        raw = "\n".join(texts)
        # Base64url is case-sensitive: decode JWT payloads from the raw text,
        # then lowercase everything for the anchor search.
        joined = (raw + _decoded_jwt_payloads(raw)).lower()
        primary = entity.anchors[0]
        in_artifacts = primary in joined or primary in "/".join(entity.artifacts).lower()
        # A composite anchor (host:user:tool) is grounded when every part appears.
        if not in_artifacts and ":" in primary:
            # Parts under 4 characters are connector-synthesized abbreviations
            # (e.g. "mcp" in a resource id), not artifact content.
            in_artifacts = all(part in joined for part in primary.split(":") if len(part) >= 4)
        if joined and not in_artifacts:
            problems.append(f"{entity.id}: primary anchor {primary!r} not found in its artifacts")
    for path in _estate_files(estate):
        if path.is_symlink():
            problems.append(f"symlink in estate: {path}")
    if problems:
        for problem in problems:
            print(f"PROBLEM {problem}")
        return 1
    print(
        f"OK {len(corpus.entities)} entities "
        f"({len(corpus.by_class('positive'))} positive, "
        f"{len(corpus.by_class('control'))} control, "
        f"{len(corpus.by_class('nearmiss'))} near-miss)"
    )
    return 0


def cmd_freeze(corpus_path: Path, estate: Path, out: Path) -> int:
    files = {str(path.relative_to(estate.parent)): _sha256(path) for path in _estate_files(estate)}
    files[corpus_path.name] = _sha256(corpus_path)
    out.write_text(json.dumps({"schema": 1, "sha256": files}, indent=1) + "\n", encoding="utf-8")
    print(f"froze {len(files)} files -> {out}")
    return 0


def cmd_verify_freeze(corpus_path: Path, estate: Path, freeze_path: Path) -> int:
    recorded = json.loads(freeze_path.read_text(encoding="utf-8"))["sha256"]
    current = {str(path.relative_to(estate.parent)): _sha256(path) for path in _estate_files(estate)}
    current[corpus_path.name] = _sha256(corpus_path)
    drift = sorted(
        set(recorded) ^ set(current)
        | {name for name in set(recorded) & set(current) if recorded[name] != current[name]}
    )
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

    p_validate = sub.add_parser("validate", help="validate the corpus and anchor presence")
    p_validate.add_argument("--corpus", type=Path, default=default_corpus)
    p_validate.add_argument("--estate", type=Path, default=default_estate)

    p_freeze = sub.add_parser("freeze", help="write the sha256 freeze manifest")
    p_freeze.add_argument("--corpus", type=Path, default=default_corpus)
    p_freeze.add_argument("--estate", type=Path, default=default_estate)
    p_freeze.add_argument("--out", type=Path, default=Path("benchmarks/shadowbench/estate/FREEZE.json"))

    p_verify = sub.add_parser("verify-freeze", help="check the estate against the freeze manifest")
    p_verify.add_argument("--corpus", type=Path, default=default_corpus)
    p_verify.add_argument("--estate", type=Path, default=default_estate)
    p_verify.add_argument("--freeze", type=Path, default=Path("benchmarks/shadowbench/estate/FREEZE.json"))

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
            return cmd_validate(args.corpus, args.estate)
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
