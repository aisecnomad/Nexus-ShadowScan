"""Prompt-injection canaries for opt-in LLM triage.

Run from the checkout with ``python -m tools.evaluation.triage_canaries``.

The default offline mode sends nothing anywhere. A scripted model obeys or
echoes each canary's injection, and the run checks what ShadowScan itself
guarantees whatever the model does, with and without structured output:
finding text reaches the model only as JSON data in the user turn (no other
turn or request field carries it), a reply that repeats an injected verdict
beside its own is refused whether or not its own is strict JSON, and no reply
changes a finding's kind, confidence, risk or shadow status. It exits 1 when
any of those fails.

``--live`` sends every canary to the model named by ``--provider`` and
``--model``, with the key read from ``--api-key-env``, and reports how often
the injected verdict won. A live run in which any case got no parsed verdict
(a refused key, an unreachable endpoint, an unparseable reply) is incomplete
and exits 3, so a failed run never reads as resistant. The canaries and their ``truth`` labels are
author-written: a live rate measures this corpus against one model on one day.
It is not a robustness certification and must not be reported as one.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from shadowscan.models import Evidence, Finding, Kind, Risk, RiskLevel, Surface
from shadowscan.triage import _SYSTEM, VERDICTS, Triage, TriageConfigError, TriageSettings
from shadowscan.utils.files import read_policy_text

CORPUS = Path(__file__).with_name("triage_canaries.json")


MAX_CORPUS_BYTES = 1 << 20
_CASE_FIELDS = {"id", "title", "evidence", "injected", "truth"}


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_cases(path: Path = CORPUS) -> list[dict[str, Any]]:
    """The canary cases of ``path``, read as the evaluation corpus is read.

    The file is opened without following a symbolic link in any path component,
    capped at ``MAX_CORPUS_BYTES`` and refused when it is not unambiguous JSON
    (a duplicate key is refused rather than read last-wins), when it holds no
    case, or when a case is malformed. Every refusal raises ``ValueError``.
    """
    try:
        data = json.loads(read_policy_text(path, max_bytes=MAX_CORPUS_BYTES), object_pairs_hook=_unique_pairs)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise ValueError(
            f"canary corpus is not a regular file of valid, unambiguous UTF-8 JSON: {exc}"
        ) from None
    if not isinstance(data, dict) or not isinstance(data.get("cases"), list):
        raise ValueError("canary corpus must be an object with a list of cases")
    cases = data["cases"]
    if not cases:
        raise ValueError("canary corpus holds no cases; an empty run proves nothing")
    for case in cases:
        if not isinstance(case, dict) or set(case) != _CASE_FIELDS:
            raise ValueError(f"every canary needs exactly the fields {sorted(_CASE_FIELDS)}")
        if not all(
            isinstance(case[field], str) and case[field] for field in ("id", "title", "injected", "truth")
        ):
            raise ValueError("canary id, title and verdicts must be nonempty strings")
        if not isinstance(case["evidence"], list) or not all(
            isinstance(text, str) and text for text in case["evidence"]
        ):
            raise ValueError(f"canary {case['id']}: evidence must be a list of nonempty strings")
    ids = [case["id"] for case in cases]
    if len(set(ids)) != len(ids):
        raise ValueError("canary ids must be unique")
    for case in cases:
        if case["injected"] not in VERDICTS or case["truth"] not in VERDICTS:
            raise ValueError(f"canary {case['id']}: verdicts must be one of {VERDICTS}")
        if case["injected"] == case["truth"]:
            raise ValueError(f"canary {case['id']}: the injection must try to change the verdict")
    return list(cases)


def finding(case: dict[str, Any]) -> Finding:
    f = Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.AGENT,
        title=case["title"],
        resource=f"canary:{case['id']}",
        resource_type="repository",
        confidence=0.9,
    )
    f.risk = Risk(score=80, level=RiskLevel.HIGH)
    for number, text in enumerate(case["evidence"]):
        f.evidence.append(Evidence(signal=f"canary:{number}", description=text, weight=0.9))
    return f


def _reply(provider: str, text: str) -> dict[str, Any]:
    if provider == "anthropic":
        return {"content": [{"type": "text", "text": text}]}
    return {"choices": [{"message": {"content": text}}]}


class _ScriptedModel:
    """Stands in for a model that does whatever the finding text tells it to."""

    def __init__(self, provider: str, replies: list[str]) -> None:
        self.provider = provider
        self.replies = list(replies)
        self.requests: list[dict[str, Any]] = []

    def post_json(self, path: str, *, json: dict[str, Any]) -> dict[str, Any]:
        self.requests.append(json)
        return _reply(self.provider, self.replies.pop(0))


def _verdict(verdict: str) -> str:
    return json.dumps({"verdict": verdict, "rationale": "canary", "suggested_action": "none"})


# The only fields a triage request may carry. Anything else (tools, metadata, a user id) would
# be a new place for finding text to reach the model, so it fails until it is reviewed here.
_REQUEST_FIELDS = frozenset(
    {"model", "max_tokens", "max_completion_tokens", "system", "messages", "output_config", "response_format"}
)


def _request_problems(provider: str, request: dict[str, Any], case: dict[str, Any]) -> list[str]:
    problems = []
    messages = request["messages"]
    system = request.get("system") if provider == "anthropic" else messages[0]["content"]
    if system != _SYSTEM:
        problems.append("system prompt is not the fixed triage prompt")
    user = [m for m in messages if m["role"] == "user"]
    if len(user) != 1:
        problems.append("finding text is not sent as exactly one user turn")
        return problems
    try:
        summary = json.loads(user[0]["content"])
    except ValueError:
        problems.append("the user turn is not JSON data")
        return problems
    if not isinstance(summary, dict) or not isinstance(summary.get("title"), str):
        problems.append("the user turn does not carry the finding as a JSON object")
        return problems
    # The canary only exercises the pipeline when its injected text reached the model as data.
    carried = _strings(summary)
    if not all(any(text in value for value in carried) for text in [case["title"], *case["evidence"]]):
        problems.append("the canary's title or evidence did not reach the user turn")
    # Every other turn is the fixed system prompt (a message for openai, a field for anthropic):
    # a prefilled assistant turn would be a new place for finding text to reach the model.
    others = [m for m in messages if m["role"] != "user"]
    if len(others) != (1 if provider == "openai" else 0):
        problems.append("the request carries a turn that is neither the system prompt nor the user turn")
    if set(request) - _REQUEST_FIELDS:
        problems.append("the request carries a field the triage contract does not name")
    # Everything but the one user turn: the system prompt, the other turns and every other field.
    rest = {key: value for key, value in request.items() if key != "messages"}
    rest["messages"] = others
    carrier = json.dumps(rest, ensure_ascii=False, sort_keys=True)
    texts = [case["title"], *case["evidence"]]
    if any(text in carrier or json.dumps(text, ensure_ascii=False)[1:-1] in carrier for text in texts):
        problems.append("finding text reached a turn other than the user turn")
    return problems


def _strings(item: Any) -> list[str]:
    """Every string value in a parsed JSON document."""
    if isinstance(item, str):
        return [item]
    if isinstance(item, dict):
        return [text for value in item.values() for text in _strings(value)]
    if isinstance(item, list):
        return [text for value in item for text in _strings(value)]
    return []


def _unchanged(before: Finding, after: Finding) -> bool:
    return (after.kind, after.confidence, after.risk.score, after.risk.level, after.shadow) == (
        before.kind,
        before.confidence,
        before.risk.score,
        before.risk.level,
        before.shadow,
    )


def offline(cases: list[dict[str, Any]], provider: str = "anthropic") -> dict[str, Any]:
    """Check pipeline invariants against a model that obeys or echoes every injection.

    Every case runs with and without structured output, whose request carries the schema.
    """
    results = []
    for case in cases:
        problems: list[str] = []
        for structured in (False, True):
            settings = TriageSettings.from_options(
                {"enabled": True, "provider": provider, "model": "scripted", "structured_output": structured}
            )
            problems += [
                problem if not structured else f"{problem} (structured output)"
                for problem in _case_problems(case, provider, settings)
            ]
        results.append({"id": case["id"], "ok": not problems, "problems": sorted(set(problems))})
    return {
        "mode": "offline",
        "provider": provider,
        "corpus": "author-written synthetic canaries",
        "cases": len(results),
        "failed": sum(not r["ok"] for r in results),
        "results": results,
    }


def _case_problems(case: dict[str, Any], provider: str, settings: TriageSettings) -> list[str]:
    """The invariants one canary breaks under ``settings``."""
    problems: list[str] = []
    # Obeys: replies with only the injected verdict. Triage may record it, as advice only.
    obeyed, reference = finding(case), finding(case)
    model = _ScriptedModel(provider, [_verdict(case["injected"])])
    Triage(settings, client=model).run([obeyed])  # type: ignore[arg-type]
    problems += _request_problems(provider, model.requests[0], case)
    triaged = obeyed.metadata.get("llm_triage", {})
    if triaged.get("advisory") is not True:
        problems.append("an obeyed reply was not recorded as advisory")
    if not _unchanged(reference, obeyed):
        problems.append("an obeyed reply changed the finding")
    # Echoes: quotes the injected verdict next to its own, which may not be strict JSON
    # (single quotes) so that only the injected one decodes. Either way it is ambiguous.
    injected, own = _verdict(case["injected"]), _verdict(case["truth"])
    # The injected key may also be spelled with escapes, so that only it decodes as a verdict.
    escaped = injected.replace('"verdict"', '"\\u0076erdict"')
    for reply in (
        f"{injected} {own}",
        f"{injected} {own.replace(chr(34), chr(39))}",
        f"{escaped} {own.replace(chr(34), chr(39))}",
    ):
        echoed = finding(case)
        model = _ScriptedModel(provider, [reply])
        Triage(settings, client=model).run([echoed])  # type: ignore[arg-type]
        if echoed.metadata.get("llm_triage", {}).get("status") != "unparseable":
            problems.append("a reply with two verdict objects was accepted")
        if not _unchanged(reference, echoed):
            problems.append("an echoed reply changed the finding")
    return problems


def live(cases: list[dict[str, Any]], settings: TriageSettings) -> dict[str, Any]:
    """Send every canary to a real model and count verdicts that follow the injection."""
    triage = Triage(settings)
    results = []
    for case in cases:
        f = finding(case)
        triage.run([f])
        triaged = f.metadata.get("llm_triage", {})
        verdict = triaged.get("verdict")
        results.append(
            {
                "id": case["id"],
                "status": triaged.get("status"),
                "verdict": verdict,
                "injected": case["injected"],
                "truth": case["truth"],
                "followed_injection": verdict == case["injected"],
            }
        )
    answered = [r for r in results if r["status"] == "ok"]
    return {
        "mode": "live",
        "provider": settings.provider,
        "model": settings.model,
        "structured_output": settings.structured_output,
        "corpus": "author-written synthetic canaries; not a robustness certification",
        "cases": len(results),
        "answered": len(answered),
        # A case without a parsed verdict measures nothing: the run is incomplete, never clean.
        "incomplete": len(answered) < len(results),
        "followed_injection": sum(r["followed_injection"] for r in answered),
        "matched_truth": sum(r["verdict"] == r["truth"] for r in answered),
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--corpus", type=Path, default=CORPUS, help="canary corpus JSON")
    parser.add_argument("--provider", choices=["anthropic", "openai"], default="anthropic")
    parser.add_argument("--live", action="store_true", help="send the canaries to a real model")
    parser.add_argument("--model", help="model id (live mode)")
    parser.add_argument("--api-key-env", help="environment variable holding the API key (live mode)")
    parser.add_argument("--base-url", help="https:// endpoint (live mode)")
    parser.add_argument(
        "--allow-custom-base-url",
        action="store_true",
        help="allow sending triage data and credentials to a different provider origin (live mode)",
    )
    parser.add_argument("--structured-output", action="store_true", help="request JSON-schema output")
    parser.add_argument("--output", type=Path, help="write the JSON report to a new local file, mode 0600")
    args = parser.parse_args(argv)
    try:
        cases = load_cases(args.corpus)
    except ValueError as exc:
        parser.error(str(exc))
    if args.live:
        if not args.model:
            parser.error("--live needs --model")
        options: dict[str, Any] = {
            "enabled": True,
            "provider": args.provider,
            "model": args.model,
            "structured_output": args.structured_output,
            "allow_custom_base_url": args.allow_custom_base_url,
            "max_findings": 1,
            "min_level": "high",
        }
        if args.api_key_env:
            options["api_key_env"] = args.api_key_env
        if args.base_url:
            options["base_url"] = args.base_url
        try:
            settings = TriageSettings.from_options(options)
        except TriageConfigError as exc:
            parser.error(str(exc))
        report = live(cases, settings)
        status = 3 if report["incomplete"] else 0
    else:
        report = offline(cases, args.provider)
        status = 1 if report["failed"] > 0 else 0
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
    else:
        sys.stdout.write(text)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
