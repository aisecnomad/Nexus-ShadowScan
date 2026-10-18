"""Turn the failures in pytest JUnit reports into GitHub Actions error annotations.

A failed CI test step says only "Process completed with exit code 1" in the
check-run annotations, which are what the pull request page and the checks API
show. The failing test's name is in the job log, which a reader without log
access cannot open. Run after a failed test step, this prints one ``::error``
workflow command per failing or erroring test case, at most
:data:`MAX_ANNOTATIONS` of them, so each failing test is named where the check
is read.

An annotation carries the test's node id, its file and line, the exception type
and the first line of the failure message. The message is passed through the
scanner's own redaction first and cut to :data:`MAX_MESSAGE` characters: test
inputs are synthetic, but some are shaped like credentials, and a workflow log
is no place for one.

    python -m tools.test_annotations "$RUNNER_TEMP"/junit-*.xml
"""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ElementTree
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

#: GitHub keeps at most 10 error annotations per step and 50 per job.
MAX_ANNOTATIONS = 50
#: Characters of the failure message kept after redaction.
MAX_MESSAGE = 200


@dataclass(frozen=True)
class Failure:
    """One failing or erroring test case of a JUnit report."""

    node_id: str
    file: str
    line: int | None
    kind: str
    message: str


def _escape_data(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(text: str) -> str:
    return _escape_data(text).replace(":", "%3A").replace(",", "%2C")


def _redact(text: str) -> str:
    """The first line of ``text``, with credential-shaped values withheld, cut to MAX_MESSAGE."""
    from shadowscan.utils.redaction import sanitize_text

    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    printable = "".join(character if character.isprintable() else "?" for character in first)
    return sanitize_text(printable)[:MAX_MESSAGE]


def _node_id(case: ElementTree.Element) -> tuple[str, str]:
    """The pytest node id of ``case`` and its file, from the JUnit classname and name."""
    classname = case.get("classname", "")
    name = case.get("name", "")
    # pytest writes classname as the dotted module path, then any class names.
    parts = classname.split(".") if classname else []
    module: list[str] = []
    for index in range(len(parts), 0, -1):
        candidate = Path(*parts[:index]).with_suffix(".py")
        if candidate.exists():
            module = parts[:index]
            break
    if not module:
        return f"{classname}::{name}" if classname else name, case.get("file", "")
    path = Path(*module).with_suffix(".py").as_posix()
    return "::".join([path, *parts[len(module) :], name]), path


def failures(reports: Iterable[Path]) -> Iterator[Failure]:
    """Every failing or erroring test case in ``reports``, in report order."""
    for report in reports:
        # Only this job's own pytest report is parsed, never a scanned input.
        tree = ElementTree.parse(report)
        for case in tree.iter("testcase"):
            problem = case.find("failure")
            if problem is None:
                problem = case.find("error")
            if problem is None:
                continue
            node_id, file = _node_id(case)
            line = case.get("line")
            yield Failure(
                node_id=node_id,
                file=case.get("file") or file,
                # JUnit lines are 0-based; annotations count from 1.
                line=int(line) + 1 if line and line.isdigit() else None,
                kind=(problem.get("type") or problem.tag).rsplit(".", 1)[-1],
                message=_redact(problem.get("message") or ""),
            )


def annotation(failure: Failure) -> str:
    """The ``::error`` workflow command for ``failure``."""
    properties = [f"title={_escape_property(failure.node_id)}"]
    if failure.file:
        properties.insert(0, f"file={_escape_property(failure.file)}")
        if failure.line is not None:
            properties.insert(1, f"line={failure.line}")
    text = failure.kind + (f": {failure.message}" if failure.message else "")
    return f"::error {','.join(properties)}::{_escape_data(text)}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("reports", nargs="*", type=Path, help="pytest --junitxml reports")
    arguments = parser.parse_args(argv)
    reports = [report for report in arguments.reports if report.is_file()]
    found = list(failures(reports))
    for failure in found[:MAX_ANNOTATIONS]:
        print(annotation(failure))
    if len(found) > MAX_ANNOTATIONS:
        print(f"{len(found) - MAX_ANNOTATIONS} more failing test(s) are not annotated; see the job log")
    print(f"{len(found)} failing test(s) in {len(reports)} report(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
