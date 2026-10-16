"""Network logs: AI services contacted, from DNS, TLS SNI and flow records.

``network.logs`` reads exported network telemetry and reports, per client
address, the AI services it contacted:

* DNS queries: Zeek ``dns.log``, Amazon Route 53 Resolver query logs, or any
  JSON/CSV with a query name and a client address;
* TLS server names: Zeek ``ssl.log`` or any record with an ``sni`` /
  ``server_name`` field;
* flows: Zeek ``conn.log`` and AWS VPC Flow Logs. A flow carries no host
  name, so it is attributed only through the same input: by Zeek ``uid`` to
  the TLS record of the same client/connection, or to the AI host that the same
  client resolved to that address. An address that also resolved to a host
  of another service (a shared CDN address) attributes nothing through DNS.
  Known non-AI or conflicting TLS evidence never falls back to DNS.

DNS answers are kept per context, client and address as merged validity
intervals per service host, so repeated lookups cost nothing extra. Storage
overflow disables DNS attribution only for the client/address it affects.

Host names are matched exactly or by a signature's declared wildcard, never by
substring, so ``www.anthropologie.com`` is not Anthropic. Only names that
match an AI signature are kept; other queries are counted, never stored.

The connector is offline: it reads files and makes no network request.
Malformed lines and unrecognised records make the scan incomplete.
"""

from __future__ import annotations

import bisect
import functools
import ipaddress
import json
import math
import re
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

from shadowscan.connectors.agent_behavior import (
    LOOP_MAX_GAP_SECONDS,
    LOOP_MIN_CALLS,
    host_service,
    loop_cadence,
)
from shadowscan.connectors.base import (
    BaseConnector,
    ConnectorContext,
    ConnectorError,
    _NoDump,
    _positive_limit,
)
from shadowscan.connectors.common import finalize
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.signatures import Match
from shadowscan.utils.safe_json import strict_json_loads
from shadowscan.utils.text import parse_timestamp

_FORMATS = {None, "auto", "zeek", "route53", "vpc-flow", "generic"}
_SUFFIXES = {".json", ".jsonl", ".ndjson", ".csv", ".log", ".txt", ".gz"}
# Domain signals below this weight are hints (a vendor's marketing site), not service use.
_MIN_HOST_WEIGHT = 0.3
_MAX_CLIENTS = 50_000
_MAX_PAIRS = 500_000
# Flow times inside one connection group are kept in bounded buckets so DNS
# validity is checked per flow time without one group per timestamp. A group
# starts with exact timestamps and coarsens (aligned, doubling widths) past
# this many buckets; buckets beyond each group's first share a scan budget.
_MAX_BUCKETS_PER_PAIR = 64
_MAX_TOTAL_BUCKETS = 500_000
_MAX_HOSTS_PER_FINDING = 20
_MAX_TIMES = 1_000
_MAX_TOTAL_TIMES = 200_000
# DNS answers are stored per (context, client, address) as merged validity
# intervals. The budget counts addresses and stored intervals across the input;
# each address keeps at most this many AI intervals (beyond them it is marked
# unattributable) and this many non-AI intervals (beyond them the closest are
# merged, which can only widen negative evidence).
_MAX_DNS_SPANS = 500_000
_MAX_DNS_SPANS_PER_ADDRESS = 1_024
_MAX_OTHER_SPANS_PER_ADDRESS = 16
_DNS_OVERFLOW = (
    "DNS answers for an address exceeded storage bounds; its flows were not attributed through DNS"
)
_DNS_UNRETAINED = (
    "Some DNS answers for this client were not retained; port attribution was not checked against them"
)
_PROVENANCE_SAMPLED = "DNS attribution provenance is sampled to 20 entries"
_MAX_JA4_PER_CONTACT = 32
_MAX_DNS_PROVENANCE = 20
_JA4 = re.compile(r"^[tqd](?:1[0-3]|s[23]|d[123]|00)[di][0-9]{4}[a-zA-Z0-9]{2}_[a-f0-9]{12}_[a-f0-9]{12}$")
_Context = tuple[str, str, str]
_DNSKey = tuple[_Context, str, str]
_TLSKey = tuple[_Context, str, str]
_PairKey = tuple[_Context, str, str, int | None, str | None]
_OLLAMA_PORT = 11434
_VPC_DEFAULT_FIELDS = [
    "version",
    "account-id",
    "interface-id",
    "srcaddr",
    "dstaddr",
    "srcport",
    "dstport",
    "protocol",
    "packets",
    "bytes",
    "start",
    "end",
    "action",
    "log-status",
]
_HOST = re.compile(
    r"^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,62}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,62}[a-z0-9_])?)*$"
)

# Field names of generic exports, in order of preference.
_QUERY_FIELDS = ("query", "qname", "query_name", "question", "domain", "dns_query")
_SNI_FIELDS = ("sni", "server_name", "tls_sni", "servername")
_CLIENT_FIELDS = (
    "client",
    "client_ip",
    "src_ip",
    "source_ip",
    "srcaddr",
    "src",
    "id.orig_h",
    "device",
    "host_ip",
)
_SERVER_FIELDS = ("dst_ip", "dest_ip", "destination_ip", "dstaddr", "server_ip", "id.resp_h", "dst")
_PORT_FIELDS = ("dst_port", "dest_port", "dstport", "id.resp_p", "port")
_TIME_FIELDS = ("ts", "timestamp", "time", "query_timestamp", "@timestamp", "start", "event_time")


@dataclass
class _Contact:
    """One client's traffic to one AI service."""

    client: str
    signature: str
    hosts: Counter = field(default_factory=Counter)
    dns_queries: int = 0
    tls_connections: int = 0
    flows: int = 0
    flows_by_dns: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    first: float | None = None
    last: float | None = None
    times: list[float] = field(default_factory=list)
    dns_attributions: list[dict[str, Any]] = field(default_factory=list)
    ja4: set[tuple[str, str, _Context, str | None]] = field(default_factory=set)
    ja4_incomplete: bool = False
    context: _Context | None = None
    mixed_contexts: bool = False
    limitations: set[str] = field(default_factory=set)


@dataclass
class _Span:
    """A merged DNS validity interval ``[start, end)`` of one service host at one address.

    ``start`` is always an answer's observation time; ``ttl`` and ``own_end``
    describe that first answer, so provenance can show when later answers
    extended the interval.
    """

    start: float
    end: float
    ttl: float
    own_end: float


@dataclass
class _AddressDNS:
    """One client's DNS answers for one address in one observation context.

    ``spans`` maps (signature, host) to sorted, disjoint, non-touching
    intervals; non-AI answers share the key ("", ""). ``unknown`` holds the
    signatures of answers whose validity is unknown (no timestamp or TTL).
    A ``lossy`` address lost an answer to a storage bound and attributes
    nothing through DNS.
    """

    spans: dict[tuple[str, str], list[_Span]] = field(default_factory=dict)
    unknown: set[str] = field(default_factory=set)
    signatures: set[str] = field(default_factory=set)
    ai_spans: int = 0
    lossy: bool = False

    def stored(self) -> int:
        return sum(len(spans) for spans in self.spans.values())


def _span_start(span: _Span) -> float:
    return span.start


def _insert_span(spans: list[_Span], start: float, end: float, ttl: float) -> int:
    """Merge ``[start, end)`` into sorted disjoint ``spans``; return the change in their number.

    Overlapping or touching intervals merge: every time in the union is inside
    at least one answer's own validity window, so the union stays exact.
    """
    index = bisect.bisect_left(spans, start, key=_span_start)
    low = index - 1 if index > 0 and spans[index - 1].end >= start else index
    high = index
    while high < len(spans) and spans[high].start <= end:
        high += 1
    if low == high:
        spans.insert(low, _Span(start, end, ttl, end))
        return 1
    first = spans[low]
    if start < first.start or (start == first.start and end > first.own_end):
        first = _Span(start, end, ttl, end)
    merged = _Span(first.start, max(end, spans[high - 1].end), first.ttl, first.own_end)
    spans[low:high] = [merged]
    return 1 - (high - low)


def _coarsen_spans(spans: list[_Span]) -> None:
    """Merge the two neighbouring intervals with the smallest gap (non-AI evidence only).

    The merged interval covers the gap, so it can only make more flows
    ambiguous: never use it to attribute.
    """
    if len(spans) < 2:
        return
    _, index = min((spans[i + 1].start - spans[i].end, i) for i in range(len(spans) - 1))
    left, right = spans[index], spans[index + 1]
    spans[index : index + 2] = [_Span(left.start, right.end, left.ttl, left.own_end)]


def _span_at(spans: list[_Span], when: float) -> _Span | None:
    """The interval containing ``when``, found by bisection."""
    index = bisect.bisect_right(spans, when, key=_span_start) - 1
    return spans[index] if index >= 0 and when < spans[index].end else None


def _overlaps(spans: list[_Span], first: float, last: float) -> bool:
    """Whether any interval meets the closed range ``[first, last]``."""
    index = bisect.bisect_right(spans, last, key=_span_start) - 1
    return index >= 0 and first < spans[index].end


class _DNSStore:
    """Bounded DNS validity per (context, client, address); see ``_MAX_DNS_SPANS``.

    A repeated answer merges into the interval it overlaps or touches, so it
    costs nothing. When a bound is reached, only the client/address concerned
    loses DNS attribution: an existing address is marked ``lossy``, and an
    address that could not be stored at all records its client in
    ``dropped_clients`` (a later address of that client starts lossy, since an
    earlier answer for it may have been dropped).
    """

    def __init__(self) -> None:
        self.addresses: dict[_DNSKey, _AddressDNS] = {}
        self.used = 0
        self.dropped = 0
        self.dropped_clients: set[str] = set()

    def add(
        self,
        key: _DNSKey,
        signature: str,
        host: str,
        window: tuple[float, float] | None,
        ttl: float | None,
    ) -> bool:
        """Record one answer; False when its address could not be stored at all."""
        state = self.addresses.get(key)
        if state is None:
            if self.used >= _MAX_DNS_SPANS:
                self.dropped += 1
                self.dropped_clients.add(key[1])
                return False
            state = self.addresses[key] = _AddressDNS(lossy=key[1] in self.dropped_clients)
            self.used += 1
        if signature:
            state.signatures.add(signature)
        if state.lossy:
            return True
        if window is None or ttl is None:
            if ttl is None:
                # Unknown validity may conflict with any window; a zero TTL never does.
                state.unknown.add(signature)
            return True
        spans = state.spans.setdefault((signature, host) if signature else ("", ""), [])
        added = _insert_span(spans, window[0], window[1], ttl)
        if signature:
            if added > 0 and (
                state.ai_spans + added > _MAX_DNS_SPANS_PER_ADDRESS or self.used + added > _MAX_DNS_SPANS
            ):
                self._lose(state, added)
                return True
            state.ai_spans += added
        elif added > 0 and (len(spans) > _MAX_OTHER_SPANS_PER_ADDRESS or self.used + added > _MAX_DNS_SPANS):
            if len(spans) < 2:
                self._lose(state, added)
                return True
            _coarsen_spans(spans)
            added -= 1
        self.used += added
        return True

    def _lose(self, state: _AddressDNS, uncounted: int) -> None:
        """Mark an address unattributable and release its intervals (``uncounted`` were never charged)."""
        self.used -= state.stored() - uncounted
        state.spans.clear()
        state.unknown.clear()
        state.ai_spans = 0
        state.lossy = True
        self.dropped += 1


@dataclass
class _Bucket:
    """Flows of one connection group whose times fall in one aligned interval."""

    first: float
    last: float
    flows: int = 0
    bytes_out: int = 0
    bytes_in: int = 0

    def merge(self, other: _Bucket) -> None:
        self.first = min(self.first, other.first)
        self.last = max(self.last, other.last)
        self.flows += other.flows
        self.bytes_out += other.bytes_out
        self.bytes_in += other.bytes_in


@dataclass
class _Pair:
    """Flows sharing context, client, server, port and connection UID (when available).

    Timed flows sit in ``buckets``: exact timestamps while ``width`` is 0,
    then aligned intervals of ``width`` seconds. Each coarsening doubles the
    width, so an old bucket always falls inside exactly one new one and its
    ``first``/``last`` bounds stay exact. Untimed flows are counted apart.
    """

    flows: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    first: float | None = None
    last: float | None = None
    times: list[float] = field(default_factory=list)
    width: float = 0.0
    buckets: dict[float, _Bucket] = field(default_factory=dict)
    untimed_flows: int = 0
    untimed_bytes_out: int = 0
    untimed_bytes_in: int = 0

    def key(self, when: float) -> float:
        return when if self.width == 0 else float(math.floor(when / self.width))

    def coarsen(self) -> int:
        """Double the bucket width; return how many buckets merged away."""
        before = len(self.buckets)
        self.width = 1.0 if self.width == 0 else self.width * 2
        merged: dict[float, _Bucket] = {}
        for bucket in self.buckets.values():
            key = self.key(bucket.first)
            if key in merged:
                merged[key].merge(bucket)
            else:
                merged[key] = bucket
        self.buckets = merged
        return before - len(merged)


@dataclass
class _TLSIdentity:
    """Bounded service identity for a client/UID, including negative evidence."""

    server: str | None
    port: int | None
    signature: str
    ambiguous: bool = False

    def observe(self, server: str | None, port: int | None, signature: str) -> None:
        if self.signature != signature or not self.matches(server, port):
            self.ambiguous = True
        self.server = self.server or server
        self.port = self.port if self.port is not None else port

    def matches(self, server: str | None, port: int | None) -> bool:
        return (self.server is None or server is None or self.server == server) and (
            self.port is None or port is None or self.port == port
        )


class NetworkLogConnector(BaseConnector, _NoDump):
    name: ClassVar[str] = "network.logs"
    surface: ClassVar[Surface] = Surface.NETWORK
    provider: ClassVar[str | None] = "network"
    description: ClassVar[str] = (
        "AI services contacted per client address, from DNS, TLS SNI and flow logs (Zeek, Route 53 Resolver, "
        "VPC Flow Logs, generic exports)."
    )
    config_keys: ClassVar[dict[str, str]] = {
        "input": (
            "log file or directory: Zeek dns/ssl/conn logs (TSV or JSON), Route 53 Resolver query logs, VPC "
            "Flow Logs or generic JSON/CSV DNS and SNI records"
        ),
        "format": "force the input format: zeek|route53|vpc-flow|generic (default auto, per record)",
        "label": "network or sensor name used in resource ids and as the finding account (default: network)",
        "max_records": "stop after N records (default 10,000,000)",
        "dns_max_ttl_seconds": "cap DNS attribution validity at N seconds (default 86400, maximum 604800)",
        "dns_clock_skew_seconds": (
            "extend DNS expiry by N seconds; never allow future answers (default 0, maximum 60)"
        ),
    }
    offline_formats: ClassVar[str] = "Zeek TSV / JSON, Route 53 Resolver JSON, VPC Flow Logs text, JSON / CSV"

    def __init__(self, ctx: ConnectorContext) -> None:
        super().__init__(ctx)
        self.format = ctx.get("format")
        if self.format not in _FORMATS:
            raise ConnectorError("network.logs: unsupported format")
        self.label = str(ctx.get("label") or "network")
        self.max_records = _positive_limit(ctx.get("max_records", 10_000_000), "max_records")
        self.dns_max_ttl = _positive_limit(ctx.get("dns_max_ttl_seconds", 86400), "dns_max_ttl_seconds")
        skew = ctx.get("dns_clock_skew_seconds", 0)
        if isinstance(skew, bool) or not isinstance(skew, int) or not 0 <= skew <= 60:
            raise ConnectorError("network.logs: dns_clock_skew_seconds must be an integer from 0 to 60")
        if self.dns_max_ttl > 604800:
            raise ConnectorError("network.logs: dns_max_ttl_seconds must not exceed 604800")
        self.dns_clock_skew = skew
        self._records = 0
        self._limit_reported = False
        self._host_cache: dict[str, Match | None] = {}
        # Record defects, by what they can hide from flow attribution (see
        # _defect and _note). Any other diagnostic is treated as global.
        self._global_defect = False
        self._defect_clients: set[str] = set()
        self._scoped_diagnostics = 0

    def _defect(self, message: str, client: Any) -> None:
        """An incomplete record that may have carried DNS or TLS evidence.

        With a known client only that client's flow attribution is disabled;
        without one, the discarded record could contradict any client's.
        """
        self._scoped_diagnostics += 1
        address = _text(client)
        if address:
            self._defect_clients.add(_address(address))
        else:
            self._global_defect = True
        self.ctx.warn(message)

    def _note(self, message: str) -> None:
        """An incomplete record that cannot contradict any attribution.

        The record is kept with the defective field unknown (an untimed flow, a
        DNS answer of unknown validity), or it is a flow-only record whose loss
        removes bytes but never DNS or TLS evidence.
        """
        self._scoped_diagnostics += 1
        self.ctx.warn(message)

    def collect(self) -> Iterable[dict[str, Any]]:
        raise ConnectorError(
            "network.logs: this connector reads exported logs; set 'input' to a file or directory"
        )

    # ------------------------------------------------------------------ input
    def load_offline(self, path: str) -> Iterator[dict[str, Any]]:
        budget = self._offline_budget()
        for source in self._iter_offline_files(path, budget, _SUFFIXES):
            suffix = source.suffix.lower()
            if suffix == ".csv":
                for rec in self._load_offline_file(source, budget):
                    yield from self._limited(self._normalise(rec, source.name))
                continue
            if suffix == ".json":
                text = self._read_offline_text(source, budget)
                if text is None:
                    continue
                yield from self._limited(self._json_document(text, source.name))
                continue
            yield from self._limited(self._text_lines(source, budget, suffix))

    def _limited(self, records: Iterable[dict[str, Any]]) -> Iterator[dict[str, Any]]:
        for rec in records:
            if self._records >= self.max_records:
                if not self._limit_reported:
                    self.ctx.warn(f"network.logs: stopped after max_records ({self.max_records:,}) records")
                    self._limit_reported = True
                return
            self._records += 1
            yield rec

    def _json_document(self, text: str, name: str) -> Iterator[dict[str, Any]]:
        if not text.strip():
            self.ctx.error(f"network.logs: {name}: empty export; use [] for an empty JSON export")
            return
        try:
            data = strict_json_loads(text)
        except (json.JSONDecodeError, RecursionError, ValueError):
            # One JSON object per line under a .json name (Zeek's JSON writer).
            yield from self._json_rows(text.splitlines(), name)
            return
        rows = (
            data
            if isinstance(data, list)
            else data.get("records", [data])
            if isinstance(data, dict)
            else None
        )
        if not isinstance(rows, list):
            self.ctx.warn(f"network.logs: {name}: unrecognized JSON document")
            return
        for row in rows:
            yield from self._normalise(row, name)

    def _json_rows(self, lines: Iterable[str], name: str) -> Iterator[dict[str, Any]]:
        saw = False
        for number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            saw = True
            try:
                row = strict_json_loads(line)
            except (json.JSONDecodeError, RecursionError, ValueError):
                self.ctx.warn(f"network.logs: {name}: invalid JSON at line {number}")
                continue
            yield from self._normalise(row, name)
        if not saw:
            self.ctx.error(f"network.logs: {name}: empty export")

    def _text_lines(self, source: Path, budget: Any, suffix: str) -> Iterator[dict[str, Any]]:
        lines = self._iter_bounded_lines(source, budget, compressed=suffix == ".gz")
        zeek_fields: list[str] | None = None
        zeek_path = ""
        separator = "\t"
        set_separator = ","
        vpc_fields: list[str] | None = None
        saw = False
        for number, raw in enumerate(lines, 1):
            line = raw.rstrip("\r\n")
            if not line.strip():
                continue
            saw = True
            if line.startswith("#"):
                directive, _, value = line.partition(separator if line.startswith("#fields") else " ")
                if line.startswith("#separator"):
                    separator = _zeek_escape(line.split(" ", 1)[1]) if " " in line else "\t"
                    if not separator:
                        # str.split("") raises ValueError; one malformed header must not
                        # abort the connector and lose the other log files. Fail this file closed.
                        self.ctx.warn(f"network.logs: {source.name}: empty Zeek #separator", incomplete=True)
                        return
                elif line.startswith("#set_separator"):
                    set_separator = line.split(separator, 1)[1] if separator in line else ","
                elif directive == "#fields":
                    zeek_fields = value.split(separator)
                elif line.startswith("#path"):
                    zeek_path = line.split(separator, 1)[1].strip() if separator in line else ""
                continue
            if line.lstrip().startswith("{"):
                yield from self._json_rows([line], f"{source.name} line {number}")
                continue
            if zeek_fields is not None:
                values = line.split(separator)
                if len(values) != len(zeek_fields):
                    self.ctx.warn(f"network.logs: {source.name}: malformed Zeek line {number}")
                    continue
                row: dict[str, Any] = {"_path": zeek_path}
                for key, value in zip(zeek_fields, values, strict=True):
                    if value in {"-", "(empty)"}:
                        continue
                    row[key] = value.split(set_separator) if key in {"answers", "TTLs"} else value
                yield from self._normalise(row, source.name)
                continue
            tokens = line.split()
            if tokens and tokens[0] == "version" and "srcaddr" in tokens:
                vpc_fields = tokens
                continue
            fields = vpc_fields or (_VPC_DEFAULT_FIELDS if len(tokens) == 14 and tokens[0] == "2" else None)
            if fields is not None and len(tokens) == len(fields):
                yield from self._vpc_flow(dict(zip(fields, tokens, strict=True)), source.name, number)
                continue
            self.ctx.warn(f"network.logs: {source.name}: unrecognized line {number}")
        if not saw:
            self.ctx.warn(f"network.logs: {source.name}: empty log")

    # -------------------------------------------------------------- normalise
    def _normalise(self, row: Any, name: str) -> Iterator[dict[str, Any]]:
        """One input row as dns / tls / flow events; nothing for other traffic."""
        if not isinstance(row, dict):
            self.ctx.warn(f"network.logs: {name}: records must be objects")
            return
        fmt = self.format if self.format not in (None, "auto") else _detect(row)
        context = self._context(row, name, flow_only=fmt == "vpc-flow")
        if context is None:
            return
        if fmt == "route53":
            client = _text(row.get("srcaddr"))
            query = _host(row.get("query_name"))
            answers = [
                text
                for a in row.get("answers") or []
                if isinstance(a, dict) and (text := _text(a.get("Rdata")))
            ]
            # Route 53 query exports normally omit TTLs: preserve observations,
            # but require explicitly supplied TTL metadata for flow attribution.
            yield from self._dns(name, client, query, answers, row.get("query_timestamp"), row, context)
            return
        if fmt == "vpc-flow":
            yield from self._vpc_flow(row, name, None)
            return
        if fmt is None:
            # Whatever this record was, only the client it names could rely on it.
            self._defect(f"network.logs: {name}: unrecognized record", _first(row, _CLIENT_FIELDS))
            return
        client = _text(_first(row, _CLIENT_FIELDS))
        when = _first(row, _TIME_FIELDS)
        query = _host(_first(row, _QUERY_FIELDS))
        sni = _host(_first(row, _SNI_FIELDS))
        server = _text(_first(row, _SERVER_FIELDS))
        port = _int(_first(row, _PORT_FIELDS))
        path = str(row.get("_path") or "")
        if query is not None or path == "dns":
            raw = row.get("answers") or []
            values = raw.split(",") if isinstance(raw, str) else raw if isinstance(raw, list) else []
            answers = [text for a in values if (text := _text(a))]
            yield from self._dns(name, client, query, answers, when, row, context)
            return
        ts = _seconds(when)
        if when is not None and ts is None:
            self._note(f"network.logs: {name}: invalid event timestamp")
        if sni is not None or path == "ssl":
            if not client:
                self._defect(f"network.logs: {name}: TLS record without a client address", None)
                return
            if sni is None:
                return  # a TLS connection without SNI names nothing
            yield {
                "kind": "tls", "ts": ts, "client": client, "server": server, "port": port,
                "sni": sni, "uid": _text(_first(row, ("uid",))), "context": context,
                "ja4": self._ja4(row, name, client),
            }  # fmt: skip
            return
        if server and client:
            yield {
                "kind": "flow", "ts": ts, "client": client, "server": server, "port": port,
                "bytes_out": _int(row.get("orig_bytes") or row.get("bytes_out") or row.get("bytes")) or 0,
                "bytes_in": _int(row.get("resp_bytes") or row.get("bytes_in")) or 0,
                "uid": _text(_first(row, ("uid",))), "context": context,
            }  # fmt: skip
            return
        self._defect(f"network.logs: {name}: record has no query, server name or flow endpoints", client)

    def _context(self, row: dict[str, Any], name: str, *, flow_only: bool = False) -> _Context | None:
        values = []
        for aliases in (("sensor", "sensor_id"), ("network_id", "vpc_id"), ("resolver", "resolver_id")):
            supplied = [row[key] for key in aliases if row.get(key) not in (None, "", "-")]
            if (
                any(
                    not isinstance(value, str)
                    or len(value) > 255
                    or not value.strip()
                    or any(ord(char) < 32 for char in value)
                    for value in supplied
                )
                or len({value.strip() for value in supplied if isinstance(value, str)}) > 1
            ):
                message = f"network.logs: {name}: malformed observation context"
                if flow_only:
                    self._note(message)
                else:
                    self._defect(message, _first(row, _CLIENT_FIELDS))
                return None
            values.append(supplied[0].strip() if supplied else "")
        return values[0], values[1], values[2]

    def _ja4(self, row: dict[str, Any], name: str, client: str | None) -> tuple[str, str] | None:
        aliases = [key for key in ("ja4", "tls.ja4") if row.get(key) not in (None, "", "-")]
        if not aliases:
            return None
        values = [row[key] for key in aliases]
        if any(not isinstance(value, str) or not _JA4.fullmatch(value) for value in values) or any(
            value != values[0] for value in values
        ):
            self._defect(f"network.logs: {name}: invalid or conflicting JA4 fingerprint", client)
            return None
        return values[0], aliases[0]

    def _dns(
        self,
        name: str,
        client: str | None,
        query: str | None,
        answers: list[str],
        when: Any,
        row: dict[str, Any],
        context: _Context,
    ) -> Iterator[dict[str, Any]]:
        if not client or query is None:
            self._defect(f"network.logs: {name}: DNS record without a client address or query name", client)
            return
        ttl: float | None = None
        variants: list[list[float]] = []
        invalid = False
        for alias in ("TTLs", "ttls", "ttl", "TTL"):
            raw = row.get(alias)
            if raw in (None, "", "-"):
                continue
            vector = alias in {"TTLs", "ttls"} or isinstance(raw, list)
            values = raw.split(",") if isinstance(raw, str) else raw if isinstance(raw, list) else [raw]
            parsed = [_ttl(value) for value in values]
            if (
                not parsed
                or any(value is None for value in parsed)
                or len(values) != (len(answers) if vector else 1)
            ):
                invalid = True
                continue
            numeric = [value for value in parsed if value is not None]
            variants.append(numeric if vector else numeric * len(answers))
        if invalid or (variants and any(values != variants[0] for values in variants)):
            self._note(f"network.logs: {name}: malformed DNS TTL values or conflicting aliases")
        elif variants and variants[0]:
            # Every alias must describe the same answer TTLs. For CNAME
            # responses all links must remain valid, so use their minimum.
            ttl = min(variants[0])
        ts = _seconds(when)
        if when is not None and ts is None:
            self._note(f"network.logs: {name}: invalid DNS timestamp")
        if len(answers) > 32:
            self._defect(f"network.logs: {name}: DNS answer limit exceeded", client)
            # A dropped answer may contradict retained data; no interval.
            ttl = None
        yield {
            "kind": "dns",
            "ts": ts,
            "client": client,
            "query": query,
            "answers": [str(ipaddress.ip_address(a)) for a in answers if _ip(a)][:32],
            "ttl": ttl,
            "context": context,
        }

    def _vpc_flow(self, row: dict[str, Any], name: str, number: int | None) -> Iterator[dict[str, Any]]:
        where = f"{name} line {number}" if number else name
        # Custom exports can omit log-status, but an explicit status must be
        # valid. SKIPDATA means AWS failed to capture flows, not an idle ENI.
        raw_statuses = [row[key] for key in ("log-status", "log_status") if key in row]
        if any(not isinstance(status, str) or not status.strip() for status in raw_statuses):
            self._note(f"network.logs: {where}: invalid VPC flow log-status")
            return
        statuses = {status.strip().upper() for status in raw_statuses}
        if len(statuses) > 1 or statuses - {"OK", "NODATA", "SKIPDATA"}:
            self._note(f"network.logs: {where}: invalid VPC flow log-status")
            return
        status = next(iter(statuses), "OK")
        if status == "SKIPDATA":
            self._note(f"network.logs: {where}: VPC Flow Logs SKIPDATA reports uncaptured flows")
            return
        if status == "NODATA":
            return
        if str(row.get("action") or "ACCEPT").upper() != "ACCEPT":
            return
        context = self._context(row, name, flow_only=True)
        if context is None:
            return
        client, server = _text(row.get("srcaddr")), _text(row.get("dstaddr"))
        if not (_ip(client) and _ip(server)):
            self._note(f"network.logs: {where}: malformed VPC flow record")
            return
        ts = _seconds(row.get("start"))
        if row.get("start") is not None and ts is None:
            self._note(f"network.logs: {where}: invalid event timestamp")
        yield {
            "kind": "flow", "ts": ts, "client": client, "server": server,
            "port": _int(row.get("dstport")), "bytes_out": _int(row.get("bytes")) or 0, "bytes_in": 0,
            "uid": None, "context": context,
        }  # fmt: skip

    # ---------------------------------------------------------------- analyse
    def _service(self, host: str) -> Match | None:
        """The signature that names a host's AI service, or None."""
        if host in self._host_cache:
            return self._host_cache[host]
        best = host_service(m for m in self.index.match_domain(host) if m.weight >= _MIN_HOST_WEIGHT)
        if len(self._host_cache) < 100_000:
            self._host_cache[host] = best
        return best

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        contacts: dict[tuple[str, str], _Contact] = {}
        dns = _DNSStore()
        sni_by_uid: dict[_TLSKey, _TLSIdentity] = {}
        pairs: dict[_PairKey, _Pair] = {}
        times_used = 0
        extra_buckets = 0
        dropped_pairs = dropped_clients = dropped_tls = dropped_ja4 = 0
        clients: set[str] = set()
        for rec in records:
            self.ctx.examined()
            kind = rec.get("kind")
            client = _address(rec.get("client"))
            context = rec.get("context") or ("", "", "")
            server = _address(rec.get("server")) if rec.get("server") else None
            if client not in clients:
                if len(clients) >= _MAX_CLIENTS:
                    dropped_clients += 1
                    continue
                clients.add(client)
            ts = rec.get("ts")
            if kind in {"dns", "tls"}:
                host = str(rec.get("query") if kind == "dns" else rec.get("sni"))
                match = self._service(host)
                signature = match.signature.id if match else ""
                unretained = False
                if kind == "dns":
                    ttl = rec.get("ttl")
                    window = (
                        (ts, ts + min(ttl, self.dns_max_ttl) + self.dns_clock_skew)
                        if ts is not None and ttl is not None and ttl > 0
                        else None
                    )
                    if ts is None:
                        ttl = None  # validity unknown, as without a TTL
                    named = host if match else ""
                    for address in rec.get("answers") or []:
                        if not dns.add((context, client, address), signature, named, window, ttl):
                            unretained = True
                elif rec.get("uid"):
                    # Scope UIDs to the observation vantage as well as client.
                    # Keep non-AI SNI as negative evidence before DNS fallback.
                    uid_key = (context, client, str(rec["uid"]))
                    identity = sni_by_uid.get(uid_key)
                    if identity is not None:
                        identity.observe(server, rec.get("port"), signature)
                    elif len(sni_by_uid) < _MAX_PAIRS:
                        sni_by_uid[uid_key] = _TLSIdentity(server, rec.get("port"), signature)
                    else:
                        dropped_tls += 1
                if match is None:
                    continue
                c = self._contact(contacts, client, match.signature.id, context)
                if len(c.hosts) < _MAX_HOSTS_PER_FINDING or host in c.hosts:
                    c.hosts[host] += 1
                if kind == "dns":
                    c.dns_queries += 1
                    if ts is None or rec.get("ttl") is None:
                        c.limitations.add("DNS observations without timestamp or TTL cannot attribute flows")
                    if unretained:
                        c.limitations.add(_DNS_OVERFLOW)
                else:
                    c.tls_connections += 1
                    if rec.get("ja4"):
                        fingerprint, source_field = rec["ja4"]
                        ja4 = (
                            fingerprint,
                            source_field,
                            context,
                            str(rec["uid"]) if rec.get("uid") else None,
                        )
                        if not c.ja4_incomplete and (ja4 in c.ja4 or len(c.ja4) < _MAX_JA4_PER_CONTACT):
                            c.ja4.add(ja4)
                        else:
                            dropped_ja4 += 1
                            c.ja4_incomplete = True
                            c.ja4.clear()
                            c.limitations.add(
                                "JA4 metadata omitted because observation storage was incomplete"
                            )
                    if ts is not None and len(c.times) < _MAX_TIMES and times_used < _MAX_TOTAL_TIMES:
                        c.times.append(ts)
                        times_used += 1
                _seen(c, ts)
                continue
            if kind == "flow":
                uid = str(rec["uid"]) if rec.get("uid") else None
                key = (context, client, str(server), rec.get("port"), uid)
                pair = pairs.get(key)
                if pair is None:
                    if len(pairs) >= _MAX_PAIRS:
                        dropped_pairs += 1
                        continue
                    pair = pairs[key] = _Pair()
                bytes_out = int(rec.get("bytes_out") or 0)
                bytes_in = int(rec.get("bytes_in") or 0)
                pair.flows += 1
                pair.bytes_out += bytes_out
                pair.bytes_in += bytes_in
                if ts is None:
                    pair.untimed_flows += 1
                    pair.untimed_bytes_out += bytes_out
                    pair.untimed_bytes_in += bytes_in
                    continue
                pair.first = ts if pair.first is None else min(pair.first, ts)
                pair.last = ts if pair.last is None else max(pair.last, ts)
                if len(pair.times) < _MAX_TIMES and times_used < _MAX_TOTAL_TIMES:
                    pair.times.append(ts)
                    times_used += 1
                # Keep flow times apart, coarsening rather than dropping: a
                # bucket attributes through DNS only when one answer is valid
                # for its whole interval, so stale bytes never move into a
                # fresh answer's window (_attribute_flows).
                bucket = pair.buckets.get(pair.key(ts))
                while (
                    bucket is None
                    and pair.buckets
                    and (len(pair.buckets) >= _MAX_BUCKETS_PER_PAIR or extra_buckets >= _MAX_TOTAL_BUCKETS)
                ):
                    extra_buckets -= pair.coarsen()
                    bucket = pair.buckets.get(pair.key(ts))
                if bucket is None:
                    if pair.buckets:
                        extra_buckets += 1
                    bucket = pair.buckets[pair.key(ts)] = _Bucket(ts, ts)
                bucket.first = min(bucket.first, ts)
                bucket.last = max(bucket.last, ts)
                bucket.flows += 1
                bucket.bytes_out += bytes_out
                bucket.bytes_in += bytes_in
        # A record limit, or a defect whose client is unknown, may have
        # discarded a DNS or TLS record contradicting any client's attribution.
        # A defect in a record with a known client only affects that client.
        input_incomplete = (
            self._limit_reported
            or self._global_defect
            or (self.ctx.diagnostics_recorded() > self._scoped_diagnostics)
        )
        defect_clients = self._defect_clients
        if dropped_clients:
            self.ctx.warn(
                f"network.logs: {dropped_clients:,} record(s) from clients beyond the first {_MAX_CLIENTS:,} "
                "addresses were not analysed"
            )
        if dropped_pairs:
            self.ctx.warn(
                f"network.logs: {dropped_pairs:,} flow record(s) beyond {_MAX_PAIRS:,} connection groups "
                "were not attributed"
            )
        if dropped_tls:
            self.ctx.warn(
                f"network.logs: {dropped_tls:,} TLS record(s) beyond {_MAX_PAIRS:,} client/UID identities "
                "were not retained for flow attribution"
            )
        if dns.dropped:
            # Every finding is still reported: an AI answer that was not kept
            # still counts as a DNS query, and the affected findings carry a
            # limitation. Only flows to the affected client addresses lose
            # DNS attribution.
            self.ctx.warn(
                f"network.logs: {dns.dropped:,} DNS answer(s) exceeded storage bounds; flows to the affected "
                "client addresses were not attributed through DNS",
                incomplete=False,
            )
        if dropped_ja4:
            self.ctx.warn(
                f"network.logs: {dropped_ja4:,} JA4 observation(s) exceeded per-contact storage bound"
            )
        # Malformed/truncated input may have discarded a contradictory DNS or
        # TLS record. Keep direct observations but do not synthesize flow claims.
        ambiguous = 0
        if input_incomplete:
            for contact in contacts.values():
                contact.limitations.add("Flow attribution disabled because input was incomplete")
        else:
            for contact in contacts.values():
                if contact.client in defect_clients:
                    contact.limitations.add(
                        "Flow attribution disabled because input for this client was incomplete"
                    )
            ambiguous = self._attribute_flows(
                contacts,
                {key: pair for key, pair in pairs.items() if key[1] not in defect_clients},
                sni_by_uid,
                bool(dropped_tls),
                dns,
            )
        if ambiguous:
            self.ctx.warn(
                f"network.logs: {ambiguous:,} flow(s) with ambiguous service attribution were not attributed",
                incomplete=False,
            )
        for c in contacts.values():
            self.ctx.check_deadline()
            if input_incomplete or c.client in defect_clients:
                c.ja4.clear()
            fingerprint_sets: dict[tuple[_Context, str], set[str]] = {}
            for value, _, context, uid in c.ja4:
                if uid is not None:
                    fingerprint_sets.setdefault((context, uid), set()).add(value)
            conflicting = {key for key, values in fingerprint_sets.items() if len(values) > 1}
            if conflicting:
                self.ctx.warn("network.logs: conflicting JA4 fingerprints for a client/UID were omitted")
            # Direct TLS fingerprints are context only; conflicting UID identity
            # must not attach one endpoint's fingerprint to another endpoint.
            c.ja4 = {
                item
                for item in c.ja4
                if item[3] is None
                or (
                    (identity := sni_by_uid.get((item[2], c.client, item[3]))) is not None
                    and not identity.ambiguous
                    and identity.signature == c.signature
                    and (item[2], item[3]) not in conflicting
                )
            }
            yield self._finding(c, ambiguous)

    @staticmethod
    def _contact(
        contacts: dict[tuple[str, str], _Contact], client: str, signature: str, context: _Context
    ) -> _Contact:
        key = (client, signature)
        c = contacts.get(key)
        if c is None:
            c = contacts[key] = _Contact(client, signature)
        if c.context is not None and c.context != context:
            c.mixed_contexts = True
        c.context = c.context if c.context is not None else context
        return c

    def _attribute_flows(
        self,
        contacts: dict[tuple[str, str], _Contact],
        pairs: dict[_PairKey, _Pair],
        sni_by_uid: dict[_TLSKey, _TLSIdentity],
        tls_limit_reached: bool,
        dns: _DNSStore,
    ) -> int:
        """Attribute each connection group; through DNS only within observed validity windows.

        A TLS identity or the Ollama service port explains the whole group. DNS
        explains a time bucket only when one same-service host's merged answer
        interval covers the bucket's whole interval; a bucket that a coarsening
        merged across an interval's start or end stays unattributed, with a
        limitation. Intervals are found by bisection, so the cost per bucket
        does not grow with repeated lookups.
        """
        for context, client, server, port, uid in pairs:
            self.ctx.check_deadline()
            identity = sni_by_uid.get((context, client, uid)) if uid is not None else None
            if identity is not None:
                identity.observe(server, port, identity.signature)
        ambiguous = 0
        for (context, client, server, port, uid), pair in pairs.items():
            self.ctx.check_deadline()
            identity = sni_by_uid.get((context, client, uid)) if uid is not None else None
            if identity is not None:
                if identity.ambiguous or not identity.matches(server, port):
                    ambiguous += pair.flows
                    continue
                if identity.signature:
                    c = self._contact(contacts, client, identity.signature, context)
                    self._count(c, pair.flows, pair.bytes_out, pair.bytes_in, pair.first, pair.last)
                continue
            if uid is not None and tls_limit_reached:
                continue
            local = dns.addresses.get((context, client, server))
            if local is None:
                # The service port does not depend on DNS storage; a client
                # whose answers were not all retained is disclosed.
                if port == _OLLAMA_PORT and self.index.get("provider.ollama") is not None:
                    c = self._contact(contacts, client, "provider.ollama", context)
                    c.hosts[f"{server}:{port}"] += pair.flows
                    self._count(c, pair.flows, pair.bytes_out, pair.bytes_in, pair.first, pair.last)
                    c.times.extend(pair.times[: max(0, _MAX_TIMES - len(c.times))])
                    if client in dns.dropped_clients:
                        c.limitations.add(_DNS_UNRETAINED)
                continue
            if local.lossy:
                for signature in sorted(local.signatures):
                    self._contact(contacts, client, signature, context).limitations.add(_DNS_OVERFLOW)
                continue
            if pair.untimed_flows:
                for signature in sorted(local.signatures):
                    self._contact(contacts, client, signature, context).limitations.add(
                        "Flow records without timestamps cannot be attributed through DNS"
                    )
            attributed: dict[float, _Contact] = {}
            for key, bucket in pair.buckets.items():
                signatures = {
                    signature
                    for (signature, _), spans in local.spans.items()
                    if _overlaps(spans, bucket.first, bucket.last)
                }
                if signatures:
                    # An answer with unknown validity may be conflicting; it
                    # cannot safely be assumed expired or outside this window.
                    signatures |= local.unknown
                if signatures - {""} and (len(signatures) > 1 or "" in signatures):
                    ambiguous += bucket.flows
                    continue
                if not signatures or "" in signatures:
                    continue
                signature = next(iter(signatures))
                c = self._contact(contacts, client, signature, context)
                valid = [
                    (host, span)
                    for (owner, host), spans in local.spans.items()
                    if owner == signature
                    and (span := _span_at(spans, bucket.first)) is not None
                    and bucket.last < span.end
                ]
                if not valid:
                    c.limitations.add(
                        "Flows grouped across a DNS validity boundary were not attributed through DNS"
                    )
                    continue
                attributed[key] = c
                for host in sorted({host for host, _ in valid}):
                    if len(c.hosts) < _MAX_HOSTS_PER_FINDING or host in c.hosts:
                        c.hosts[host] += bucket.flows
                if _PROVENANCE_SAMPLED not in c.limitations:
                    self._provenance(c, valid, server, bucket, context)
                self._count(c, bucket.flows, bucket.bytes_out, bucket.bytes_in, bucket.first, bucket.last)
                c.flows_by_dns += bucket.flows
            for when in pair.times if attributed else ():
                owner = attributed.get(pair.key(when))
                if owner is not None and len(owner.times) < _MAX_TIMES:
                    owner.times.append(when)
        return ambiguous

    @staticmethod
    def _provenance(
        c: _Contact, valid: list[tuple[str, _Span]], server: str, bucket: _Bucket, context: _Context
    ) -> None:
        """Sample the first distinct attributions; stop building them once one is dropped."""
        for host, span in sorted(valid, key=lambda item: (item[1].start, item[0])):
            provenance: dict[str, Any] = {
                "host": host,
                "address": server,
                "observed_at": _iso(span.start),
                "ttl_seconds": span.ttl,
                "flow_at": _iso(bucket.first),
                "sensor": context[0],
                "network_id": context[1],
                "resolver": context[2],
            }
            if span.end != span.own_end:
                # Later answers extended the first answer's validity.
                provenance["valid_until"] = _iso(span.end)
            if bucket.last != bucket.first:
                provenance["flow_last_at"] = _iso(bucket.last)
            if provenance in c.dns_attributions:
                continue
            if len(c.dns_attributions) >= _MAX_DNS_PROVENANCE:
                c.limitations.add(_PROVENANCE_SAMPLED)
                return
            c.dns_attributions.append(provenance)

    @staticmethod
    def _count(
        c: _Contact, flows: int, bytes_out: int, bytes_in: int, first: float | None, last: float | None
    ) -> None:
        c.flows += flows
        c.bytes_out += bytes_out
        c.bytes_in += bytes_in
        _seen(c, first)
        _seen(c, last)

    def _finding(self, c: _Contact, ambiguous: int) -> Finding:
        sig = self.index.get(c.signature)
        product = sig.name if sig else c.signature
        hosts = [h for h, _ in c.hosts.most_common(5)]
        f = Finding(
            surface=Surface.NETWORK,
            connector=self.name,
            kind=Kind.NETWORK_CONTACT,
            title=f"AI service contacted: {product} ({', '.join(hosts[:2]) or 'by address'}) from {c.client}",
            resource=f"network:{self.label}:{c.client}:{c.signature}",
            resource_type="network-contact",
            provider="network",
            account=self.label,
            first_seen=_iso(c.first),
            last_seen=_iso(c.last),
        )
        if sig is not None:
            if sig.category == "provider":
                f.add_model_provider(sig.id)
            else:
                f.add_framework(sig.id)
            for capability in sig.capabilities:
                f.add_capability(capability)
            for tag in sig.tags:
                f.add_tag(tag)
        if c.dns_queries:
            f.add_evidence(
                Evidence(
                    signal="network:dns",
                    description=f"{c.dns_queries} DNS quer(ies) for {', '.join(hosts)}",
                    weight=0.5,
                    signature=c.signature,
                )
            )
        if c.tls_connections:
            f.add_evidence(
                Evidence(
                    signal="network:tls-sni",
                    description=f"{c.tls_connections} TLS connection(s) naming {', '.join(hosts)}",
                    weight=0.7,
                    signature=c.signature,
                )
            )
        if c.flows:
            basis = []
            if c.flows_by_dns:
                basis.append(f"{c.flows_by_dns} by this client's DNS answers")
            rest = c.flows - c.flows_by_dns
            if rest:
                basis.append(f"{rest} by TLS server name or service port")
            f.add_evidence(
                Evidence(
                    signal="network:flow",
                    description=(
                        f"{c.flows} flow(s), {c.bytes_out:,} bytes sent, {c.bytes_in:,} received; attributed "
                        + "; ".join(basis)
                    ),
                    weight=0.6,
                    signature=c.signature,
                )
            )
        if sig is not None and sig.agent_indicator and sig.category != "identity-app":
            # A coding agent's, MCP server's or agent platform's own service.
            f.metadata["agent_indicators"] = 1
            f.add_tag("agent-service")
        cadence = loop_cadence([] if c.mixed_contexts else c.times)
        if c.mixed_contexts:
            c.limitations.add(
                "Cadence inference suppressed because the contact combines observation contexts"
            )
        if cadence.loops and sig is not None and sig.category == "provider":
            # Browsers rarely open connections to a model API; scripts and agents do.
            f.add_tag("agent-loop")
            f.add_evidence(
                Evidence(
                    signal="network:agent-loop",
                    description=(
                        f"{cadence.loops} run(s) of {LOOP_MIN_CALLS}+ connections at most "
                        f"{LOOP_MAX_GAP_SECONDS:.0f}s apart (longest {cadence.longest}): agent-loop cadence; "
                        "a batch script looks the same, and connection reuse hides requests"
                    ),
                    weight=0.4,
                )
            )
            f.metadata["agent_indicators"] = f.metadata.get("agent_indicators", 0) + 1
        f.metadata.update(
            {
                "client": c.client,
                "service": c.signature,
                "hosts": dict(c.hosts.most_common(_MAX_HOSTS_PER_FINDING)),
                "dns_queries": c.dns_queries,
                "tls_connections": c.tls_connections,
                "flows": c.flows,
                "bytes_out": c.bytes_out,
                "bytes_in": c.bytes_in,
                "network": self.label,
            }
        )
        if c.dns_attributions:
            f.metadata["dns_attribution"] = sorted(c.dns_attributions, key=lambda item: str(item))
        if c.ja4:
            f.metadata["tls_fingerprints"] = [
                {
                    "type": "ja4",
                    "value": value,
                    "source_field": source_field,
                    "sensor": context[0],
                    "network_id": context[1],
                    "resolver": context[2],
                    "uid": uid,
                }
                for value, source_field, context, uid in sorted(c.ja4, key=lambda item: str(item))
            ]
            c.limitations.add("JA4 describes a TLS client stack, not AI use, agency or a unique application")
        if c.limitations:
            f.metadata["limitations"] = sorted(c.limitations)
        if cadence.loops:
            f.metadata["loop_cadence"] = {"loops": cadence.loops, "longest": cadence.longest}
        if ambiguous:
            f.metadata["ambiguous_flows_in_input"] = ambiguous
        return finalize(f, self.index)


# ------------------------------------------------------------------- helpers


def _detect(row: dict[str, Any]) -> str | None:
    if "query_name" in row and "srcaddr" in row:
        return "route53"
    if "log-status" in row or "log_status" in row or {"srcaddr", "dstaddr", "dstport"} <= row.keys():
        return "vpc-flow"
    if "id.orig_h" in row or "_path" in row:
        return "zeek"
    keys = set(row)
    if keys & set(_QUERY_FIELDS + _SNI_FIELDS) or (keys & set(_CLIENT_FIELDS) and keys & set(_SERVER_FIELDS)):
        return "generic"
    return None


def _first(row: dict[str, Any], names: tuple[str, ...]) -> Any:
    for name in names:
        value = row.get(name)
        if value not in (None, "", "-"):
            return value
    return None


def _text(value: Any) -> str | None:
    if value is None or isinstance(value, (dict, list, bool)):
        return None
    text = str(value).strip()
    return text[:255] or None


def _host(value: Any) -> str | None:
    text = _text(value)
    if text is None:
        return None
    host = text.lower().rstrip(".")
    return host if _HOST.match(host) and not _ip(host) else None


@functools.lru_cache(maxsize=65_536)
def _cached_ip(text: str) -> str | None:
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _parsed_ip(text: str) -> str | None:
    """The canonical form of an IP address, or None; logs repeat few distinct addresses.

    Only short strings are cached, so hostile input cannot pin large values in memory.
    """
    if len(text) > 64:
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            return None
    return _cached_ip(text)


def _ip(value: Any) -> bool:
    return _parsed_ip(str(value)) is not None


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return number if 0 <= number <= 10**15 else None


def _address(value: Any) -> str:
    text = str(value)
    return _parsed_ip(text) or text


def _ttl(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return None
    try:
        ttl = float(value)
    except (ValueError, OverflowError):
        return None
    return ttl if math.isfinite(ttl) and 0 <= ttl <= 2**31 - 1 else None


def _seconds(value: Any) -> float | None:
    moment = parse_timestamp(value)
    return moment.timestamp() if moment else None


def _iso(value: float | None) -> str | None:
    if value is None:
        return None
    moment = parse_timestamp(value)
    return moment.isoformat() if moment else None


def _seen(c: _Contact, ts: float | None) -> None:
    if ts is None:
        return
    c.first = ts if c.first is None else min(c.first, ts)
    c.last = ts if c.last is None else max(c.last, ts)


def _zeek_escape(text: str) -> str:
    """Decode a Zeek ``#separator`` value such as ``\\x09``."""
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), text.strip())
