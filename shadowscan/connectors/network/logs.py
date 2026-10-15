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

Host names are matched exactly or by a signature's declared wildcard, never by
substring, so ``www.anthropologie.com`` is not Anthropic. Only names that
match an AI signature are kept; other queries are counted, never stored.

The connector is offline: it reads files and makes no network request.
Malformed lines and unrecognised records make the scan incomplete.
"""

from __future__ import annotations

import bisect
import ipaddress
import json
import math
import re
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from functools import lru_cache
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
_MAX_TIMESTAMPS_PER_CONNECTION = 100_000
_MAX_HOSTS_PER_FINDING = 20
_MAX_TIMES = 1_000
_MAX_TOTAL_TIMES = 200_000
_MAX_DNS_OBSERVATIONS = 500_000
_MAX_DNS_PER_ADDRESS = 4_096
# Distinct (signature, host) keys per context/client/address: every timestamp
# group bisects each key's windows, so this bounds attribution work per group.
_MAX_DNS_HOSTS_PER_ADDRESS = 64
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


@dataclass(slots=True)
class _DNSObservation:
    """A client's answers naming one host for one address, merged into one validity window.

    An answer that arrives before the previous window ends extends it, whatever
    TTL a caching resolver reported, so a day of 60-second TTLs is one window
    rather than thousands of entries. ``expires_at`` is None without a window:
    a zero TTL, or no timestamp or TTL (unknown validity). ``ttl`` is the
    longest TTL merged into the window.
    """

    signature: str
    host: str
    observed_at: float | None
    ttl: float | None
    refreshed_at: float | None = None
    expires_at: float | None = None

    @property
    def unknown(self) -> bool:
        return self.observed_at is None or self.ttl is None

    def valid(self, when: float | None) -> bool:
        # Never explain an older flow using a newer DNS answer.
        return (
            when is not None
            and self.observed_at is not None
            and self.expires_at is not None
            and self.observed_at <= when < self.expires_at
        )

    def extend(self, other: _DNSObservation) -> None:
        """Absorb an overlapping or touching window of the same host."""
        if self.observed_at is not None and other.observed_at is not None:
            self.observed_at = min(self.observed_at, other.observed_at)
        if self.refreshed_at is not None and other.refreshed_at is not None:
            self.refreshed_at = max(self.refreshed_at, other.refreshed_at)
        if self.expires_at is not None and other.expires_at is not None:
            self.expires_at = max(self.expires_at, other.expires_at)
        if self.ttl is not None and other.ttl is not None:
            self.ttl = max(self.ttl, other.ttl)


@dataclass(slots=True)
class _DNSAnswers:
    """What one client resolved to one address: disjoint windows per host, sorted by start."""

    windows: dict[tuple[str, str], list[_DNSObservation]] = field(default_factory=dict)
    others: list[_DNSObservation] = field(default_factory=list)  # answers without a window
    hosts: set[tuple[str, str]] = field(default_factory=set)  # (signature, host) keys held
    size: int = 0

    def holds(self, observation: _DNSObservation) -> bool:
        """Whether an entry for the answer's host key fits the per-address host bound."""
        key = (observation.signature, observation.host)
        return key in self.hosts or len(self.hosts) < _MAX_DNS_HOSTS_PER_ADDRESS

    def entries(self) -> Iterator[_DNSObservation]:
        yield from self.others
        for windows in self.windows.values():
            yield from windows

    def absorb(self, observation: _DNSObservation) -> bool:
        """Merge the answer into what is kept; False when it needs an entry of its own."""
        start, end = observation.observed_at, observation.expires_at
        if start is None or end is None:
            return any(
                item.signature == observation.signature
                and item.host == observation.host
                and item.unknown == observation.unknown
                for item in self.others
            )
        windows = self.windows.get((observation.signature, observation.host), [])
        index = bisect.bisect_right(windows, start, key=_start)
        merged: _DNSObservation | None = None
        following = index
        left = windows[index - 1] if index else None
        if left is not None and left.expires_at is not None and left.expires_at >= start:
            left.extend(observation)
            merged = left
        elif index < len(windows):
            right = windows[index]
            if right.observed_at is not None and right.observed_at <= end:
                right.extend(observation)
                merged = right
                following = index + 1
        if merged is None:
            return False
        # The answer may bridge any number of later windows: absorb every one
        # the merged window now reaches, so windows stay disjoint and valid_at's
        # single bisection cannot land on a shorter window that hides this one.
        while following < len(windows):
            nxt = windows[following]
            if nxt.observed_at is None or merged.expires_at is None or nxt.observed_at > merged.expires_at:
                break
            merged.extend(windows.pop(following))
        return True

    def append(self, observation: _DNSObservation) -> None:
        start = observation.observed_at
        if start is None or observation.expires_at is None:
            self.others.append(observation)
        else:
            windows = self.windows.setdefault((observation.signature, observation.host), [])
            windows.insert(bisect.bisect_right(windows, start, key=_start), observation)
        self.hosts.add((observation.signature, observation.host))
        self.size += 1

    def valid_at(self, when: float | None) -> list[_DNSObservation]:
        """The windows covering ``when``: at most one per host, found by bisection."""
        valid = []
        if when is not None:
            for windows in self.windows.values():
                index = bisect.bisect_right(windows, when, key=_start)
                if index and windows[index - 1].valid(when):
                    valid.append(windows[index - 1])
        return valid


@dataclass(slots=True)
class _Pair:
    """Flows of one connection (client, server, port and UID when available) at one timestamp."""

    flows: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    first: float | None = None
    last: float | None = None
    times: list[float] = field(default_factory=list)


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
        context = self._context(row, name)
        if context is None:
            return
        fmt = self.format if self.format not in (None, "auto") else _detect(row)
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
            self.ctx.warn(f"network.logs: {name}: unrecognized record")
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
            self.ctx.warn(f"network.logs: {name}: invalid event timestamp")
        if sni is not None or path == "ssl":
            if not client:
                self.ctx.warn(f"network.logs: {name}: TLS record without a client address")
                return
            if sni is None:
                return  # a TLS connection without SNI names nothing
            yield {
                "kind": "tls", "ts": ts, "client": client, "server": server, "port": port,
                "sni": sni, "uid": _text(_first(row, ("uid",))), "context": context,
                "ja4": self._ja4(row, name),
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
        self.ctx.warn(f"network.logs: {name}: record has no query, server name or flow endpoints")

    def _context(self, row: dict[str, Any], name: str) -> _Context | None:
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
                self.ctx.warn(f"network.logs: {name}: malformed observation context")
                return None
            values.append(supplied[0].strip() if supplied else "")
        return values[0], values[1], values[2]

    def _ja4(self, row: dict[str, Any], name: str) -> tuple[str, str] | None:
        aliases = [key for key in ("ja4", "tls.ja4") if row.get(key) not in (None, "", "-")]
        if not aliases:
            return None
        values = [row[key] for key in aliases]
        if any(not isinstance(value, str) or not _JA4.fullmatch(value) for value in values) or any(
            value != values[0] for value in values
        ):
            self.ctx.warn(f"network.logs: {name}: invalid or conflicting JA4 fingerprint")
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
        # A defect in a record whose client is known stays with that client:
        # the record is reported without marking the input incomplete, and
        # analyze() disables DNS attribution for the client and marks the
        # scan incomplete. Without a client, the doubt covers the input.
        if not client or query is None:
            message = f"network.logs: {name}: DNS record without a client address or query name"
            self.ctx.warn(message, incomplete=not client)
            if client:
                yield {"kind": "dns", "ts": None, "client": client, "query": "", "answers": [], "ttl": None,
                       "context": context, "malformed": True}  # fmt: skip
            return
        malformed = False
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
            self.ctx.warn(
                f"network.logs: {name}: malformed DNS TTL values or conflicting aliases", incomplete=False
            )
            malformed = True
        elif variants and variants[0]:
            # Every alias must describe the same answer TTLs. For CNAME
            # responses all links must remain valid, so use their minimum.
            ttl = min(variants[0])
        ts = _seconds(when)
        if when is not None and ts is None:
            self.ctx.warn(f"network.logs: {name}: invalid DNS timestamp", incomplete=False)
            malformed = True
        if len(answers) > 32:
            self.ctx.warn(f"network.logs: {name}: DNS answer limit exceeded", incomplete=False)
            # A dropped answer may contradict retained data; no interval.
            ttl = None
            malformed = True
        yield {
            "kind": "dns",
            "ts": ts,
            "client": client,
            "query": query,
            "answers": [str(ipaddress.ip_address(a)) for a in answers if _ip(a)][:32],
            "ttl": ttl,
            "context": context,
            "malformed": malformed,
        }

    def _vpc_flow(self, row: dict[str, Any], name: str, number: int | None) -> Iterator[dict[str, Any]]:
        where = f"{name} line {number}" if number else name
        # Custom exports can omit log-status, but an explicit status must be
        # valid. SKIPDATA means AWS failed to capture flows, not an idle ENI.
        raw_statuses = [row[key] for key in ("log-status", "log_status") if key in row]
        if any(not isinstance(status, str) or not status.strip() for status in raw_statuses):
            self.ctx.warn(f"network.logs: {where}: invalid VPC flow log-status")
            return
        statuses = {status.strip().upper() for status in raw_statuses}
        if len(statuses) > 1 or statuses - {"OK", "NODATA", "SKIPDATA"}:
            self.ctx.warn(f"network.logs: {where}: invalid VPC flow log-status")
            return
        status = next(iter(statuses), "OK")
        if status == "SKIPDATA":
            self.ctx.warn(f"network.logs: {where}: VPC Flow Logs SKIPDATA reports uncaptured flows")
            return
        if status == "NODATA":
            return
        if str(row.get("action") or "ACCEPT").upper() != "ACCEPT":
            return
        context = self._context(row, name)
        if context is None:
            return
        client, server = _text(row.get("srcaddr")), _text(row.get("dstaddr"))
        if not (_ip(client) and _ip(server)):
            self.ctx.warn(f"network.logs: {where}: malformed VPC flow record")
            return
        ts = _seconds(row.get("start"))
        if row.get("start") is not None and ts is None:
            self.ctx.warn(f"network.logs: {where}: invalid event timestamp")
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
        resolved: dict[_DNSKey, _DNSAnswers] = {}
        sni_by_uid: dict[_TLSKey, _TLSIdentity] = {}
        pairs: dict[_PairKey, dict[float | None, _Pair]] = {}
        dns_overflow: set[_DNSKey] = set()
        dns_defects: set[tuple[_Context, str]] = set()
        unscoped_defects = False
        times_used = dns_used = dropped_address_dns = 0
        dropped_pairs = dropped_times = dropped_clients = dropped_tls = dropped_dns = dropped_ja4 = 0
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
            if kind == "dns" and rec.get("malformed"):
                # The record stays in evidence; the client's DNS attribution does not.
                if len(dns_defects) < _MAX_CLIENTS:
                    dns_defects.add((context, client))
                else:
                    unscoped_defects = True
                if not rec.get("query"):
                    continue
            if kind in {"dns", "tls"}:
                host = str(rec.get("query") if kind == "dns" else rec.get("sni"))
                match = self._service(host)
                signature = match.signature.id if match else ""
                if kind == "dns":
                    ttl = rec.get("ttl")
                    # Skew only relaxes expiration; zero-TTL records must not create a cache interval.
                    expires = (
                        ts + min(ttl, self.dns_max_ttl) + self.dns_clock_skew
                        if ts is not None and ttl
                        else None
                    )
                    for address in rec.get("answers") or []:
                        key_dns = (context, client, address)
                        answers = resolved.get(key_dns)
                        observation = _DNSObservation(signature, host if match else "", ts, ttl, ts, expires)
                        if answers is not None and answers.absorb(observation):
                            continue
                        if dns_used >= _MAX_DNS_OBSERVATIONS:
                            dropped_dns += 1
                            continue
                        if answers is not None and (
                            answers.size >= _MAX_DNS_PER_ADDRESS or not answers.holds(observation)
                        ):
                            # A discarded answer could contradict this address's
                            # retained ones; the doubt stays with the address.
                            dropped_address_dns += 1
                            dns_overflow.add(key_dns)
                            continue
                        if answers is None:
                            answers = resolved[key_dns] = _DNSAnswers()
                        answers.append(observation)
                        dns_used += 1
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
                groups = pairs.get(key)
                if groups is None:
                    if len(pairs) >= _MAX_PAIRS:
                        dropped_pairs += 1
                        continue
                    groups = pairs[key] = {}
                # Keep timestamps distinct within a connection: an aggregate
                # spanning expiry must not transfer its stale bytes through one
                # fresh observation. The bound counts a connection's timestamps,
                # not the input's flow records.
                pair = groups.get(ts)
                if pair is None:
                    if len(groups) >= _MAX_TIMESTAMPS_PER_CONNECTION:
                        dropped_times += 1
                        continue
                    pair = groups[ts] = _Pair()
                pair.flows += 1
                pair.bytes_out += int(rec.get("bytes_out") or 0)
                pair.bytes_in += int(rec.get("bytes_in") or 0)
                if ts is not None:
                    pair.first = ts if pair.first is None else min(pair.first, ts)
                    pair.last = ts if pair.last is None else max(pair.last, ts)
                    if len(pair.times) < _MAX_TIMES and times_used < _MAX_TOTAL_TIMES:
                        pair.times.append(ts)
                        times_used += 1
        input_incomplete = (
            self._limit_reported or unscoped_defects or bool(self.ctx.stats and self.ctx.stats.incomplete)
        )
        if dns_defects:
            self.ctx.warn(
                f"network.logs: malformed or incomplete DNS records from {len(dns_defects):,} client(s); "
                "their DNS and service-port flow attribution disabled because a discarded value may conflict"
            )
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
        if dropped_times:
            self.ctx.warn(
                f"network.logs: {dropped_times:,} flow record(s) beyond {_MAX_TIMESTAMPS_PER_CONNECTION:,} "
                "timestamps on one connection were not attributed"
            )
        if dropped_tls:
            self.ctx.warn(
                f"network.logs: {dropped_tls:,} TLS record(s) beyond {_MAX_PAIRS:,} client/UID identities "
                "were not retained for flow attribution"
            )
        if dropped_dns:
            self.ctx.warn(
                f"network.logs: {dropped_dns:,} DNS observation(s) exceeded storage bounds; "
                "DNS and service-port flow attribution disabled because discarded answers may conflict"
            )
        if dropped_address_dns:
            self.ctx.warn(
                f"network.logs: {dropped_address_dns:,} DNS observation(s) exceeded the per-address bound "
                f"({_MAX_DNS_PER_ADDRESS:,} windows or {_MAX_DNS_HOSTS_PER_ADDRESS} hosts); DNS and "
                f"service-port flow attribution disabled for {len(dns_overflow):,} address(es) because "
                "discarded answers may conflict"
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
            ambiguous = self._attribute_flows(
                contacts,
                pairs,
                sni_by_uid,
                bool(dropped_tls),
                resolved,
                bool(dropped_dns),
                dns_overflow,
                dns_defects,
            )
            defective = {client for _, client in dns_defects}
            for contact in contacts.values():
                # Attribution was gated per (context, client): say so only
                # where it applied. A contact spanning contexts records its
                # first only, so any defect of its client counts there.
                if (contact.context, contact.client) in dns_defects or (
                    contact.mixed_contexts and contact.client in defective
                ):
                    contact.limitations.add(
                        "DNS and service-port attribution disabled because this client's DNS records were "
                        "malformed or incomplete"
                    )
        if ambiguous:
            self.ctx.warn(
                f"network.logs: {ambiguous:,} flow(s) with ambiguous service attribution were not attributed",
                incomplete=False,
            )
        for c in contacts.values():
            self.ctx.check_deadline()
            if input_incomplete:
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
        pairs: dict[_PairKey, dict[float | None, _Pair]],
        sni_by_uid: dict[_TLSKey, _TLSIdentity],
        tls_limit_reached: bool,
        resolved: dict[_DNSKey, _DNSAnswers],
        dns_limit_reached: bool,
        dns_overflow: set[_DNSKey],
        dns_defects: set[tuple[_Context, str]],
    ) -> int:
        """Attribute each connection's timestamp groups only within observed validity windows."""
        for context, client, server, port, uid in pairs:
            self.ctx.check_deadline()
            identity = sni_by_uid.get((context, client, uid)) if uid is not None else None
            if identity is not None:
                identity.observe(server, port, identity.signature)
        ambiguous = 0
        for (context, client, server, port, uid), groups in pairs.items():
            self.ctx.check_deadline()
            tls_signature: str | None = None
            identity = sni_by_uid.get((context, client, uid)) if uid is not None else None
            if identity is not None:
                if identity.ambiguous or not identity.matches(server, port):
                    ambiguous += sum(pair.flows for pair in groups.values())
                    continue
                if not identity.signature:
                    continue
                tls_signature = identity.signature
            elif (
                (uid is not None and tls_limit_reached)
                or dns_limit_reached
                or (context, client) in dns_defects
            ):
                continue
            local = resolved.get((context, client, server))
            local_signatures = (
                {item.signature for item in local.entries() if item.signature} if local else set()
            )
            if tls_signature is None and (context, client, server) in dns_overflow:
                for name in local_signatures:
                    self._contact(contacts, client, name, context).limitations.add(
                        "DNS and service-port attribution disabled for an address whose answers "
                        "exceeded storage bounds"
                    )
                continue
            for number, (ts, pair) in enumerate(groups.items()):
                if number and not number % 1024:
                    # A connection may hold 100,000 groups, each bisecting every
                    # host key of the address: honour the deadline within it.
                    self.ctx.check_deadline()
                signature: str | None = None
                basis = ""
                valid: list[_DNSObservation] = []
                if tls_signature is not None:
                    signature, basis = tls_signature, "tls"
                else:
                    if ts is None:
                        for name in local_signatures:
                            self._contact(contacts, client, name, context).limitations.add(
                                "Flow records without timestamps cannot be attributed through DNS"
                            )
                    valid = local.valid_at(ts) if local else []
                    signatures = {item.signature for item in valid}
                    if valid and local:
                        # An answer with unknown validity may be conflicting; it
                        # cannot safely be assumed expired or outside this window.
                        signatures.update(item.signature for item in local.others if item.unknown)
                    if len(signatures) == 1 and "" not in signatures:
                        signature, basis = next(iter(signatures)), "dns"
                    elif signatures - {""}:
                        ambiguous += pair.flows
                    elif (
                        local is None
                        and port == _OLLAMA_PORT
                        and self.index.get("provider.ollama") is not None
                    ):
                        signature, basis = "provider.ollama", "port"
                if signature is None:
                    continue
                c = self._contact(contacts, client, signature, context)
                if basis == "port":
                    c.hosts[f"{server}:{port}"] += pair.flows
                elif basis == "dns":
                    for host in sorted({item.host for item in valid}):
                        if len(c.hosts) < _MAX_HOSTS_PER_FINDING or host in c.hosts:
                            c.hosts[host] += pair.flows
                    for item in sorted(valid, key=lambda item: (item.observed_at or 0, item.host)):
                        if len(c.dns_attributions) >= _MAX_DNS_PROVENANCE:
                            c.limitations.add("DNS attribution provenance is sampled to 20 entries")
                            break
                        provenance = {
                            "host": item.host,
                            "address": server,
                            "observed_at": _iso(item.observed_at),
                            "refreshed_at": _iso(item.refreshed_at),
                            "expires_at": _iso(item.expires_at),
                            "ttl_seconds": item.ttl,
                            "flow_at": _iso(ts),
                            "sensor": context[0],
                            "network_id": context[1],
                            "resolver": context[2],
                        }
                        if provenance not in c.dns_attributions:
                            c.dns_attributions.append(provenance)
                c.flows += pair.flows
                c.flows_by_dns += pair.flows if basis == "dns" else 0
                c.bytes_out += pair.bytes_out
                c.bytes_in += pair.bytes_in
                if basis != "tls":
                    room = _MAX_TIMES - len(c.times)
                    c.times.extend(pair.times[: max(0, room)])
                _seen(c, pair.first)
                _seen(c, pair.last)
        return ambiguous

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


@lru_cache(maxsize=100_000)
def _canonical(text: str) -> str | None:
    """The canonical form of an IP address literal, or None for other text.

    Cached: a log repeats a few thousand addresses hundreds of thousands of
    times, and parsing dominated analysis otherwise. Inputs are bounded text.
    """
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _ip(value: Any) -> bool:
    return _canonical(str(value)) is not None


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
    return _canonical(text) or text


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


def _start(item: _DNSObservation) -> float:
    """Bisection key of a window: only windowed answers are kept in sorted lists."""
    return item.observed_at if item.observed_at is not None else 0.0


def _seen(c: _Contact, ts: float | None) -> None:
    if ts is None:
        return
    c.first = ts if c.first is None else min(c.first, ts)
    c.last = ts if c.last is None else max(c.last, ts)


def _zeek_escape(text: str) -> str:
    """Decode a Zeek ``#separator`` value such as ``\\x09``."""
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), text.strip())
