# Network connector

The network connector finds AI services contacted from your network in DNS,
TLS and flow telemetry that you already collect. It covers traffic that never
passes an AI gateway or an HTTP proxy: a laptop resolving `api.anthropic.com`,
a workload opening TLS connections to Bedrock, a desktop client reaching a
remote MCP server.

!!! info "Log-based"
    The network connector reads exported logs. It makes no network request
    and captures no packets.

## `network.logs`

Each input record is read as a DNS query, a TLS connection or a flow:

| Source | Records | Notes |
|---|---|---|
| Zeek `dns.log`, `ssl.log`, `conn.log` | DNS queries and answers, TLS server names, connections | TSV with `#fields` headers or JSON (one object per line, `_path` optional) |
| Amazon Route 53 Resolver query logs | DNS queries and answers | JSON or JSONL as delivered to CloudWatch Logs, S3 or Firehose |
| AWS VPC Flow Logs | flows | default version 2 format, or any format with a header line; JSON accepts `log-status` or `log_status`; `REJECT` and `NODATA` rows are skipped |
| Generic JSON or CSV | DNS queries (`query`, `qname`, `domain`…), TLS server names (`sni`, `server_name`), flows (`dst_ip` with `dst_port`) | client address from `client`, `client_ip`, `src_ip`, `srcaddr`… |

The result is one `network-contact` finding per client address and AI
service, with the host names seen, DNS query and TLS connection counts, flow
counts and bytes.

**Host matching is strict.** A host name matches a signature's exact domain
or declared wildcard, never a substring: `www.anthropologie.com`,
`api.gemini.com` (a crypto exchange) and `claude-monet.org` match nothing.
Domain hints weighted below 0.3 are ignored. Only host names that match an AI
signature are kept; other DNS queries are counted as examined records and
never stored.

**Flows are attributed only through the same input.** A flow has addresses,
not names, so it counts towards a service only when:

- its Zeek `uid` and client address link it to a TLS record whose server
  name is an AI host, with matching server address and port when supplied;
- the same client resolved an AI host to that address **before** the flow,
  and the flow timestamp is inside the answer's bounded TTL window.

DNS windows start at the observation timestamp and exclude their expiry
boundary. Missing timestamps or TTLs retain DNS query findings with explicit
limitations, but cannot attribute flows. This includes ordinary Route 53
query exports that omit TTLs. The connector never borrows another client's
DNS answers. Repeated answers for the same host and address merge into one
validity interval when their windows overlap or touch, so a busy client's
repeated lookups cost no storage; expired answers do not identify later
traffic, and future answers never identify earlier traffic.

Optional `sensor`/`sensor_id`, `network_id`/`vpc_id`, and
`resolver`/`resolver_id` fields scope both DNS and TLS UID joins. Supplied
context must match exactly; missing context does not wildcard-match a known
sensor. With no context fields, the configured input/label is the shared
vantage. Split overlapping address spaces into separate labeled connector
inputs when exporters cannot supply context. Findings still aggregate by
configured label, client and service.

Zeek `TTLs`, generic `ttls`, `ttl`/`TTL`, and explicitly supplied Route 53
TTL metadata are accepted. Vector TTLs must align with the answers. A
response containing a CNAME and IP answers uses the shortest answer TTL;
CNAME-only records do not produce an IP association, and chains are never
resolved over the network. IPv4 and IPv6 addresses are normalized. Sampled
`dns_attribution` metadata preserves host, address, the first answer's
observation time and original TTL, flow timestamps and context; when later
answers extended that answer's validity, `valid_until` gives the end of the
merged interval. Provenance samples are limited to 20 entries with an
explicit limitation when more are available.

Flow counts and bytes remain separated by connection UID until attribution,
so one AI connection cannot claim another connection's traffic on the same
address and port. UIDs are scoped to the client address and observation
context. Each flow group keeps its flow times in at most 64 buckets: exact
timestamps at first, then aligned intervals whose width doubles as more
distinct times arrive (with a 500,000-bucket budget across groups beyond each
group's first). DNS attributes a bucket only when one answer is valid for the
whole interval, so an aggregate cannot count stale bytes through one fresh
DNS observation. A bucket that coarsening merged across an answer's start or
expiry stays unattributed, with the limitation "Flows grouped across a DNS
validity boundary were not attributed through DNS". A known non-AI TLS
name blocks DNS and service-port attribution for that connection; conflicting
TLS service identities or endpoints leave its flows unattributed. A missing
UID does not inherit a different connection's TLS name. Without linked TLS
evidence, the DNS rules above still apply.

DNS evidence for a shared address does not attribute flows when it names
multiple services or both AI and non-AI hosts within an applicable window.
A potentially conflicting answer with unknown validity also blocks attribution. Ambiguous flows are reported
as a warning that does not make the scan incomplete. A flow to port 11434,
the default Ollama port, is attributed to Ollama only without TLS or DNS
evidence that contradicts it.

**Agent indicators.** Traffic to a coding agent's own service, an MCP server
or a hosted agent runtime (for example `api2.cursor.sh`, `mcp.linear.app` or
`bedrock-agent-runtime`) is tagged `agent-service`. Runs of three or more
connections to a model API at most 30 seconds apart are tagged `agent-loop`.
Cadence inference is suppressed when a contact combines different observation
contexts, so overlapping addresses from separate sensors cannot synthesize an
agent loop. That cadence is a heuristic: a batch script has the same shape, and a client
that reuses one connection for many requests shows none. Consumer AI sites
such as `chatgpt.com` are AI use, not agent indicators.

**JA4 context.** Existing Zeek JSON/TSV `ja4` and generic `tls.ja4` fields
are validated against the hashed [JA4 client format](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md)
and retained as bounded `tls_fingerprints` metadata on the directly observed
AI TLS contact. Metadata includes the source field, UID and sensor context;
it does not assert an exporter version that the input did not supply.
JA4 contributes no confidence, risk or agency score. If fingerprint storage
fills, the contact's fingerprint metadata is omitted because discarded
observations could conflict. The same fingerprint
on a non-AI host creates no finding. Conflicting UID/endpoint identities do
not transfer fingerprints; contradictory fingerprints for the same UID are
omitted and mark the export incomplete. Missing fingerprints leave the
existing detection path unchanged. There is no capture, external fingerprint
lookup, stack-to-agent classifier, or required JA4 detection gate.

Options:

- `input` (required): a log file or a directory of logs. DNS logs and flow
  logs that should be attributed to each other must be in the same input.
- `format`: `zeek`, `route53`, `vpc-flow` or `generic` forces the record
  format; the default `auto` detects it per record.
- `label`: the network or sensor name used in resource ids and as the finding
  account (default `network`).
- `max_records`: the number of records read (default 10,000,000). Reaching
  it makes the scan incomplete.
- `dns_max_ttl_seconds`: maximum DNS attribution age, even when the input
  reports a longer TTL (default 86,400; maximum 604,800).
- `dns_clock_skew_seconds`: optional expiry extension (integer 0–60,
  default 0). It never allows a flow before the DNS observation and never
  turns a zero-TTL answer into a cache interval.

Malformed lines, records the connector cannot read as DNS, TLS or flow
records, and DNS or TLS records without a client address make the scan
incomplete. Analysis keeps at most 50,000 client addresses, 500,000 flow
groups (context, client, server address, port and UID), 500,000
TLS identities (context, client and UID), and 32 JA4 observations per
contact. Records beyond these bounds are reported and make the scan
incomplete. If TLS identity storage fills, flows with an unretained UID are
left unattributed because a discarded TLS record could contradict DNS.

DNS answers are stored per context, client and address as merged validity
intervals per AI host, plus the merged intervals of non-AI answers, within a
budget of 500,000 addresses and intervals for the input. An address keeps at
most 1,024 AI intervals; non-AI intervals beyond 16 are merged across their
smallest gap, which can only widen the negative evidence that blocks
attribution. When an answer cannot be kept, only that client/address loses
DNS attribution: its flows stay unattributed, the affected findings carry the
limitation "DNS answers for an address exceeded storage bounds; its flows
were not attributed through DNS", and a warning reports the count without
making the scan incomplete (every DNS query still counts on its finding).
Attribution looks intervals up by bisection, so its cost does not grow with
repeated lookups. The Ollama service-port rule does not depend on DNS
storage; when some of the client's DNS answers were not retained, the finding
says so. Malformed TTLs, timestamps, context and explicit
JA4 values also make the scan incomplete. A discarded record might contradict
the retained DNS or SNI, so flow attribution is suppressed as far as that
record could reach; direct query/TLS observations remain visible with the
limitation:

- Reaching `max_records`, an unreadable line or file, a record that is not an
  object, and a DNS, TLS or unrecognized record without a client address
  suppress flow attribution for the whole input ("Flow attribution disabled
  because input was incomplete").
- An unrecognized or incomplete record, a malformed context, a DNS answer list
  over 32 or an invalid JA4 value whose record names a client suppresses flow
  attribution and JA4 metadata for that client only ("Flow attribution disabled
  because input for this client was incomplete").
- A malformed timestamp or TTL keeps the record with that field unknown, and a
  defective VPC flow record carries no DNS or TLS evidence, so neither
  suppresses attribution.

Each case still makes the scan incomplete. Observation timestamps are
exporter-provided, not independently verified.

VPC Flow Logs `SKIPDATA` records mean AWS did not capture some flows. They
produce an incomplete report (`summary.complete: false`) and CLI exit 3,
including exports containing only `SKIPDATA`. Unknown, malformed or conflicting
explicit log statuses also make the scan incomplete. `NODATA` means no traffic
was observed for that interface and interval; it remains a clean empty result.
Custom exports that omit the status field retain the normal flow handling.
See [AWS log-status definitions](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html).

Client addresses identify a device or a NAT gateway, not a person. Join
findings to DHCP, VPN or asset records before assigning an owner.

See the [main connector reference](../connectors.md) for shared options and offline safety limits.
