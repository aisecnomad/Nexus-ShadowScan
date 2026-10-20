# DNS observation snapshots

Status: proposed, October 20, 2026; **not implemented**. This is the design and
acceptance plan for [#210](https://github.com/aisecnomad/Nexus-ShadowScan/issues/210).
It does not add a command, connector, configuration key, dependency or DNS
egress. `network.logs` remains offline. Its existing passive temporal DNS
attribution is a separate, implemented capability.

## Problem and trust boundary

A flow to an address alone does not identify an AI service. An operator may
want to collect the addresses currently returned for a small set of service
endpoints, retain that observation with provenance, and replay it beside
flows from the same vantage and time. The snapshot cannot establish that a
client resolved, contacted or executed an agent at an endpoint.

The operator chooses exact endpoint names, resolver and observation vantage.
DNS replies, snapshot files and telemetry remain untrusted. Resolver answers
are claims from one vantage, not authenticated service ownership. A digest
binds bytes; it does not establish authenticity, exclusivity or freshness.
Provider IP ranges and CDN ownership are insufficient substitutes.

## Proposed interface

Use a separate collector, provisionally `network.dns-snapshot`, with an
explicit live opt-in. Offline input for that collector validates a snapshot
without any resolver call. A collection produces a versioned snapshot and
collection statistics, **no client-contact findings**. Reuse the engine's
deadline, cancellation, scope attestation and sanitized export facilities;
choose the final artifact interface before implementation.

Replay is a separate opt-in to `network.logs` using a local snapshot path and
its expected SHA-256. Replay never invokes the collector or refreshes data.
Paths resolve relative to the configuration file, with the existing bounded
no-symlink file reader. The names above describe proposed interfaces, not
accepted configuration today. In particular, `resolve_dns` is unsupported.

### Collection policy

- Require both a nonempty exact endpoint allowlist and the explicit live
  switch. Reject wildcard, URL, port, path, IP literal and control-character
  entries. Normalize ASCII DNS names once; query only those names.
- Query A and AAAA independently. Select one configured resolver and a stable
  resolver identifier; record sensor and network identifiers. Do not silently
  change resolvers, follow transport redirects or query names found in logs.
- Select a TTL-aware, cancellable resolver implementation in a separate
  dependency/transport review. Standard-library `getaddrinfo` and
  `gethostbyname_ex` do not provide answer TTLs and are not that interface.
  Do not add a bespoke DNS wire parser for this feature.
- Proposed hard ceilings: 64 unique endpoints, two questions per endpoint,
  four concurrent questions, five seconds per question, 30 seconds total,
  32 returned addresses per question, 64 KiB per response and 1 MiB per
  snapshot. Operator limits may reduce these ceilings. Count retries and
  aliases against the same question and deadline budgets.
- Do not perform application requests to returned addresses. An allowlisted
  private resolver or private service endpoint needs an explicit reviewed
  policy; private-address allowances must not arise from DNS replies.
- Cancel outstanding work at the deadline. Record an outcome for each
  requested name/type. A deadline, cancellation, refused/malformed/oversize
  reply or exhausted budget marks collection incomplete. Preserve completed
  observations. NXDOMAIN and NODATA are explicit negative observations, not
  missing records or positive service evidence.

### Snapshot contract

Use a strict versioned object with these fields; final field names require
schema review before implementation.

| Field | Required meaning |
|---|---|
| `schema` | Exact version, provisionally `shadowscan.dns-observation/v1`; refuse unsupported versions. |
| `collection` | Requested endpoint/type set, start/end times, resolver id, sensor id, network id, effective limits and complete/incomplete outcome with reason counts. |
| `observations` | At most one terminal outcome per requested endpoint/type; duplicates and missing outcomes are integrity failures. |
| Observation identity | Exact queried name/type, observed answer name, normalized address family/address, collection timestamp and supplied TTL. |
| Observation provenance | Resolver and vantage context inherited from the collection plus transport identity and source dataset identifier. |
| Negative outcome | NXDOMAIN/NODATA, timeout, cancelled, refused or failed, without a synthetic address or validity interval. |

Reject duplicate JSON keys, non-finite or out-of-range numbers, fractional or
boolean TTLs, invalid addresses, unexpected fields, contradictory collection
times and an outcome for an unrequested name. Bound strings, object depth,
record count and aggregate addresses before retaining them. CNAME handling
must preserve the chain and use its shortest positive TTL, or refuse alias
responses in the initial version; it must never invent a TTL. A zero TTL has
no replay validity interval. Do not deduplicate away contradictory answers.

### Replay and evidence

Replay considers a flow only when its supplied vantage exactly matches the
snapshot and its timestamp lies in the half-open interval from observation
time to observation time plus bounded TTL. Missing context does not match a
known context. Missing time, expired data, future observations and incomplete
snapshot coverage cannot establish eligible enrichment.

A match yields bounded **service-location context** with snapshot digest,
observation identity, address and validity interval. It must not synthesize a
client DNS query, increment observed contact counts, supply execution cadence,
infer agency or raise a finding to registered status. It must not overwrite
TLS SNI, use a resolver observation as an independent second signal, or assign
`Finding.confidence` directly. If a contextual `Evidence` record is emitted,
its weight and confidence group must keep it dependent on the same underlying
observation; the initial proposal assigns it zero scoring weight.

Multiple eligible endpoints at an address leave the service ambiguous. A
single allowlisted name does not prove address exclusivity: preserve that
limitation even if no other queried name shares the address. Known conflicting
SNI blocks enrichment. Keep IPv4 and IPv6 and overlapping address spaces
scoped to their supplied vantage. Bound replay indexes and provenance samples;
overflow reports an incomplete enrichment scope rather than dropping
contradictory records and selecting the remaining candidate.

## Deterministic acceptance plan

Use injected resolver responses and synthetic documentation addresses. No CI
test or offline/default invocation may ask a resolver or send a packet.

| Case | Required result |
|---|---|
| Bedrock answer `203.0.113.8`, observed at 1000, TTL 60; matching-vantage flow at 1001 | Eligible location context only; no synthetic DNS query, contact, cadence or agent claim. |
| Same flow at 1060, 2000000 or before 1000 | No location context; expiry is exclusive and future answers do not explain earlier traffic. |
| Conflicting non-AI or different AI SNI | Preserve SNI; no fallback enrichment. |
| Two eligible endpoint names share an address | Ambiguous context; do not choose a service or add confidence. |
| IPv6 compressed/expanded forms | Canonical address comparison with unchanged time and scope requirements. |
| Same address, different sensor/network/resolver | No context join; absent context is not a wildcard. |
| NXDOMAIN and NODATA | Explicit negative outcomes; no positive context, address or finding. |
| Resolver timeout, cancellation, malformed or oversized response | Bounded termination; completed records retained, collection incomplete with explicit reasons. |
| Record, question, retry, deadline or replay-index cap | Never exceed the hard ceiling; report incomplete scope without losing contradictory evidence silently. |
| Invalid digest, symlink, duplicate JSON key or unsupported schema | Refuse replay; fail closed without attempting live collection. |
| Missing live opt-in, endpoint allowlist, or invalid name | Reject before opening a resolver transport. |
| Ordinary `network.logs` scan or offline snapshot replay | Zero resolver calls and zero network sends. |

The existing passive tests in `tests/unit/test_network_logs.py` establish
TTL, shared-address, exact-context and bounded-storage behavior for exported
client observations. They do not establish live resolver correctness or the
new snapshot contract. The explicit offline resolver/send guards in that
module protect the current boundary while this proposal remains open.

## Delivery and decision points

1. Review this interface, snapshot schema, privacy implications and resolver
   dependency/transport. Choose how an engine collection exposes a reusable
   artifact without confusing it with a scan report.
2. Implement strict snapshot validation and deterministic replay first, with
   mocked acceptance cases and no egress capability.
3. Add the separate collector after transport and cancellation review. Exercise
   it with injected responses; perform any live acceptance separately and
   retain its reviewed scope and provenance.
4. Regenerate connector reference, connector inventory and product-guide
   matrix; update the network guide, configuration path/boolean declarations,
   production limitations and threat model. Run `make check`, full connector
   coverage gates, package smoke checks and required CI on the final revision.

Keep #210 open until collection and replay both meet these gates. This plan
is AI-assisted design, not independent approval or evidence of live acceptance.
