# HTTP Client

The transport is deliberately strict because API URLs and response data are
untrusted. URL validation is only a preflight: the HTTPS connection resolves
the hostname once and connects to a numeric address while retaining the
hostname for TLS verification. By default it rejects every non-public or
metadata address in the result, a mixed public and private answer included.
That rejection is lifted only by the trusted `allow_private_origin` opt-in,
which the scan configuration grants to every connector
(`options.allow_private_origin`) or to one connector (its own
`allow_private_origin` key), and which the operator's `--deny-private-origin`
(`ScanConfig.deny_private_origin`) overrides for the whole scan; see the
[threat model](../security/threat-model.md). A client constructed with an
explicit `allow_private_origin` argument keeps it whatever the scan grants or
refuses: the `cloud.gcp` credential transport passes its
`allow_instance_credentials` approval there, so `--deny-private-origin` does
not cover it and `--deny-instance-credentials` does. Under the opt-in the
numeric connection and TLS hostname verification still apply. Proxies and replacement
adapters are refused. Each client copies urllib3's pool-class mapping before
selecting its destination-policy pool, so a client cannot change another
session's policy. An injected `session` must be a `requests.Session` (or a
`unittest.mock` double in tests): any other object is refused with `TypeError`
at construction, because it would send requests without the destination-policy
adapter and the proxy and adapter checks.

Name resolution is bounded. `socket.getaddrinfo` has no timeout of its own, so
it runs in a worker thread and the caller waits at most 20 seconds
(`_RESOLVE_TIMEOUT`): at connection time also no longer than the client timeout
or the remaining acquisition deadline, and in the `validate_url` preflight no
longer than the connector deadline or its `dns_budget`, which `HttpClient`
sets to its timeout cut to its remaining deadline. A lookup that does not
finish in time fails the request closed (`NameResolutionError` at connection,
`ValueError` in the preflight), and the abandoned worker's late answer is
discarded, never connected to. A spent budget refuses without starting a
worker, and at most 32 workers (`_MAX_RESOLVER_THREADS`) run at once: a lookup
waits within its budget for a free one and otherwise fails closed, so a
stalled resolver cannot accumulate threads.

Two deadlines protect different phases. The acquisition deadline covers DNS
completion, TCP/TLS, request transmission and response headers; the resolver
call cannot be stopped safely, but the request stops waiting for it and a late
result cannot proceed to a connection. The body-read deadline is separate from
the socket's per-read timeout, so a server cannot keep a response alive
indefinitely by sending occasional bytes. An expired body is incomplete, even
if socket shutdown makes the response iterator end normally.

The read watchdog depends on urllib3's response shutdown and connection-release
behavior. urllib3 returns a keep-alive connection to its pool while the final
body read completes, so interruption must not race with that release and affect
a subsequent request. `tests/unit/test_http_contracts.py` is a compatibility
tripwire for the urllib3 hooks and response methods used by this transport; run
it when changing the urllib3 constraint or lock.

::: shadowscan.utils.http
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
