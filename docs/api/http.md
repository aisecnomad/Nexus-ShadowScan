# HTTP Client

The transport is deliberately strict because API URLs and response data are
untrusted. URL validation is only a preflight: the HTTPS connection resolves
the hostname once, rejects every non-public or metadata address in the result,
and connects to a numeric address while retaining the hostname for TLS
verification. Proxies and replacement adapters are refused. Each client copies
urllib3's pool-class mapping before selecting its destination-policy pool, so a
client cannot change another session's policy.

Two deadlines protect different phases. The acquisition deadline covers DNS
completion, TCP/TLS, request transmission and response headers; DNS cannot be
stopped safely, but a late result cannot proceed to a connection. The body-read
deadline is separate from the socket's per-read timeout, so a server cannot
keep a response alive indefinitely by sending occasional bytes. An expired
body is incomplete, even if socket shutdown makes the response iterator end
normally.

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
