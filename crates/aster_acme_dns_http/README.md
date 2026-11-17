# aster_acme_dns_http

Host-side execution of `aster_acme_dns::operation::HttpRequest` through Forge's shared HTTP transport. `ForgeDnsHttp` is cheap to clone and lazily shares its connection pool. Construction and local provider discovery perform no network I/O.

Requests contain method, URL, headers, already encoded body bytes and an explicit mutation classification. The adapter preserves payload bytes, validates canonical HTTPS URLs and rejects URL normalization after signing, disables redirects and automatic retries, and bounds URLs (8 KiB), request headers (64 KiB), bodies/responses (1 MiB), connection establishment and the host's absolute cancellation/deadline scope. Failed mutations remain uncertain after dispatch; malformed requests fail before dispatch. Raw URLs, headers, tokens and response bodies are excluded from transport errors and response Debug output.

Provider code interprets status, headers and body. HTTP success alone does not prove publication ownership or CA acceptance. No file storage or credential loading is bundled: the independent `CredentialReader` port is supplied by CLI/embedding hosts under their private-file policy.

Tests use loopback only under `cfg(test)` to verify exact bytes, no retries/redirects, invalid inputs, size limits, deadlines and cancellation. Production does not expose an insecure-HTTP switch.
