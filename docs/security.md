# Security model

## Inbound

Hookbound reads and verifies the exact raw body before JSON decoding. Verification supports timestamp tolerance, constant-time HMAC comparison, Ed25519 trust lists, multiple signatures for key rotation, strict body limits, and stable message IDs for deduplication.

## Outbound

The default transport requires HTTPS, rejects URL credentials, blocks loopback/private/link-local/multicast/unspecified addresses, prevents automatic redirects, validates DNS results, limits response bodies, and applies bounded timeouts.

Network policy is defense in depth, not a substitute for isolating delivery workers or using a dedicated egress proxy in high-risk multi-tenant environments.

## Escape hatches

`SenderConfig.UnsafeHTTPClient` deliberately names its risk: a custom client can bypass Hookbound's DNS/IP dial enforcement. Use `NetworkPolicy` for TLS, proxy, and dial customization whenever possible. Explicit proxies become part of the application's egress trust boundary and must enforce destination policy themselves.

Durable PostgreSQL audit records remove common credential headers. Response bodies are not stored unless `MaxResponseBodyBytes` is explicitly enabled.
