# Security model

## Inbound

Hookbound reads and verifies the exact raw body before JSON decoding. Verification supports timestamp tolerance, constant-time HMAC comparison, Ed25519 trust lists, multiple signatures for key rotation, strict body limits, and stable message IDs for deduplication.

## Outbound

The default transport requires HTTPS, rejects URL credentials, blocks loopback/private/link-local/multicast/unspecified addresses, prevents automatic redirects, validates DNS results, limits response bodies, and applies bounded timeouts.

Network policy is defense in depth, not a substitute for isolating delivery workers or using a dedicated egress proxy in high-risk multi-tenant environments.
