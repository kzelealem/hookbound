# Security model

## Inbound

Hookbound reads and verifies the exact raw body before JSON decoding. Verification supports timestamp tolerance, constant-time HMAC comparison, Ed25519 trust lists, multiple signatures for key rotation, strict body limits, and stable message IDs for deduplication.

## Outbound

The default transport requires HTTPS, rejects URL credentials, blocks loopback/private/link-local/multicast/unspecified addresses, prevents automatic redirects, validates DNS results, limits response bodies, and applies bounded timeouts.

Network policy is defense in depth, not a substitute for isolating delivery workers or using a dedicated egress proxy in high-risk multi-tenant environments.

## Escape hatches

`SenderConfig.UnsafeHTTPClient` deliberately names its risk: a custom client can bypass Hookbound's DNS/IP dial enforcement. Use `NetworkPolicy` for TLS, proxy, and dial customization whenever possible. Explicit proxies become part of the application's egress trust boundary and must enforce destination policy themselves.

Durable PostgreSQL audit records remove common credential and webhook-signature headers. Response bodies are not stored unless `MaxResponseBodyBytes` is explicitly enabled. Raw error details are also disabled unless `PersistErrorDetails` is explicitly enabled.


## Signed and unsigned metadata

Standard Webhooks authenticates the message ID, timestamp, and exact body. Put the event `type` inside the signed JSON body. Hookbound's `X-Hookbound-Event` outbound header is convenience metadata and is not part of the Standard Webhooks signature; receivers must not use it as an authentication boundary.

GitHub's `X-Hub-Signature-256` authenticates the request body, not the `X-GitHub-Delivery` or `X-GitHub-Event` headers. Hookbound follows GitHub's protocol and uses those headers for identity and routing after body verification. Deploy GitHub receivers behind trusted TLS termination and prevent untrusted intermediaries from rewriting webhook headers.
