# Reliability model

HTTP cannot provide universal exactly-once delivery. A destination may commit a webhook and return success while the sender crashes before recording the response. Hookbound therefore uses stable message IDs, at-least-once delivery, and receiver-side deduplication.

For retries:

- the message ID and body remain unchanged;
- the attempt timestamp and signature are regenerated;
- `2xx` is delivered;
- `410` disables the destination;
- `408`, `425`, `429`, most `5xx`, timeouts, resets, and temporary DNS failures retry;
- redirects are rejected by default;
- `Retry-After` overrides the normal backoff when valid and bounded.
