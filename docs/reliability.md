# Reliability model

HTTP cannot provide universal exactly-once delivery. A destination may commit a webhook and return success while the sender crashes before recording the response. Hookbound therefore uses stable message IDs, at-least-once delivery, and receiver-side deduplication.

For retries:

- the message ID and body remain unchanged;
- the attempt timestamp and signature are regenerated;
- `2xx` is delivered;
- `410` disables the destination;
- `408`, `425`, `429`, most `5xx`, timeouts, resets, and temporary DNS failures retry;
- redirects are rejected by default;
- a valid bounded `Retry-After` may delay a retry further, but never shortens the configured local backoff.


## Replay claims

The built-in memory replay guard separates an active handler from an accepted message. A concurrent duplicate waits for the active claim to commit or release; it is never acknowledged merely because another request is still processing. A successful handler is acknowledged only after a commit-aware replay guard records acceptance.

Custom `ReplayGuard` implementations must preserve the same contract: `Claim` may return `claimed=false` only for a message that has already been accepted. Implement `ReplayCommitter` when the backing store distinguishes active claims from accepted identities.

## Durable leases

PostgreSQL lease timestamps use the database clock by default so workers on hosts with skewed clocks agree on due and expired work. Hookbound does not yet extend leases while a handler or HTTP attempt is running. Configure `LeaseDuration` above the longest allowed attempt or handler execution time; otherwise duplicate work is possible after lease expiry.
