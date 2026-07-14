# Reliability model

HTTP cannot provide universal exactly-once delivery. A destination may commit a webhook and return success while the sender crashes before recording the response. Hookbound therefore uses stable message IDs, at-least-once delivery, receiver-side deduplication, and explicit publication idempotency.

For retries:

- the message ID and body remain unchanged;
- the attempt timestamp and signature are regenerated;
- `2xx` is delivered;
- `410` disables the destination;
- `408`, `425`, `429`, most `5xx`, timeouts, resets, and temporary DNS failures retry;
- redirects are rejected by default;
- a valid bounded `Retry-After` may delay a retry further, but never shortens the configured local backoff.

## Publication idempotency

A durable enqueue can itself have an ambiguous result: the transaction may commit while the caller loses the response. `postgres.EnqueueWithOptions` and `EnqueueTxWithOptions` accept a stable publication idempotency key. The raw key is never stored. Equivalent retries return the original message and delivery IDs; conflicting reuse fails.

Publication idempotency prevents duplicate durable rows. It does not make remote HTTP processing exactly once. The destination must still deduplicate the stable message ID.

## Replay claims

The built-in memory replay guard separates an active handler from an accepted message. A concurrent duplicate waits for the active claim to commit or release; it is never acknowledged merely because another request is still processing. A successful handler is acknowledged only after a commit-aware replay guard records acceptance.

Custom `ReplayGuard` implementations must preserve the same contract: `Claim` may return `claimed=false` only for a message that has already been accepted. Implement `ReplayCommitter` when the backing store distinguishes active claims from accepted identities.

## Durable leases

PostgreSQL lease timestamps use the database clock by default so workers on hosts with skewed clocks agree on due and expired work. Active durable workers renew their leases before expiry. Renewal is conditional on the current attempt number and, for outbound delivery, the unfinished attempt identity.

A renewal failure cancels the active work context and leaves the row to expire naturally. A stale worker cannot renew or complete a claim after another worker reclaims it. This may produce a duplicate external attempt after an ambiguous network or database failure, which is required for honest at-least-once delivery.

Choose a lease duration that comfortably exceeds the renewal interval plus the worst expected database renewal latency. Keep sender and handler code responsive to context cancellation.

## Retention

Retention is explicit, terminal-state-only, and bounded. Cleanup uses row locking with `SKIP LOCKED`; it never treats active work as disposable. Operators choose different windows for successful deliveries, failed deliveries, inbound receipts, and unreferenced immutable messages.
