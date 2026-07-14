# Architecture

Hookbound separates four concepts:

1. **Message** — immutable event identity and exact body.
2. **Delivery** — one message destined for one URL.
3. **Attempt** — one HTTP request for a delivery.
4. **Receipt** — one inbound message accepted by a receiver.

The root package handles protocol boundaries. The `standard` package handles interoperable signatures. The `transport` package handles outbound network policy. The `postgres` package persists durable state and claims one attempt at a time.

No constructor starts hidden goroutines. No direct send retries. Durable workers perform one external attempt and persist the outcome before scheduling another.
