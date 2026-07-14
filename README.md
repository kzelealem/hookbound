# Hookbound

**Secure webhooks, both ways.**

Hookbound is a dependency-light webhook runtime for Go. It sends signed webhooks, receives and verifies third-party events, and provides an optional durable PostgreSQL runtime without forcing applications to deploy a separate webhook platform.

> Status: `v0.1` foundation. The public API is intentionally small, but may evolve before `v1.0.0`.

## Design goals

- Safe defaults: raw-body verification, replay windows, response limits, SSRF-aware delivery, no redirects.
- Honest reliability: direct sends make one attempt; durable delivery is at-least-once.
- Lightweight core: the root module uses only the Go standard library.
- Go-native DX: `net/http`, `context.Context`, `log/slog`, concrete configuration, typed errors.
- Explicit durability: PostgreSQL persistence is optional and queue semantics never leak into webhook semantics.
- Standards first: Standard Webhooks HMAC-SHA256 and Ed25519 profiles, including key rotation.

## Receive a webhook

```go
registry := hookbound.NewRegistry()
hookbound.HandleJSON(registry, "invoice.paid", func(ctx context.Context, message hookbound.Message[InvoicePaid]) error {
    return invoices.MarkPaid(ctx, message.Data.InvoiceID)
})

receiver, err := hookbound.NewReceiver(hookbound.ReceiverConfig{
    Verifier: standard.NewHMACVerifier(
        standard.StaticHMACKeys(secret),
        standard.WithTolerance(5*time.Minute),
    ),
    Handler: registry,
})
if err != nil {
    log.Fatal(err)
}

mux.Handle("POST /webhooks", receiver)
```

## Send a webhook

```go
sender, err := hookbound.NewSender(hookbound.SenderConfig{
    Signer: standard.NewHMACSigner(secret),
})
if err != nil {
    log.Fatal(err)
}

result, err := sender.Send(ctx, hookbound.SendRequest{
    URL:       "https://customer.example/webhooks",
    EventType: "invoice.paid",
    Body:      payload,
})
```

A direct send performs exactly one HTTP request. Use `postgres.Runtime` for durable attempts, retry scheduling, inbox deduplication, and crash recovery.

## Packages

- `hookbound`: messages, sender, receiver, handlers, authentication, outcomes, retry policy.
- `standard`: Standard Webhooks HMAC-SHA256 and Ed25519 signing and verification.
- `transport`: SSRF-aware outbound HTTP transport.
- `provider/github`: GitHub inbound verification and metadata extraction.
- `provider/stripe`: Stripe inbound verification and metadata extraction.
- `postgres`: durable inbox/outbox, deliveries, attempts, and worker claiming.
- `testkit`: deterministic webhook endpoints and assertions.
- `cmd/hookbound`: signing and verification CLI.

## Reliability contract

Hookbound guarantees no more than the underlying HTTP boundary can guarantee:

- outbound durable delivery is **at least once**;
- the message ID and payload stay stable across retries;
- each attempt has a fresh timestamp and signature;
- receivers must deduplicate by `(source, message_id)`;
- a remote endpoint can process a request even when the sender never observes its response.

See [docs/reliability.md](docs/reliability.md) and [docs/security.md](docs/security.md).

## Development

```bash
make verify
```

The repository is tested with the race detector, fuzz smoke tests, `go vet`, and multiple supported Go versions in CI.

## License

Apache-2.0.
