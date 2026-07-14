# Hookbound

**Secure webhooks, both ways.**

Hookbound is a dependency-light webhook runtime for Go. It sends signed webhooks, receives and verifies third-party events, and provides an optional durable PostgreSQL runtime without forcing applications to deploy a separate webhook platform.

> Status: `v0.1.0` foundation. The public API is intentionally small, but may evolve before `v1.0.0`.

## Design goals

- Safe defaults: raw-body verification, replay windows, response limits, SSRF-aware delivery, no redirects.
- Honest reliability: direct sends make one attempt; durable delivery is at-least-once.
- Lightweight core: the root module uses only the Go standard library.
- Go-native DX: `net/http`, `context.Context`, `log/slog`, concrete configuration, typed errors.
- Explicit durability: PostgreSQL persistence is optional and queue semantics never leak into webhook semantics.
- Standards first: Standard Webhooks HMAC-SHA256 and Ed25519 profiles, including key rotation.

## Install

```bash
go get github.com/hookbound/hookbound@v0.1.0
```

## Receive a webhook

```go
keys, err := standard.StaticHMACKeys(os.Getenv("HOOKBOUND_SECRET"))
if err != nil {
    return err
}
verifier, err := standard.NewHMACVerifier(keys)
if err != nil {
    return err
}

registry := hookbound.NewRegistry()
if err := hookbound.HandleJSON(registry, "invoice.paid.v1", handleInvoicePaid); err != nil {
    return err
}
receiver, err := hookbound.NewReceiver(hookbound.ReceiverConfig{
    Verifier: verifier,
    Handler: registry,
    ReplayGuard: hookbound.NewMemoryReplayGuard(10_000, nil),
})
if err != nil {
    return err
}

mux.Handle("POST /webhooks", receiver)
```

## Send a webhook

```go
signer, err := standard.NewHMACSigner(keys)
if err != nil {
    return err
}
sender, err := hookbound.NewSender(hookbound.SenderConfig{Signer: signer})
if err != nil {
    return err
}

result, err := sender.Send(ctx, hookbound.SendRequest{
    URL:       "https://customer.example/webhooks",
    EventType: "invoice.paid.v1",
    Body:      payload,
})
```

A direct send performs exactly one HTTP request. Use `postgres.Runtime` for durable attempts, retry scheduling, inbox deduplication, and crash recovery. See the [quickstart](docs/quickstart.md) and [PostgreSQL guide](docs/postgres.md).

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

The repository is tested with the race detector, dedicated bounded fuzz jobs, `go vet`, and multiple Go toolchain lines in CI.

## License

Apache-2.0.
