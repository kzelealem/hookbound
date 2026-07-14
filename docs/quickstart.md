# Quickstart

## Generate a signing secret

```bash
export HOOKBOUND_SECRET="$(go run ./cmd/hookbound generate-secret)"
```

The same secret is configured at the sender and receiver. Store production keys in a secret manager and resolve them at attempt time.

## Receive

Create a key provider and verifier, register handlers, and mount the receiver directly on `net/http`:

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

The receiver bounds and reads the body once, verifies those exact bytes, claims the replay identity, and only then decodes and dispatches it.

## Send

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
    URL: "https://customer.example/webhooks",
    EventType: "invoice.paid.v1",
    Body: payload,
})
```

`Send` performs one request. It never sleeps or silently retries. Use the PostgreSQL runtime when attempts must survive process failure.
