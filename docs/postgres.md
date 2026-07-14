# Durable PostgreSQL runtime

The `postgres` package uses `database/sql`, so applications retain control of their PostgreSQL driver. It stores four separate records:

- immutable messages;
- destination-specific deliveries;
- one record per HTTP attempt;
- inbound receipts keyed by `(source, message_id)`.

## Schema

Apply the embedded idempotent migration through `postgres.Migrate`, or consume `postgres.Migrations()` with the application's migration tool.

```go
if err := postgres.Migrate(ctx, db); err != nil {
    return err
}
```

## Transactional publication

`EnqueueTx` stores the immutable message and delivery in the caller's transaction. A rollback removes both the business change and the webhook publication.

```go
publication, err := store.EnqueueTx(ctx, tx, hookbound.SendRequest{
    URL: endpointURL,
    EventType: "invoice.paid.v1",
    Body: payload,
})
```

Do not place credentials in durable request headers. Configure the sender's `Authenticator` so secrets are resolved at attempt time and never written to Hookbound's tables.

## Workers

`postgres.NewRuntime` starts no goroutines. Call `Run(ctx)` explicitly, or call `WorkOutboundOnce` and `WorkInboundOnce` from an existing worker system.

Each outbound claim creates exactly one attempt and one lease. Expired leases are recoverable and preserved as abandoned attempts. Completion is conditional on the original lease, preventing a stale worker from overwriting a newer result.

## Audit retention

Response bodies are not persisted by default because they may contain customer data or credentials. Set `MaxResponseBodyBytes` through `postgres.NewStoreWithConfig` only when the operational need is understood. Common credential headers are always removed, and applications can add custom sensitive header names.
