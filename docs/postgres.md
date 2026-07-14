# Durable PostgreSQL runtime

The `postgres` package uses `database/sql`, so applications retain control of their PostgreSQL driver, pool, TLS settings, and credentials. Hookbound stores four separate records:

- immutable messages;
- destination-specific deliveries;
- one record per outbound HTTP attempt;
- inbound receipts keyed by `(source, message_id)`.

## Schema isolation

Use a dedicated schema in production and pass the same schema to the migrator and store. Runtime queries fully qualify every Hookbound relation and do not rely on the connection pool's ambient `search_path`.

```go
const hookboundSchema = "hookbound"

if err := postgres.MigrateWithConfig(ctx, db, postgres.MigrationConfig{
    Schema: hookboundSchema,
}); err != nil {
    return err
}

store, err := postgres.NewStoreWithConfig(db, postgres.StoreConfig{
    Schema: hookboundSchema,
})
if err != nil {
    return err
}
```

An empty schema keeps the compatibility default, `public`. The built-in migrator:

- creates the configured schema when permitted;
- serializes concurrent migrators with a schema-specific advisory transaction lock;
- applies every migration in one transaction;
- uses an explicit local migration `search_path`;
- records SHA-256 migration checksums in the selected schema;
- rejects modification of an already-applied migration.

Applications may instead consume `postgres.Migrations()` through their normal migration system. Preserve file ordering and the `-- hookbound:statement` boundaries.

## Transactional publication

`EnqueueTx` stores the immutable message and delivery in the caller's transaction. A rollback removes both the business change and the webhook publication.

```go
publication, err := store.EnqueueTx(ctx, tx, hookbound.SendRequest{
    URL:       endpointURL,
    EventType: "invoice.paid.v1",
    Body:      payload,
})
```

### Publication idempotency

Use `EnqueueWithOptions` or `EnqueueTxWithOptions` when a business operation may be retried after an ambiguous commit or process failure.

```go
publication, err := store.EnqueueTxWithOptions(
    ctx,
    tx,
    hookbound.SendRequest{
        URL:       endpointURL,
        EventType: "invoice.paid.v1",
        Body:      payload,
    },
    postgres.EnqueueOptions{
        IdempotencyKey: tenantID + ":invoice:" + invoiceID + ":endpoint:" + endpointID,
    },
)
```

The idempotency key is scoped to the configured Hookbound schema. Hookbound stores only a domain-separated SHA-256 digest of the key. Reusing the key with the same destination, event type, body, content type, headers, and any explicit message ID returns the original publication. Reusing it with different immutable content returns `hookbound.CodeConflict`.

Choose keys from stable business identity, not random attempt identity. Include the tenant and destination identity when the same business event can be published independently to multiple endpoints.

Do not place credentials in durable request headers. Configure the sender's `Authenticator` so secrets are resolved at attempt time and never written to Hookbound's tables.

## Workers and renewable leases

`postgres.NewRuntime` starts no goroutines. Call `Run(ctx)` explicitly, or call `WorkOutboundOnce` and `WorkInboundOnce` from an existing worker system.

Each outbound claim creates exactly one attempt and one lease. Completion is conditional on the original attempt ownership, preventing a stale worker from overwriting a newer result. PostgreSQL time is authoritative unless a test clock is explicitly injected.

Long-running sends and handlers are protected by lease heartbeats:

```go
runtime, err := postgres.NewRuntime(postgres.RuntimeConfig{
    Store:                store,
    Sender:               sender,
    InboundHandler:       handler,
    LeaseDuration:        time.Minute,
    LeaseRenewalInterval: 20 * time.Second,
    LeaseRenewalTimeout:  5 * time.Second,
    CompletionTimeout:    10 * time.Second,
    OutboundWorkers:      4,
    InboundWorkers:       4,
})
```

The default renewal interval is one third of the lease. The default renewal timeout is the smaller of five seconds and the interval. Hookbound rejects configurations where a renewal cannot finish before the current lease expires.

If renewal fails or ownership is lost, Hookbound cancels the active send or handler and does not record a potentially stale completion. The row remains recoverable after its existing lease expires. This deliberately preserves at-least-once behavior rather than pretending an ambiguous attempt was safely completed.

`CompletionTimeout` gives state persistence a fresh bounded context after the caller cancels an in-flight worker.

## Retention and cleanup

`Store.Cleanup` performs one bounded transaction. It uses `FOR UPDATE SKIP LOCKED`, so multiple cleanup processes may run without selecting the same rows.

```go
result, err := store.Cleanup(ctx, postgres.RetentionPolicy{
    DeliveredRetention:      30 * 24 * time.Hour,
    FailedDeliveryRetention: 90 * 24 * time.Hour,
    ReceiptRetention:        30 * 24 * time.Hour,
    OrphanMessageRetention:  30 * 24 * time.Hour,
    BatchSize:               1_000,
})
```

A zero duration disables that category. A zero batch size defaults to 1,000; the maximum is 10,000. Each enabled category may delete up to one batch per call. Schedule repeated bounded passes rather than one unbounded maintenance transaction.

Cleanup removes only terminal deliveries (`delivered`, `permanent_failure`, `disabled`, or `exhausted`) and terminal receipts (`processed`, `failed`, or `exhausted`). Delivery attempts are removed through the delivery foreign key. Pending, retrying, processing, and in-flight records are never retention candidates. Orphan message age is measured from message creation after all of its deliveries have been removed.

The embedded migrations include indexes for terminal cleanup, message lookup, and orphan detection.

## Audit data

Response bodies are not persisted by default because they may contain customer data or credentials. Set `MaxResponseBodyBytes` only when the operational need is understood. Credential and signature headers are removed, and applications can add custom sensitive header names. Raw error causes are also omitted by default; enable `PersistErrorDetails` only after reviewing errors produced by custom authenticators, transports, and handlers.

## PostgreSQL integration tests

The real-database suite lives in a nested module so the root module remains standard-library-only.

```bash
make test-postgres-integration
```

By default it starts and removes a PostgreSQL 17 container through Docker. To use an existing disposable database instead:

```bash
HOOKBOUND_TEST_DATABASE_URL='postgres://user:password@localhost/hookbound_test?sslmode=disable' \
  make test-postgres-integration
```

The suite intentionally fails when neither a working database URL nor Docker is available. It verifies concurrent migrations and checksum drift, schema isolation, publication and receipt deduplication races, `SKIP LOCKED` claiming, lease renewal and recovery, runtime heartbeats, stale-owner rejection, and retention behavior.
