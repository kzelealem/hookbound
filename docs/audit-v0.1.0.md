# Hookbound v0.1.0 maintainer audit

Audit date: 2026-07-14  
Audited tag: `v0.1.0` (`018271e`)  
Hardening branch: `audit/hardening-v0.2.0`

## Executive verdict

Hookbound has unusually good instincts for a first release: the package is small, the protocol boundaries are explicit, the root module is standard-library-only, direct sends honestly perform one attempt, raw request bytes are preserved for verification, redirects are disabled, and the PostgreSQL runtime is optional rather than infecting the core API.

The v0.1.0 snapshot was **not ready to be called production-grade**, primarily because its replay lifecycle could acknowledge a duplicate before processing succeeded and because the durable PostgreSQL state machine had almost no real database coverage. Several boundary-arithmetic and configuration ambiguities also produced security or correctness failures under adversarial input.

After the hardening commits in this branch, the non-durable core is a strong release candidate. The PostgreSQL package should remain beta until real-container tests prove migration, `SKIP LOCKED`, lease expiry, stale completion, crash recovery, and concurrent deduplication behavior.

## Provenance and review scope

The supplied Git bundle is valid and contains the complete reachable history, `main`, and the annotated `v0.1.0` tag. The tag and `main` both point at `018271e`. A fresh archive of the tagged tree matches the supplied source ZIP byte-for-byte.

The original history contains 11 semantically separated commits, but all 11 were authored within roughly 21 minutes. The boundaries are useful, but that timing looks like a reconstructed or scripted history rather than evidence of an organic review cycle. It should not be treated as proof that each layer was independently tested before the next was added.

Review coverage included:

- public API and package boundaries;
- signing and verification behavior;
- provider adapters;
- replay and concurrency semantics;
- SSRF and HTTP transport policy;
- retry classification and arithmetic;
- durable inbox/outbox state transitions;
- migration behavior;
- shutdown and cancellation behavior;
- error and audit-data handling;
- CLI behavior;
- tests, fuzz targets, docs, CI, release metadata, and Git history.

## What is already strong

### Architecture

- The core does not pretend HTTP can provide exactly-once delivery.
- Message, delivery, attempt, and receipt are separate concepts.
- Direct delivery and durable delivery have distinct contracts.
- Constructors do not start hidden goroutines.
- PostgreSQL is optional and uses `database/sql`, leaving the driver choice to applications.
- The provider packages avoid pulling entire SDKs into a webhook verifier.

### Security defaults

- Verification runs over the exact raw body.
- HMAC comparison is constant-time.
- Signature key rotation is supported.
- HTTPS and port 443 are the outbound defaults.
- Redirects are refused.
- URL credentials are forbidden.
- DNS results are validated immediately before dialing.
- Private, loopback, link-local, multicast, unspecified, and reserved ranges are blocked unless explicitly allowed.
- Request and response bodies are bounded.
- Durable response-body persistence is opt-in.

### Developer experience

- The public API is small and Go-native.
- Errors have stable machine-readable categories.
- The typed handler registry preserves raw bytes.
- The testkit is useful without becoming a second framework.
- Documentation explains the at-least-once contract instead of marketing around it.

## Reproduced release blockers in v0.1.0

### 1. Concurrent duplicate could be acknowledged before the original handler committed

The receiver inserted the replay identity before invoking the handler. A concurrent request that observed the identity immediately received success. If the original handler later failed, one provider request had already been told the event was accepted even though no successful processing occurred.

This is a genuine message-loss path, not a theoretical race.

**Resolution:** the memory guard now distinguishes active and accepted claims. Concurrent duplicates wait for commit or release. `ReplayCommitter` lets commit-aware stores record acceptance only after handler success. See `8fee370`.

### 2. Handler failure plus replay-release failure returned HTTP 204

A generic handler error was joined with a coded replay error. `ErrorCode` found the replay code, and the default responder mapped it to `204 No Content`. The system therefore acknowledged a request precisely when both business processing and replay cleanup had failed.

**Resolution:** replay-store failures are no longer interpreted as duplicate success, and the combined failure is wrapped as a handler failure. See `8fee370`.

## Other reproduced correctness and security defects

### Signature tolerance overflow

The Standard Webhooks and Stripe verifiers computed an absolute duration by negating a negative `time.Duration`. For sufficiently distant timestamps, `time.Sub` saturates and negation overflows, allowing a correctly signed far-future timestamp to bypass freshness checks.

**Resolution:** compare time in the known positive direction. See `a62a0d5`.

### `Retry-After` integer overflow

A large numeric `Retry-After` value was converted to `time.Duration` and multiplied before the configured cap was applied. The multiplication could overflow and schedule a retry in the past.

**Resolution:** cap in integer-second space before duration conversion. See `a62a0d5`.

### Out-of-contract jitter could overflow retry scheduling

`RetryPolicy` documented jitter as bounded but trusted custom implementations without enforcing the contract. A malicious or buggy jitter could overflow `delay+jitter` and produce a date centuries in the past.

**Resolution:** clamp jitter to `[0,max]` and guard addition. `CryptoJitter` also avoids `max+1` duration overflow. See `a62a0d5`.

### Port-policy flags contradicted each other

Starting with `DefaultPolicy` and setting `AllowAnyPort=true` still retained the default `{443}` map, so arbitrary ports remained blocked. Conversely, an explicitly empty `AllowedPorts` map disabled the check and allowed every port.

**Resolution:** `AllowAnyPort` is authoritative; an empty allow-list restores the secure default. See `9c44f52`.

### Mutable caller-owned network policy

The sender retained maps, slices, and pointer fields from caller configuration. Mutating them after construction could change a live sender's security policy or race with delivery.

**Resolution:** policy cloning now copies maps, CIDRs, dialers, and TLS configuration, and floors TLS at 1.2. The sender stores the frozen snapshot. See `9c44f52`.

### CLI silently disabled normal event-type extraction

Without `--type`, `hookbound verify` set `AllowNoType=true`, so a normal signed JSON payload containing `"type"` was reported as `unknown`. This contradicted the flag's documented purpose.

**Resolution:** the CLI now uses the verifier's default JSON type extraction unless an explicit override is supplied. See `a329e50`.

## Durable-runtime defects corrected on the hardening branch

- Invalid or injectable outbound headers are rejected by `SendRequest.Validate`, before either direct send or durable persistence (`cdb3633`).
- Deterministic inbox errors such as decode failures, invalid messages, unsupported events, and invalid configuration become terminal `failed` receipts rather than retrying to exhaustion (`ecbb819`).
- A remote `Retry-After` can delay, but cannot shorten, local backoff (`ecbb819`).
- Attempt completion verifies the attempt ID, delivery ID, attempt number, unfinished state, and affected-row count (`ecbb819`).
- Credential and webhook-signature headers are redacted from durable audit records (`ecbb819`).
- Raw error causes are disabled by default; persistence requires the explicit `PersistErrorDetails` opt-in (`ecbb819`).
- Error truncation preserves valid UTF-8 (`ecbb819`).
- Worker completion uses a fresh bounded context after cancellation so lease state can still be recorded (`ecbb819`).
- Panics from durable handlers, custom outbound code, or a worker iteration are converted to coded errors so workers survive and claimed work can be completed or recovered (`72f8997`).
- Due checks, lease timestamps, and completion timestamps use PostgreSQL's clock by default, avoiding multi-host application-clock skew (`60594e6`).
- Embedded migrations run in one transaction, serialize concurrent migrators, and record immutable checksums (`4157317`).

## Additional protocol hardening

Commit `2f084a4` also closes smaller but real edge cases:

- message IDs with leading/trailing whitespace or control bytes are rejected;
- bearer/header secrets reject all unsafe header controls;
- Basic authentication rejects ambiguous usernames containing `:`;
- authentication header names use the same strict token validation as request headers;
- Standard Webhooks JSON type extraction rejects trailing garbage;
- Ed25519 signing key rotation is capped and signer output length is checked;
- a handler panic releases an active in-memory replay claim before the panic is rethrown;
- the test endpoint no longer attempts to write bodies for bodyless HTTP statuses.

## Remaining release blockers

### 1. PostgreSQL behavior is not proven against PostgreSQL

Current PostgreSQL statement coverage is about 14%, and nearly all of it is helper/state-transition testing. There is no real database test for:

- first migration and repeat migration;
- checksum mismatch detection;
- concurrent migration locking;
- two workers racing through `FOR UPDATE SKIP LOCKED`;
- lease expiration and abandoned-attempt recording;
- stale worker completion rejection;
- concurrent receipt deduplication;
- crash between claim and completion;
- transaction rollback around `EnqueueTx`;
- database restart or connection loss during completion.

This is the most important remaining task. Do not label the durable package production-ready until these tests run in CI against at least the oldest and newest supported PostgreSQL major versions.

### 2. Leases are not heartbeated or extended

The runtime has a fixed lease and no renewal operation. If a custom sender timeout or inbound handler runs beyond `LeaseDuration`, another worker can reclaim the same work while the first is still active. At-least-once semantics permit duplicates, but overlapping execution is materially more dangerous than sequential retry.

Add `ExtendDeliveryLease` and `ExtendReceiptLease`, or explicitly enforce a maximum work duration below the lease. Test renewal loss and stale-worker completion.

### 3. Durable publication lacks a delivery idempotency key

Message IDs protect immutable message content, but repeating `Enqueue` with the same message ID still creates another delivery. After an ambiguous transaction commit, a caller cannot safely retry without potentially duplicating the destination delivery.

Add an optional caller-supplied publication/delivery idempotency key with a uniqueness constraint and immutable-content conflict check.

### 4. Migration namespace is search-path dependent

Tables are unqualified. This is convenient, but applications with a mutable or hostile `search_path` can migrate or query the wrong schema. Support an explicit validated schema name or state clearly that callers must pin `search_path` at connection creation.

### 5. No retention and cleanup API

Attempts, completed deliveries, processed receipts, and persisted bodies grow forever. Provide documented SQL or store methods for bounded retention, with batch deletion and indexes that keep cleanup predictable.

## Important design issues still requiring a decision

### Event type source of truth

The Standard Webhooks signature authenticates ID, timestamp, and body. `X-Hookbound-Event` is not signed. The safest contract is: the event type lives in the signed JSON body, and the header is informational only. Consider removing the header, renaming it to make that status explicit, or providing a small standard envelope builder that guarantees body/type consistency.

### GitHub header trust

GitHub's HMAC covers the body, not the delivery and event headers Hookbound uses for deduplication and routing. This is a limitation of the provider protocol, not a cryptographic mistake in Hookbound. It still deserves a prominent deployment warning and test cases for trusted-proxy behavior.

### Typed-nil interfaces

Several constructors check `interface == nil`, which does not catch a typed nil pointer stored in an interface. This can turn a configuration mistake into a panic later. Decide whether the library will use reflection to reject typed nils at boundaries or document that Go's normal typed-nil rule applies.

### Persistence versus observability

Disabling raw durable error details by default is the safe choice, but operators still need diagnostics. Add structured hooks or a redactor interface so applications can emit detailed errors to their controlled logging system while storing only stable codes and safe summaries.

## CI and release engineering review

### Good

- race detector and shuffle are enabled;
- minimum and current Go lines are exercised;
- `go vet`, formatting, builds, CodeQL, Dependabot, and `govulncheck` are present;
- fuzz targets exist for the highest-risk parsers.

### Improved on this branch

- dedicated bounded fuzz jobs now execute fuzzing rather than only seed corpora;
- `go mod verify` and job timeouts were added;
- the README no longer overstates ordinary tests as fuzz execution.

### Still missing

- PostgreSQL service integration jobs;
- action pinning by immutable commit SHA;
- release checksums, SBOM, build provenance, and signed tags or attestations;
- API compatibility checking between tags;
- a verified release workflow that builds the CLI for supported platforms;
- evidence that private vulnerability reporting is enabled for the hosted repository.

The supplied `v0.1.0` tag is annotated but not cryptographically signed.

## Verification performed

On the available Go 1.23.2 toolchain:

- `gofmt` clean;
- `go vet ./...` passed;
- `go test ./...` passed;
- `go test -race -shuffle=on -count=1 ./...` passed;
- Standard signature parser fuzzed for 2 seconds with 2,912 executions;
- transport URL parser fuzzed for 2 seconds with 15,705 executions;
- package coverage after hardening:
  - root: 62.0%;
  - CLI: 69.5%;
  - PostgreSQL: 14.0%;
  - GitHub: 72.1%;
  - Stripe: 78.3%;
  - Standard Webhooks: 67.4%;
  - testkit: 50.4%;
  - transport: 82.2%.

The environment could not download Go 1.25/1.26 toolchains or locally install/run `govulncheck`, `staticcheck`, `gosec`, or a PostgreSQL driver because outbound module-network access and Docker were unavailable. CI is configured for the current toolchains and vulnerability scan, but those results were not independently reproduced during this audit.

## Recommended release sequence

1. Merge the hardening commits as a `v0.2.0-rc.1`, not a patch release. The behavior and replay contract changed enough to deserve a minor pre-1.0 version.
2. Add a separate PostgreSQL integration-test module and CI matrix, then test real concurrent claims, migrations, leases, and crash recovery.
3. Add lease renewal or enforce maximum work duration below the lease.
4. Add delivery-level idempotency and retention operations.
5. Run current `govulncheck`, `staticcheck`, `gosec`, and API-diff checks in CI.
6. Pin CI actions, add provenance/SBOM/checksums, and sign or attest the release.
7. Publish `v0.2.0` only after the durable matrix passes repeatedly under race and randomized concurrency.

## Bottom line

The package is not trash. Its architecture is much better than the average new webhook library, and the restraint around dependencies and hidden behavior is exactly right. The dangerous parts were mostly at lifecycle boundaries: “accepted versus in progress,” arithmetic at extreme values, caller-owned mutable policy, and durable state that looked plausible without having been exercised against its actual database.

The hardening branch fixes the concrete core defects found in this audit. The remaining work is concentrated and clear: prove PostgreSQL behavior, handle long-running leases, make publication retries idempotent, and finish release-supply-chain discipline.
