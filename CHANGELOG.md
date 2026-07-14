# Changelog

All notable changes to Hookbound will be documented here. The project follows Semantic Versioning after the `v0.x` API-development period.

## Unreleased

- Corrected the canonical module path and release target to `github.com/kzelealem/hookbound` so Go tooling can resolve the public repository.
- Added registry, release, license, and package-discovery metadata for the first valid public Go module release.
- Made in-memory replay claims commit-aware so concurrent duplicates cannot be acknowledged before the active handler succeeds.
- Hardened signature tolerance, `Retry-After`, jitter, message IDs, authentication headers, and protocol parser boundaries against overflow and ambiguity.
- Froze outbound network policies at sender construction and made `AllowAnyPort` and empty port allow-lists unambiguous.
- Corrected CLI event-type extraction and expanded adversarial regression and fuzz coverage.
- Hardened PostgreSQL completion state, redaction, retry classification, database-clock leases, and transactional checksum-tracked migrations.
- Added explicit PostgreSQL schema isolation, race-safe hashed publication idempotency keys, renewable worker leases, and bounded retention cleanup with supporting indexes.
- Added real-container PostgreSQL tests for migration concurrency and drift, inbox/outbox deduplication races, `SKIP LOCKED` claiming, lease recovery and heartbeat behavior, stale ownership, and cleanup.
- Pinned all GitHub Actions to immutable commit SHAs and added signed-tag enforcement, reproducible archives, SHA-256 checksums, an SPDX SBOM, Sigstore provenance, and SBOM attestations for releases.
- Added schema-isolated PostgreSQL operation, race-safe publication idempotency, active lease renewal, bounded terminal-record retention, and container-backed integration coverage.
- Pinned every GitHub Action to an immutable commit and added signed-tag release verification, reproducible archives, SHA-256 checksums, SPDX SBOM generation, and Sigstore-backed provenance/SBOM attestations.

## v0.1.0 — 2026-07-14

- Added the dependency-free sender, receiver, typed handler registry, authentication, retries, and machine-readable errors.
- Added Standard Webhooks HMAC-SHA256 and Ed25519 signing, verification, rotation, and key utilities.
- Added an SSRF-aware outbound transport and conservative response classifier.
- Added lightweight GitHub and Stripe inbound verifiers without provider SDK dependencies.
- Added optional PostgreSQL durable inbox/outbox state, leases, attempts, and explicit workers.
- Added deterministic testkit utilities and the `hookbound` CLI.
