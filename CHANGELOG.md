# Changelog

All notable changes to Hookbound will be documented here. The project follows Semantic Versioning after the `v0.x` API-development period.

## v0.1.0 — 2026-07-14

- Added the dependency-free sender, receiver, typed handler registry, authentication, retries, and machine-readable errors.
- Added Standard Webhooks HMAC-SHA256 and Ed25519 signing, verification, rotation, and key utilities.
- Added an SSRF-aware outbound transport and conservative response classifier.
- Added lightweight GitHub and Stripe inbound verifiers without provider SDK dependencies.
- Added optional PostgreSQL durable inbox/outbox state, leases, attempts, and explicit workers.
- Added deterministic testkit utilities and the `hookbound` CLI.
