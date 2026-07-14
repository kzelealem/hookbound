# Security policy

## Supported versions

Hookbound is pre-1.0. Security fixes are released on the latest minor line only. Use the newest Hookbound release and a Go toolchain currently supported by the Go project.

| Version | Supported |
| --- | --- |
| Latest `v0.x` | Yes |
| Older releases | No |

## Reporting a vulnerability

Do not report vulnerabilities in public issues. Use GitHub's private vulnerability reporting feature for the repository. Include the affected version, impact, and a minimal reproduction without real credentials or customer payloads.

Consumers should compile Hookbound with a currently supported Go toolchain because standard-library security fixes ship with Go releases.

Security-sensitive areas include signature parsing, replay protection, URL validation, DNS resolution, redirects, authentication headers, body limits, and durable deduplication.


## Release supply chain

Official releases are created only from annotated, cryptographically verified tags. The release workflow publishes SHA-256 checksums, an SPDX SBOM, signed build provenance, and a signed SBOM attestation. See [docs/releases.md](docs/releases.md) for verification commands.

All third-party workflow actions are pinned to immutable commit SHAs. Release archives should be considered unverified until both their checksum and GitHub artifact attestation have been checked.
