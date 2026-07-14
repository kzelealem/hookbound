# Security policy

Do not report vulnerabilities in public issues. Until a dedicated security mailbox is published, use GitHub's private vulnerability reporting feature for the repository.

Supported releases receive security fixes on the latest minor line. Consumers should compile Hookbound with a currently supported Go toolchain because standard-library security fixes ship with Go releases.

Security-sensitive areas include signature parsing, replay protection, URL validation, DNS resolution, redirects, authentication headers, body limits, and durable deduplication.


## Release supply chain

Official releases are created only from annotated, cryptographically verified tags. The release workflow publishes SHA-256 checksums, an SPDX SBOM, signed build provenance, and a signed SBOM attestation. See [docs/releases.md](docs/releases.md) for verification commands.

All third-party workflow actions are pinned to immutable commit SHAs. Release archives should be considered unverified until both their checksum and GitHub artifact attestation have been checked.
