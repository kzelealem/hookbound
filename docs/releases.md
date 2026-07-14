# Release integrity

Hookbound's release workflow is designed to fail closed.

## Release creation

A release is created only from a semantic-version tag that is:

- annotated rather than lightweight;
- cryptographically signed;
- reported as verified by GitHub;
- pointed directly at the checked-out commit.

The workflow runs the race-enabled unit suite, PostgreSQL container suite, formatting checks, and `go vet` before building. It creates deterministic source and CLI archives for Linux, macOS, and Windows on AMD64 and ARM64.

Every third-party GitHub Action is pinned to a full commit SHA. `scripts/check-workflow-pins.sh` is run in CI to prevent a floating tag or branch from being introduced later. Dependabot remains responsible for proposing reviewed SHA updates.

## Published integrity material

Each release includes:

- platform archives and a source archive;
- `SHA256SUMS` covering every archive and the SBOM;
- an SPDX JSON software bill of materials;
- a Sigstore-signed GitHub build-provenance attestation;
- a Sigstore-signed SBOM attestation for the source archive.

The release tag signature and artifact attestations are separate controls. The tag authenticates the source commit selected for release. The attestations bind the produced artifacts and SBOM to the GitHub Actions identity that built them.

## Verify a release

Download the release assets into one directory and verify the checksum file:

```bash
sha256sum --check SHA256SUMS
```

Verify an individual archive's signed provenance with GitHub CLI:

```bash
gh attestation verify hookbound-0.2.0-linux-amd64.tar.gz \
  --repo hookbound/hookbound
```

Inspect the signed release tag:

```bash
git fetch --tags origin
git verify-tag v0.2.0
```

`git verify-tag` requires the maintainer signing key to be trusted by the local Git or GPG configuration. GitHub's release workflow independently rejects a tag that GitHub does not mark verified.

Repository administrators should also enable GitHub's immutable-release setting and protect release environments so authorized users cannot replace assets outside the workflow. Even without that setting, modified assets will fail the published checksum and attestation verification.
