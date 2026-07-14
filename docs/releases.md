# Release integrity

Hookbound's release workflow is designed to fail closed.

## Module identity and registries

The canonical module path is `github.com/kzelealem/hookbound`, matching the public GitHub repository. A personal GitHub username is a normal and valid Go module namespace. Do not change this path unless the repository is permanently moved and a new compatibility plan is published.

Go does not use a manual package upload. Publishing a semantic-version Git tag makes the module available to Go tooling. The release workflow also asks `proxy.golang.org` to index the exact tag; pkg.go.dev discovers it from the public module ecosystem afterward.

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
  --repo kzelealem/hookbound
```

Inspect the signed release tag:

```bash
git fetch --tags origin
git verify-tag v0.2.0
```

`git verify-tag` requires the maintainer signing key to be trusted by the local Git or GPG configuration. GitHub's release workflow independently rejects a tag that GitHub does not mark verified.

Repository administrators should also enable GitHub's immutable-release setting and protect release environments so authorized users cannot replace assets outside the workflow. Even without that setting, modified assets will fail the published checksum and attestation verification.

## Maintainer release checklist

1. Confirm `CHANGELOG.md` describes the release and the tree is clean.
2. Run `make verify-all`, including the disposable PostgreSQL suite.
3. Commit the release changes and push `main`; require CI to pass.
4. Create an annotated, cryptographically signed tag, for example `git tag -s v0.2.0 -m "Hookbound v0.2.0"`.
5. Push only that tag: `git push origin v0.2.0`.
6. Wait for the Release workflow to publish the GitHub release and warm the Go proxy.
7. Verify `GOPROXY=https://proxy.golang.org go list -m github.com/kzelealem/hookbound@v0.2.0` and the [pkg.go.dev module page](https://pkg.go.dev/github.com/kzelealem/hookbound).

Never move or recreate a published tag. Publish a new semantic version for every change.
