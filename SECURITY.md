# Security policy

Do not report vulnerabilities in public issues. Until a dedicated security mailbox is published, use GitHub's private vulnerability reporting feature for the repository.

Supported releases receive security fixes on the latest minor line. Consumers should compile Hookbound with a currently supported Go toolchain because standard-library security fixes ship with Go releases.

Security-sensitive areas include signature parsing, replay protection, URL validation, DNS resolution, redirects, authentication headers, body limits, and durable deduplication.
