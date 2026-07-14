# Contributing

Hookbound favors small, reviewable changes and a deliberately narrow public API.

1. Open an issue for new exported APIs or behavioral changes.
2. Add tests for security, interoperability, and failure behavior.
3. Run `make verify`.
4. Keep the root module free of non-standard-library dependencies.
5. Never weaken a secure default without an explicitly named opt-in.

Commit messages use Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).
