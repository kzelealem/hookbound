# Contributing

Hookbound favors small, reviewable changes and a deliberately narrow public API.

1. Open an issue for new exported APIs or behavioral changes.
2. Add tests for security, interoperability, and failure behavior.
3. Run `make verify`.
4. Run `make test-postgres-integration` for PostgreSQL changes.
5. Keep the root module free of non-standard-library dependencies; test-only database drivers belong in the nested integration module.
6. Pin every third-party GitHub Action to a full commit SHA and run `make check-actions`.
7. Never weaken a secure default without an explicitly named opt-in.

Commit messages use Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).
