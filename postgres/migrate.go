// Package postgres provides an optional durable inbox/outbox runtime using
// PostgreSQL through Go's database/sql interfaces. Applications choose their
// own PostgreSQL driver; Hookbound does not force one into the dependency tree.
package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Migrations returns the embedded SQL migration files for integration with an
// application's migration tool.
func Migrations() fs.FS {
	sub, err := fs.Sub(migrations, "migrations")
	if err != nil {
		panic(err)
	}
	return sub
}

// Migrate applies Hookbound's embedded migrations transactionally. It records
// a checksum for each migration and serializes concurrent migrators with a
// PostgreSQL advisory transaction lock. Production teams may instead consume
// Migrations through their existing migration tool.
func Migrate(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("hookbound postgres: database is required")
	}
	entries, err := fs.ReadDir(Migrations(), ".")
	if err != nil {
		return fmt.Errorf("hookbound postgres: list migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("hookbound postgres: begin migrations: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('hookbound:migrations', 0))`); err != nil {
		return fmt.Errorf("hookbound postgres: lock migrations: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS hookbound_schema_migrations (
			name text PRIMARY KEY,
			checksum text NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
		)`); err != nil {
		return fmt.Errorf("hookbound postgres: create migration ledger: %w", err)
	}

	for _, name := range names {
		contents, err := fs.ReadFile(Migrations(), name)
		if err != nil {
			return fmt.Errorf("hookbound postgres: read migration %s: %w", name, err)
		}
		checksum := migrationChecksum(contents)
		var existing string
		err = tx.QueryRowContext(ctx, `SELECT checksum FROM hookbound_schema_migrations WHERE name = $1`, name).Scan(&existing)
		switch {
		case err == nil:
			if existing != checksum {
				return fmt.Errorf("hookbound postgres: migration %s checksum changed after application", name)
			}
			continue
		case !errors.Is(err, sql.ErrNoRows):
			return fmt.Errorf("hookbound postgres: inspect migration %s: %w", name, err)
		}

		for index, statement := range splitStatements(string(contents)) {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("hookbound postgres: apply %s statement %d: %w", name, index+1, err)
			}
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO hookbound_schema_migrations (name, checksum) VALUES ($1, $2)`, name, checksum); err != nil {
			return fmt.Errorf("hookbound postgres: record migration %s: %w", name, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("hookbound postgres: commit migrations: %w", err)
	}
	return nil
}

func migrationChecksum(contents []byte) string {
	sum := sha256.Sum256(contents)
	return hex.EncodeToString(sum[:])
}

func splitStatements(contents string) []string {
	parts := strings.Split(contents, "-- hookbound:statement")
	statements := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			statements = append(statements, trimmed)
		}
	}
	return statements
}
