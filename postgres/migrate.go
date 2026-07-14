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

// MigrationConfig configures the embedded migration runner.
type MigrationConfig struct {
	// Schema is created when it does not exist and is made the explicit local
	// search path while migrations run. The default is public for compatibility.
	Schema string
}

// Migrations returns the embedded SQL migration files for integration with an
// application's migration tool.
func Migrations() fs.FS {
	sub, err := fs.Sub(migrations, "migrations")
	if err != nil {
		panic(err)
	}
	return sub
}

// Migrate applies Hookbound's embedded migrations to the public schema.
func Migrate(ctx context.Context, db *sql.DB) error {
	return MigrateWithConfig(ctx, db, MigrationConfig{})
}

// MigrateWithConfig applies Hookbound's embedded migrations transactionally.
// It creates and selects the configured schema, records migration checksums,
// and serializes concurrent migrators with a schema-specific advisory lock.
func MigrateWithConfig(ctx context.Context, db *sql.DB, config MigrationConfig) error {
	if db == nil {
		return fmt.Errorf("hookbound postgres: database is required")
	}
	schema, err := normalizeSchema(config.Schema)
	if err != nil {
		return fmt.Errorf("hookbound postgres: schema: %w", err)
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
	if _, err := tx.ExecContext(ctx, `SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1, 0))`, "hookbound:migrations:"+schema); err != nil {
		return fmt.Errorf("hookbound postgres: lock migrations: %w", err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`CREATE SCHEMA IF NOT EXISTS %s`, quoteIdentifier(schema))); err != nil {
		return fmt.Errorf("hookbound postgres: create schema %q: %w", schema, err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_catalog.set_config('search_path', $1, true)`, schemaSearchPath(schema)); err != nil {
		return fmt.Errorf("hookbound postgres: set migration search path: %w", err)
	}
	relations := relationsForSchema(schema)
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			name text PRIMARY KEY,
			checksum text NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
		)`, relations.migrations)); err != nil {
		return fmt.Errorf("hookbound postgres: create migration ledger: %w", err)
	}

	for _, name := range names {
		contents, err := fs.ReadFile(Migrations(), name)
		if err != nil {
			return fmt.Errorf("hookbound postgres: read migration %s: %w", name, err)
		}
		checksum := migrationChecksum(contents)
		var existing string
		err = tx.QueryRowContext(ctx, fmt.Sprintf(`SELECT checksum FROM %s WHERE name = $1`, relations.migrations), name).Scan(&existing)
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
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`
			INSERT INTO %s (name, checksum) VALUES ($1, $2)`, relations.migrations), name, checksum); err != nil {
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
