// Package postgres provides an optional durable inbox/outbox runtime using
// PostgreSQL through Go's database/sql interfaces. Applications choose their
// own PostgreSQL driver; Hookbound does not force one into the dependency tree.
package postgres

import (
	"context"
	"database/sql"
	"embed"
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

// Migrate applies Hookbound's idempotent schema statements. Production teams
// may instead copy or consume Migrations through their normal migration tool.
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
	for _, name := range names {
		contents, err := fs.ReadFile(Migrations(), name)
		if err != nil {
			return fmt.Errorf("hookbound postgres: read migration %s: %w", name, err)
		}
		for index, statement := range splitStatements(string(contents)) {
			if _, err := db.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("hookbound postgres: apply %s statement %d: %w", name, index+1, err)
			}
		}
	}
	return nil
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
