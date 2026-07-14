package postgres

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/kzelealem/hookbound"
)

const defaultSchema = "public"

type relationNames struct {
	messages   string
	deliveries string
	attempts   string
	receipts   string
	migrations string
}

func normalizeSchema(schema string) (string, error) {
	if schema == "" {
		schema = defaultSchema
	}
	if !utf8.ValidString(schema) || len(schema) > 63 {
		return "", hookbound.NewError(hookbound.CodeInvalidConfiguration, "PostgreSQL schema must be valid UTF-8 and at most 63 bytes", nil)
	}
	for index, r := range schema {
		if r == 0 || r < 0x20 || r == 0x7f {
			return "", hookbound.NewError(hookbound.CodeInvalidConfiguration, "PostgreSQL schema contains control characters", nil)
		}
		if index == 0 && r >= '0' && r <= '9' {
			// PostgreSQL permits quoted identifiers beginning with a digit, but
			// rejecting them keeps configuration portable and unsurprising.
			return "", hookbound.NewError(hookbound.CodeInvalidConfiguration, "PostgreSQL schema cannot begin with a digit", nil)
		}
	}
	if strings.TrimSpace(schema) != schema || schema == "" {
		return "", hookbound.NewError(hookbound.CodeInvalidConfiguration, "PostgreSQL schema cannot be empty or surrounded by whitespace", nil)
	}
	lower := strings.ToLower(schema)
	if strings.HasPrefix(lower, "pg_") || lower == "information_schema" {
		return "", hookbound.NewError(hookbound.CodeInvalidConfiguration, "PostgreSQL system schemas cannot be used by Hookbound", nil)
	}
	return schema, nil
}

func quoteIdentifier(identifier string) string {
	return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"`
}

func qualifiedRelation(schema, table string) string {
	return quoteIdentifier(schema) + "." + quoteIdentifier(table)
}

func relationsForSchema(schema string) relationNames {
	return relationNames{
		messages:   qualifiedRelation(schema, "hookbound_messages"),
		deliveries: qualifiedRelation(schema, "hookbound_deliveries"),
		attempts:   qualifiedRelation(schema, "hookbound_attempts"),
		receipts:   qualifiedRelation(schema, "hookbound_receipts"),
		migrations: qualifiedRelation(schema, "hookbound_schema_migrations"),
	}
}

func schemaSearchPath(schema string) string {
	return fmt.Sprintf("%s, pg_catalog", quoteIdentifier(schema))
}

func (s *Store) qualifyQuery(query string) string {
	return strings.NewReplacer(
		"hookbound_schema_migrations", s.relations.migrations,
		"hookbound_messages", s.relations.messages,
		"hookbound_deliveries", s.relations.deliveries,
		"hookbound_attempts", s.relations.attempts,
		"hookbound_receipts", s.relations.receipts,
	).Replace(query)
}
