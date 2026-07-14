package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/kzelealem/hookbound"
)

const (
	defaultCleanupBatchSize = 1000
	maximumCleanupBatchSize = 10000
)

// Cleanup performs one bounded, concurrency-safe retention pass. It only
// removes terminal deliveries and receipts, then removes old messages that no
// longer have any delivery. Multiple cleaners may run concurrently because
// candidate rows are selected with SKIP LOCKED.
func (s *Store) Cleanup(ctx context.Context, policy RetentionPolicy) (CleanupResult, error) {
	var err error
	policy, err = normalizeRetentionPolicy(policy)
	if err != nil {
		return CleanupResult{}, err
	}
	if s == nil || s.db == nil {
		return CleanupResult{}, hookbound.NewError(hookbound.CodeInvalidConfiguration, "durable store is required", nil)
	}
	if policy.DeliveredRetention == 0 && policy.FailedDeliveryRetention == 0 &&
		policy.ReceiptRetention == 0 && policy.OrphanMessageRetention == 0 {
		return CleanupResult{}, nil
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return CleanupResult{}, hookbound.NewError(hookbound.CodePersistence, "begin webhook retention cleanup", err)
	}
	defer tx.Rollback()
	now, err := s.authoritativeNow(ctx, tx)
	if err != nil {
		return CleanupResult{}, err
	}
	var result CleanupResult
	if policy.DeliveredRetention > 0 {
		result.DeliveredDeliveries, err = cleanupRows(ctx, tx, s.qualifyQuery(`
			WITH candidates AS (
				SELECT id FROM hookbound_deliveries
				WHERE state = 'delivered' AND completed_at < $1
				ORDER BY completed_at, id
				FOR UPDATE SKIP LOCKED
				LIMIT $2
			)
			DELETE FROM hookbound_deliveries d
			USING candidates c WHERE d.id = c.id`), now.Add(-policy.DeliveredRetention), policy.BatchSize)
		if err != nil {
			return CleanupResult{}, hookbound.NewError(hookbound.CodePersistence, "remove retained delivered webhooks", err)
		}
	}
	if policy.FailedDeliveryRetention > 0 {
		result.FailedDeliveries, err = cleanupRows(ctx, tx, s.qualifyQuery(`
			WITH candidates AS (
				SELECT id FROM hookbound_deliveries
				WHERE state IN ('permanent_failure','disabled','exhausted') AND completed_at < $1
				ORDER BY completed_at, id
				FOR UPDATE SKIP LOCKED
				LIMIT $2
			)
			DELETE FROM hookbound_deliveries d
			USING candidates c WHERE d.id = c.id`), now.Add(-policy.FailedDeliveryRetention), policy.BatchSize)
		if err != nil {
			return CleanupResult{}, hookbound.NewError(hookbound.CodePersistence, "remove retained failed webhooks", err)
		}
	}
	if policy.ReceiptRetention > 0 {
		result.Receipts, err = cleanupRows(ctx, tx, s.qualifyQuery(`
			WITH candidates AS (
				SELECT source, message_id FROM hookbound_receipts
				WHERE state IN ('processed','failed','exhausted') AND processed_at < $1
				ORDER BY processed_at, source, message_id
				FOR UPDATE SKIP LOCKED
				LIMIT $2
			)
			DELETE FROM hookbound_receipts r
			USING candidates c
			WHERE r.source = c.source AND r.message_id = c.message_id`), now.Add(-policy.ReceiptRetention), policy.BatchSize)
		if err != nil {
			return CleanupResult{}, hookbound.NewError(hookbound.CodePersistence, "remove retained webhook receipts", err)
		}
	}
	if policy.OrphanMessageRetention > 0 {
		result.OrphanMessages, err = cleanupRows(ctx, tx, s.qualifyQuery(`
			WITH candidates AS (
				SELECT m.id FROM hookbound_messages m
				WHERE m.created_at < $1
				  AND NOT EXISTS (
				      SELECT 1 FROM hookbound_deliveries d WHERE d.message_id = m.id
				  )
				ORDER BY m.created_at, m.id
				FOR UPDATE OF m SKIP LOCKED
				LIMIT $2
			)
			DELETE FROM hookbound_messages m
			USING candidates c WHERE m.id = c.id`), now.Add(-policy.OrphanMessageRetention), policy.BatchSize)
		if err != nil {
			return CleanupResult{}, hookbound.NewError(hookbound.CodePersistence, "remove retained orphan webhook messages", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return CleanupResult{}, hookbound.NewError(hookbound.CodePersistence, "commit webhook retention cleanup", err)
	}
	return result, nil
}

func cleanupRows(ctx context.Context, tx *sql.Tx, query string, cutoff time.Time, batchSize int) (int64, error) {
	result, err := tx.ExecContext(ctx, query, cutoff, batchSize)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func normalizeRetentionPolicy(policy RetentionPolicy) (RetentionPolicy, error) {
	if policy.DeliveredRetention < 0 || policy.FailedDeliveryRetention < 0 ||
		policy.ReceiptRetention < 0 || policy.OrphanMessageRetention < 0 {
		return RetentionPolicy{}, hookbound.NewError(hookbound.CodeInvalidConfiguration, "retention durations cannot be negative", nil)
	}
	if policy.BatchSize < 0 || policy.BatchSize > maximumCleanupBatchSize {
		return RetentionPolicy{}, hookbound.NewError(hookbound.CodeInvalidConfiguration, "cleanup batch size must be zero or between 1 and 10000", nil)
	}
	if policy.BatchSize == 0 {
		policy.BatchSize = defaultCleanupBatchSize
	}
	return policy, nil
}
