package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/hookbound/hookbound"
)

var opaqueEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

type Store struct {
	db    *sql.DB
	clock hookbound.Clock
	ids   hookbound.IDGenerator
}

func NewStore(db *sql.DB, clock hookbound.Clock, ids hookbound.IDGenerator) (*Store, error) {
	if db == nil {
		return nil, hookbound.NewError(hookbound.CodeInvalidConfiguration, "PostgreSQL database is required", nil)
	}
	return &Store{db: db, clock: clock, ids: ids}, nil
}

func (s *Store) now() time.Time {
	if s.clock == nil {
		return time.Now().UTC()
	}
	return s.clock.Now().UTC()
}

func (s *Store) newMessageID() (string, error) {
	if s.ids != nil {
		return s.ids.NewMessageID()
	}
	return hookbound.RandomIDGenerator{}.NewMessageID()
}

func randomOpaqueID(prefix string) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", hookbound.NewError(hookbound.CodeInternal, "generate durable identifier", err)
	}
	return prefix + strings.ToLower(opaqueEncoding.EncodeToString(value[:])), nil
}

// Enqueue inserts a durable outbound delivery in its own transaction.
func (s *Store) Enqueue(ctx context.Context, request hookbound.SendRequest) (Publication, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Publication{}, hookbound.NewError(hookbound.CodePersistence, "begin enqueue transaction", err)
	}
	defer tx.Rollback()
	publication, err := s.EnqueueTx(ctx, tx, request)
	if err != nil {
		return Publication{}, err
	}
	if err := tx.Commit(); err != nil {
		return Publication{}, hookbound.NewError(hookbound.CodePersistence, "commit enqueue transaction", err)
	}
	return publication, nil
}

// EnqueueTx atomically stores an immutable message and its first delivery.
func (s *Store) EnqueueTx(ctx context.Context, tx *sql.Tx, request hookbound.SendRequest) (Publication, error) {
	if tx == nil {
		return Publication{}, hookbound.NewError(hookbound.CodeInvalidConfiguration, "transaction is required", nil)
	}
	if request.Auth != nil {
		return Publication{}, hookbound.NewError(hookbound.CodeInvalidConfiguration, "per-request authenticators cannot be persisted; configure authentication on Runtime", nil)
	}
	if err := request.Validate(); err != nil {
		return Publication{}, err
	}
	if request.ID == "" {
		id, err := s.newMessageID()
		if err != nil {
			return Publication{}, err
		}
		request.ID = id
	}
	contentType := request.ContentType
	if contentType == "" {
		contentType = "application/json"
	}
	headers, err := json.Marshal(request.Headers)
	if err != nil {
		return Publication{}, hookbound.NewError(hookbound.CodeInvalidMessage, "encode delivery headers", err)
	}
	createdAt := s.now()
	result, err := tx.ExecContext(ctx, `
		INSERT INTO hookbound_messages (id, event_type, body, content_type, created_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (id) DO NOTHING`, request.ID, request.EventType, request.Body, contentType, createdAt)
	if err != nil {
		return Publication{}, hookbound.NewError(hookbound.CodePersistence, "insert webhook message", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return Publication{}, hookbound.NewError(hookbound.CodePersistence, "inspect webhook message insert", err)
	}
	if rows == 0 {
		var eventType, existingContentType string
		var body []byte
		if err := tx.QueryRowContext(ctx, `SELECT event_type, body, content_type FROM hookbound_messages WHERE id = $1`, request.ID).
			Scan(&eventType, &body, &existingContentType); err != nil {
			return Publication{}, hookbound.NewError(hookbound.CodePersistence, "read existing webhook message", err)
		}
		if eventType != request.EventType || existingContentType != contentType || !bytes.Equal(body, request.Body) {
			return Publication{}, hookbound.NewError(hookbound.CodeConflict, "message ID already exists with different immutable content", nil)
		}
	}
	deliveryID, err := randomOpaqueID("dlv_")
	if err != nil {
		return Publication{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO hookbound_deliveries
			(id, message_id, destination_url, headers, state, next_attempt_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4::jsonb, 'pending', $5, $5, $5)`,
		deliveryID, request.ID, request.URL, headers, createdAt); err != nil {
		return Publication{}, hookbound.NewError(hookbound.CodePersistence, "insert webhook delivery", err)
	}
	return Publication{MessageID: request.ID, DeliveryID: deliveryID}, nil
}

// Handle implements hookbound.Handler as a durable inbound inbox. Duplicate
// (source, message ID) pairs are acknowledged without replacing original data.
func (s *Store) Handle(ctx context.Context, message hookbound.VerifiedMessage) error {
	if err := message.Validate(); err != nil {
		return err
	}
	headers, err := json.Marshal(message.Headers)
	if err != nil {
		return hookbound.NewError(hookbound.CodeInvalidMessage, "encode receipt headers", err)
	}
	metadata, err := json.Marshal(message.Metadata)
	if err != nil {
		return hookbound.NewError(hookbound.CodeInvalidMessage, "encode receipt metadata", err)
	}
	now := s.now()
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO hookbound_receipts
			(source, message_id, event_type, event_timestamp, body, content_type, headers, metadata,
			 state, next_attempt_at, received_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, 'pending', $9, $9, $9)
		ON CONFLICT (source, message_id) DO NOTHING`,
		message.Source, message.ID, message.Type, message.Timestamp, message.Body, message.ContentType,
		headers, metadata, now)
	if err != nil {
		return hookbound.NewError(hookbound.CodePersistence, "persist webhook receipt", err)
	}
	return nil
}

func (s *Store) ClaimDelivery(ctx context.Context, lease time.Duration) (*ClaimedDelivery, error) {
	if lease <= 0 {
		lease = time.Minute
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, hookbound.NewError(hookbound.CodePersistence, "begin delivery claim", err)
	}
	defer tx.Rollback()
	now := s.now()
	claimed := &ClaimedDelivery{}
	var headersJSON []byte
	err = tx.QueryRowContext(ctx, `
		SELECT d.id, d.attempt_count + 1, m.id, d.destination_url, m.event_type, m.body, m.content_type, d.headers
		FROM hookbound_deliveries d
		JOIN hookbound_messages m ON m.id = d.message_id
		WHERE
			(d.state IN ('pending','retry') AND d.next_attempt_at <= $1)
			OR (d.state = 'in_flight' AND d.lease_expires_at <= $1)
		ORDER BY d.next_attempt_at, d.created_at
		FOR UPDATE OF d SKIP LOCKED
		LIMIT 1`, now).Scan(
		&claimed.DeliveryID, &claimed.Attempt, &claimed.MessageID, &claimed.Destination,
		&claimed.EventType, &claimed.Body, &claimed.ContentType, &headersJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, hookbound.NewError(hookbound.CodePersistence, "claim due webhook delivery", err)
	}
	if err := json.Unmarshal(headersJSON, &claimed.Headers); err != nil {
		return nil, hookbound.NewError(hookbound.CodePersistence, "decode delivery headers", err)
	}
	claimed.AttemptID, err = randomOpaqueID("att_")
	if err != nil {
		return nil, err
	}
	claimed.StartedAt = now
	if _, err := tx.ExecContext(ctx, `
		UPDATE hookbound_deliveries
		SET state = 'in_flight', attempt_count = $2, lease_expires_at = $3, updated_at = $1
		WHERE id = $4`, now, claimed.Attempt, now.Add(lease), claimed.DeliveryID); err != nil {
		return nil, hookbound.NewError(hookbound.CodePersistence, "lease webhook delivery", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO hookbound_attempts (id, delivery_id, attempt_number, started_at)
		VALUES ($1, $2, $3, $4)`, claimed.AttemptID, claimed.DeliveryID, claimed.Attempt, now); err != nil {
		return nil, hookbound.NewError(hookbound.CodePersistence, "insert webhook attempt", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, hookbound.NewError(hookbound.CodePersistence, "commit delivery claim", err)
	}
	return claimed, nil
}

func (s *Store) CompleteDelivery(ctx context.Context, claimed *ClaimedDelivery, result hookbound.AttemptResult, sendErr error, retry hookbound.RetryPolicy) error {
	if claimed == nil {
		return hookbound.NewError(hookbound.CodeInvalidConfiguration, "claimed delivery is required", nil)
	}
	now := s.now()
	state, nextAttempt := deliveryTransition(now, claimed.Attempt, result, sendErr, retry)
	responseHeaders, err := json.Marshal(result.ResponseHeader)
	if err != nil {
		return hookbound.NewError(hookbound.CodeInternal, "encode response headers", err)
	}
	errorCode := result.ErrorCode
	if errorCode == "" && sendErr != nil {
		errorCode = hookbound.ErrorCode(sendErr)
	}
	errorDetail := truncateError(sendErr, 2048)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return hookbound.NewError(hookbound.CodePersistence, "begin delivery completion", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
		UPDATE hookbound_attempts
		SET finished_at = $1, outcome = $2, status_code = NULLIF($3, 0), duration_ns = $4,
			error_code = NULLIF($5, ''), error_detail = NULLIF($6, ''), response_headers = $7::jsonb,
			response_body = $8, next_attempt_at = $9
		WHERE id = $10`, now, result.Outcome.String(), result.StatusCode, result.Duration.Nanoseconds(),
		string(errorCode), errorDetail, responseHeaders, result.ResponseBody, nullTime(nextAttempt), claimed.AttemptID); err != nil {
		return hookbound.NewError(hookbound.CodePersistence, "complete webhook attempt", err)
	}
	completedAt := any(nil)
	if state == DeliveryDelivered || state == DeliveryPermanentFailure || state == DeliveryDisabled || state == DeliveryExhausted {
		completedAt = now
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE hookbound_deliveries
		SET state = $1, next_attempt_at = COALESCE($2, next_attempt_at), lease_expires_at = NULL,
			last_status_code = NULLIF($3, 0), last_error_code = NULLIF($4, ''), updated_at = $5,
			completed_at = $6
		WHERE id = $7 AND state = 'in_flight' AND attempt_count = $8`,
		state, nullTime(nextAttempt), result.StatusCode, string(errorCode), now, completedAt,
		claimed.DeliveryID, claimed.Attempt); err != nil {
		return hookbound.NewError(hookbound.CodePersistence, "complete webhook delivery", err)
	}
	if err := tx.Commit(); err != nil {
		return hookbound.NewError(hookbound.CodePersistence, "commit delivery completion", err)
	}
	return nil
}

func (s *Store) ClaimReceipt(ctx context.Context, lease time.Duration) (*ClaimedReceipt, error) {
	if lease <= 0 {
		lease = time.Minute
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, hookbound.NewError(hookbound.CodePersistence, "begin receipt claim", err)
	}
	defer tx.Rollback()
	now := s.now()
	claimed := &ClaimedReceipt{StartedAt: now}
	var headersJSON, metadataJSON []byte
	err = tx.QueryRowContext(ctx, `
		SELECT source, message_id, event_type, event_timestamp, body, content_type, headers, metadata,
		       attempt_count + 1
		FROM hookbound_receipts
		WHERE
			(state IN ('pending','retry') AND next_attempt_at <= $1)
			OR (state = 'processing' AND lease_expires_at <= $1)
		ORDER BY next_attempt_at, received_at
		FOR UPDATE SKIP LOCKED
		LIMIT 1`, now).Scan(
		&claimed.Message.Source, &claimed.Message.ID, &claimed.Message.Type, &claimed.Message.Timestamp,
		&claimed.Message.Body, &claimed.Message.ContentType, &headersJSON, &metadataJSON, &claimed.Attempt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, hookbound.NewError(hookbound.CodePersistence, "claim due webhook receipt", err)
	}
	if err := json.Unmarshal(headersJSON, &claimed.Message.Headers); err != nil {
		return nil, hookbound.NewError(hookbound.CodePersistence, "decode receipt headers", err)
	}
	if err := json.Unmarshal(metadataJSON, &claimed.Message.Metadata); err != nil {
		return nil, hookbound.NewError(hookbound.CodePersistence, "decode receipt metadata", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE hookbound_receipts
		SET state = 'processing', attempt_count = $1, lease_expires_at = $2, updated_at = $3
		WHERE source = $4 AND message_id = $5`,
		claimed.Attempt, now.Add(lease), now, claimed.Message.Source, claimed.Message.ID); err != nil {
		return nil, hookbound.NewError(hookbound.CodePersistence, "lease webhook receipt", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, hookbound.NewError(hookbound.CodePersistence, "commit receipt claim", err)
	}
	return claimed, nil
}

func (s *Store) CompleteReceipt(ctx context.Context, claimed *ClaimedReceipt, handlerErr error, retry hookbound.RetryPolicy) error {
	if claimed == nil {
		return hookbound.NewError(hookbound.CodeInvalidConfiguration, "claimed receipt is required", nil)
	}
	now := s.now()
	state := ReceiptProcessed
	var next time.Time
	if handlerErr != nil {
		if candidate, ok := retry.Next(now, claimed.Attempt); ok {
			state, next = ReceiptRetry, candidate
		} else {
			state = ReceiptExhausted
		}
	}
	processedAt := any(nil)
	if state == ReceiptProcessed || state == ReceiptFailed || state == ReceiptExhausted {
		processedAt = now
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE hookbound_receipts
		SET state = $1, next_attempt_at = COALESCE($2, next_attempt_at), lease_expires_at = NULL,
			last_error_code = NULLIF($3, ''), last_error_detail = NULLIF($4, ''),
			processed_at = $5, updated_at = $6
		WHERE source = $7 AND message_id = $8 AND state = 'processing' AND attempt_count = $9`,
		state, nullTime(next), string(hookbound.ErrorCode(handlerErr)), truncateError(handlerErr, 2048),
		processedAt, now, claimed.Message.Source, claimed.Message.ID, claimed.Attempt)
	if err != nil {
		return hookbound.NewError(hookbound.CodePersistence, "complete webhook receipt", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return hookbound.NewError(hookbound.CodePersistence, "inspect receipt completion", err)
	}
	if rows != 1 {
		return hookbound.NewError(hookbound.CodeConflict, "receipt lease was lost before completion", nil)
	}
	return nil
}

func deliveryTransition(now time.Time, attempt int, result hookbound.AttemptResult, sendErr error, retry hookbound.RetryPolicy) (DeliveryState, time.Time) {
	outcome := result.Outcome
	if outcome == 0 && sendErr != nil {
		switch hookbound.ErrorCode(sendErr) {
		case hookbound.CodeInvalidMessage, hookbound.CodeInvalidURL, hookbound.CodeUnsafeDestination, hookbound.CodeInvalidConfiguration:
			outcome = hookbound.OutcomePermanentFailure
		default:
			outcome = hookbound.OutcomeRetry
		}
	}
	switch outcome {
	case hookbound.OutcomeDelivered:
		return DeliveryDelivered, time.Time{}
	case hookbound.OutcomeDisableDestination:
		return DeliveryDisabled, time.Time{}
	case hookbound.OutcomePermanentFailure:
		return DeliveryPermanentFailure, time.Time{}
	default:
		if !result.RetryAt.IsZero() && result.RetryAt.After(now) {
			return DeliveryRetry, result.RetryAt
		}
		if next, ok := retry.Next(now, attempt); ok {
			return DeliveryRetry, next
		}
		return DeliveryExhausted, time.Time{}
	}
}

func nullTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}

func truncateError(err error, maximum int) string {
	if err == nil {
		return ""
	}
	value := err.Error()
	if len(value) <= maximum {
		return value
	}
	return value[:maximum]
}
