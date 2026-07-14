package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hookbound/hookbound"
)

var opaqueEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

type StoreConfig struct {
	// Schema selects the PostgreSQL schema used by Hookbound. The default is
	// public for compatibility, but production deployments should normally use
	// a dedicated schema such as "hookbound".
	Schema               string
	Clock                hookbound.Clock
	IDGenerator          hookbound.IDGenerator
	MaxResponseBodyBytes int
	SensitiveHeaders     []string
	PersistErrorDetails  bool
}

type Store struct {
	db                   *sql.DB
	schema               string
	relations            relationNames
	clock                hookbound.Clock
	ids                  hookbound.IDGenerator
	maxResponseBodyBytes int
	sensitiveHeaderNames []string
	persistErrorDetails  bool
}

// NewStore creates a store with safe audit defaults: response bodies are not
// persisted and common credential headers are removed.
func NewStore(db *sql.DB, clock hookbound.Clock, ids hookbound.IDGenerator) (*Store, error) {
	return NewStoreWithConfig(db, StoreConfig{Clock: clock, IDGenerator: ids})
}

func NewStoreWithConfig(db *sql.DB, config StoreConfig) (*Store, error) {
	if db == nil {
		return nil, hookbound.NewError(hookbound.CodeInvalidConfiguration, "PostgreSQL database is required", nil)
	}
	if config.MaxResponseBodyBytes < 0 {
		return nil, hookbound.NewError(hookbound.CodeInvalidConfiguration, "maximum persisted response body cannot be negative", nil)
	}
	schema, err := normalizeSchema(config.Schema)
	if err != nil {
		return nil, err
	}
	sensitive := append([]string(nil), defaultSensitiveHeaders...)
	sensitive = append(sensitive, config.SensitiveHeaders...)
	return &Store{
		db: db, schema: schema, relations: relationsForSchema(schema),
		clock: config.Clock, ids: config.IDGenerator,
		maxResponseBodyBytes: config.MaxResponseBodyBytes,
		sensitiveHeaderNames: sensitive,
		persistErrorDetails:  config.PersistErrorDetails,
	}, nil
}

func (s *Store) now() time.Time {
	if s.clock == nil {
		return time.Now().UTC()
	}
	return s.clock.Now().UTC()
}

type rowQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Store) authoritativeNow(ctx context.Context, queryer rowQuerier) (time.Time, error) {
	if s.clock != nil {
		return s.now(), nil
	}
	var now time.Time
	if err := queryer.QueryRowContext(ctx, s.qualifyQuery(`SELECT clock_timestamp()`)).Scan(&now); err != nil {
		return time.Time{}, hookbound.NewError(hookbound.CodePersistence, "read PostgreSQL clock", err)
	}
	return now.UTC(), nil
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
	return s.EnqueueWithOptions(ctx, request, EnqueueOptions{})
}

// EnqueueWithOptions inserts a durable outbound delivery in its own
// transaction and optionally deduplicates publication with an idempotency key.
func (s *Store) EnqueueWithOptions(ctx context.Context, request hookbound.SendRequest, options EnqueueOptions) (Publication, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Publication{}, hookbound.NewError(hookbound.CodePersistence, "begin enqueue transaction", err)
	}
	defer tx.Rollback()
	publication, err := s.EnqueueTxWithOptions(ctx, tx, request, options)
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
	return s.EnqueueTxWithOptions(ctx, tx, request, EnqueueOptions{})
}

// EnqueueTxWithOptions atomically stores an immutable message and its first
// delivery. An idempotency key is scoped to the Store's PostgreSQL schema.
func (s *Store) EnqueueTxWithOptions(ctx context.Context, tx *sql.Tx, request hookbound.SendRequest, options EnqueueOptions) (Publication, error) {
	if tx == nil {
		return Publication{}, hookbound.NewError(hookbound.CodeInvalidConfiguration, "transaction is required", nil)
	}
	if request.Auth != nil {
		return Publication{}, hookbound.NewError(hookbound.CodeInvalidConfiguration, "per-request authenticators cannot be persisted; configure authentication on Runtime", nil)
	}
	if err := request.Validate(); err != nil {
		return Publication{}, err
	}
	if containsSensitiveHeaders(request.Headers, s.sensitiveHeaderNames) {
		return Publication{}, hookbound.NewError(hookbound.CodeInvalidConfiguration, "durable deliveries cannot persist authorization or cookie headers; configure a runtime authenticator", nil)
	}
	keyHash, err := publicationKeyHash(options.IdempotencyKey)
	if err != nil {
		return Publication{}, err
	}
	explicitMessageID := request.ID != ""
	request.Headers = canonicalHeaders(request.Headers)
	contentType := request.ContentType
	if contentType == "" {
		contentType = "application/json"
	}
	headers, err := json.Marshal(request.Headers)
	if err != nil {
		return Publication{}, hookbound.NewError(hookbound.CodeInvalidMessage, "encode delivery headers", err)
	}
	if len(keyHash) > 0 {
		publication, found, err := s.findIdempotentPublication(ctx, tx, keyHash, request, contentType, explicitMessageID)
		if err != nil || found {
			return publication, err
		}
	}
	if request.ID == "" {
		id, err := s.newMessageID()
		if err != nil {
			return Publication{}, err
		}
		request.ID = id
	}
	createdAt, err := s.authoritativeNow(ctx, tx)
	if err != nil {
		return Publication{}, err
	}
	result, err := tx.ExecContext(ctx, s.qualifyQuery(`
		INSERT INTO hookbound_messages (id, event_type, body, content_type, created_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (id) DO NOTHING`), request.ID, request.EventType, request.Body, contentType, createdAt)
	if err != nil {
		return Publication{}, hookbound.NewError(hookbound.CodePersistence, "insert webhook message", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return Publication{}, hookbound.NewError(hookbound.CodePersistence, "inspect webhook message insert", err)
	}
	messageInserted := rows == 1
	if rows == 0 {
		var eventType, existingContentType string
		var body []byte
		if err := tx.QueryRowContext(ctx, s.qualifyQuery(`SELECT event_type, body, content_type FROM hookbound_messages WHERE id = $1`), request.ID).
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
	result, err = tx.ExecContext(ctx, s.qualifyQuery(`
		INSERT INTO hookbound_deliveries
			(id, message_id, destination_url, headers, idempotency_key_hash, state, next_attempt_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4::jsonb, $5, 'pending', $6, $6, $6)
		ON CONFLICT (idempotency_key_hash) WHERE idempotency_key_hash IS NOT NULL DO NOTHING`),
		deliveryID, request.ID, request.URL, headers, nullableBytes(keyHash), createdAt)
	if err != nil {
		return Publication{}, hookbound.NewError(hookbound.CodePersistence, "insert webhook delivery", err)
	}
	rows, err = result.RowsAffected()
	if err != nil {
		return Publication{}, hookbound.NewError(hookbound.CodePersistence, "inspect webhook delivery insert", err)
	}
	if rows == 1 {
		return Publication{MessageID: request.ID, DeliveryID: deliveryID}, nil
	}
	if len(keyHash) == 0 {
		return Publication{}, hookbound.NewError(hookbound.CodePersistence, "webhook delivery insert affected no rows", nil)
	}
	publication, found, err := s.findIdempotentPublication(ctx, tx, keyHash, request, contentType, explicitMessageID)
	if err != nil {
		return Publication{}, err
	}
	if !found {
		return Publication{}, hookbound.NewError(hookbound.CodePersistence, "idempotent webhook publication disappeared during enqueue", nil)
	}
	if messageInserted {
		if _, err := tx.ExecContext(ctx, s.qualifyQuery(`
			DELETE FROM hookbound_messages m
			WHERE m.id = $1
			  AND NOT EXISTS (SELECT 1 FROM hookbound_deliveries d WHERE d.message_id = m.id)`), request.ID); err != nil {
			return Publication{}, hookbound.NewError(hookbound.CodePersistence, "remove unreferenced message after idempotent enqueue race", err)
		}
	}
	return publication, nil
}

func (s *Store) findIdempotentPublication(
	ctx context.Context,
	tx *sql.Tx,
	keyHash []byte,
	request hookbound.SendRequest,
	contentType string,
	explicitMessageID bool,
) (Publication, bool, error) {
	var publication Publication
	var eventType, existingContentType, destination string
	var body, headersJSON []byte
	err := tx.QueryRowContext(ctx, s.qualifyQuery(`
		SELECT m.id, d.id, m.event_type, m.body, m.content_type, d.destination_url, d.headers
		FROM hookbound_deliveries d
		JOIN hookbound_messages m ON m.id = d.message_id
		WHERE d.idempotency_key_hash = $1`), keyHash).Scan(
		&publication.MessageID, &publication.DeliveryID, &eventType, &body, &existingContentType, &destination, &headersJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return Publication{}, false, nil
	}
	if err != nil {
		return Publication{}, false, hookbound.NewError(hookbound.CodePersistence, "read idempotent webhook publication", err)
	}
	var headers http.Header
	if err := json.Unmarshal(headersJSON, &headers); err != nil {
		return Publication{}, false, hookbound.NewError(hookbound.CodePersistence, "decode idempotent webhook publication headers", err)
	}
	matches := eventType == request.EventType && bytes.Equal(body, request.Body) &&
		existingContentType == contentType && destination == request.URL &&
		reflect.DeepEqual(canonicalHeaders(headers), canonicalHeaders(request.Headers))
	if explicitMessageID {
		matches = matches && publication.MessageID == request.ID
	}
	if !matches {
		return Publication{}, false, hookbound.NewError(hookbound.CodeConflict, "idempotency key already exists with different immutable publication content", nil)
	}
	return publication, true, nil
}

func publicationKeyHash(key string) ([]byte, error) {
	if key == "" {
		return nil, nil
	}
	if !utf8.ValidString(key) || len(key) > 512 || strings.TrimSpace(key) != key {
		return nil, hookbound.NewError(hookbound.CodeInvalidConfiguration, "idempotency key must be valid UTF-8, at most 512 bytes, and have no surrounding whitespace", nil)
	}
	for _, character := range key {
		if character == 0 || character < 0x20 || character == 0x7f {
			return nil, hookbound.NewError(hookbound.CodeInvalidConfiguration, "idempotency key contains control characters", nil)
		}
	}
	sum := sha256.Sum256(append([]byte("hookbound:publication:v1:\x00"), key...))
	return sum[:], nil
}

func canonicalHeaders(headers http.Header) http.Header {
	if len(headers) == 0 {
		return http.Header{}
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	slices.Sort(names)
	canonical := make(http.Header, len(headers))
	for _, name := range names {
		canonicalName := http.CanonicalHeaderKey(name)
		canonical[canonicalName] = append(canonical[canonicalName], headers[name]...)
	}
	return canonical
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

// Handle implements hookbound.Handler as a durable inbound inbox. Duplicate
// (source, message ID) pairs are acknowledged without replacing original data.
func (s *Store) Handle(ctx context.Context, message hookbound.VerifiedMessage) error {
	if err := message.Validate(); err != nil {
		return err
	}
	headers, err := json.Marshal(redactedHeaders(message.Headers, s.sensitiveHeaderNames))
	if err != nil {
		return hookbound.NewError(hookbound.CodeInvalidMessage, "encode receipt headers", err)
	}
	metadata, err := json.Marshal(message.Metadata)
	if err != nil {
		return hookbound.NewError(hookbound.CodeInvalidMessage, "encode receipt metadata", err)
	}
	now, err := s.authoritativeNow(ctx, s.db)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, s.qualifyQuery(`
		INSERT INTO hookbound_receipts
			(source, message_id, event_type, event_timestamp, body, content_type, headers, metadata,
			 state, next_attempt_at, received_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, 'pending', $9, $9, $9)
		ON CONFLICT (source, message_id) DO NOTHING`),
		message.Source, message.ID, message.Type, message.Timestamp, message.Body, message.ContentType,
		headers, metadata, now)
	if err != nil {
		return hookbound.NewError(hookbound.CodePersistence, "persist webhook receipt", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return hookbound.NewError(hookbound.CodePersistence, "inspect webhook receipt insert", err)
	}
	if rows == 0 {
		var eventType, contentType string
		var body []byte
		if err := s.db.QueryRowContext(ctx, s.qualifyQuery(`
			SELECT event_type, body, content_type FROM hookbound_receipts
			WHERE source = $1 AND message_id = $2`), message.Source, message.ID).
			Scan(&eventType, &body, &contentType); err != nil {
			return hookbound.NewError(hookbound.CodePersistence, "read existing webhook receipt", err)
		}
		if eventType != message.Type || contentType != message.ContentType || !bytes.Equal(body, message.Body) {
			return hookbound.NewError(hookbound.CodeConflict, "receipt ID already exists with different immutable content", nil)
		}
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
	now, err := s.authoritativeNow(ctx, tx)
	if err != nil {
		return nil, err
	}
	claimed := &ClaimedDelivery{}
	var headersJSON []byte
	var previousState DeliveryState
	var previousAttempt int
	err = tx.QueryRowContext(ctx, s.qualifyQuery(`
		SELECT d.id, d.state, d.attempt_count, d.attempt_count + 1, m.id, d.destination_url, m.event_type, m.body, m.content_type, d.headers
		FROM hookbound_deliveries d
		JOIN hookbound_messages m ON m.id = d.message_id
		WHERE
			(d.state IN ('pending','retry') AND d.next_attempt_at <= $1)
			OR (d.state = 'in_flight' AND d.lease_expires_at <= $1)
		ORDER BY d.next_attempt_at, d.created_at
		FOR UPDATE OF d SKIP LOCKED
		LIMIT 1`), now).Scan(
		&claimed.DeliveryID, &previousState, &previousAttempt, &claimed.Attempt, &claimed.MessageID, &claimed.Destination,
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
	if previousState == DeliveryInFlight && previousAttempt > 0 {
		if _, err := tx.ExecContext(ctx, s.qualifyQuery(`
			UPDATE hookbound_attempts
			SET finished_at = $1, outcome = 'retry', error_code = 'lease_expired',
				error_detail = 'worker lease expired before completion'
			WHERE delivery_id = $2 AND attempt_number = $3 AND finished_at IS NULL`),
			now, claimed.DeliveryID, previousAttempt); err != nil {
			return nil, hookbound.NewError(hookbound.CodePersistence, "expire abandoned webhook attempt", err)
		}
	}
	claimed.AttemptID, err = randomOpaqueID("att_")
	if err != nil {
		return nil, err
	}
	claimed.StartedAt = now
	if _, err := tx.ExecContext(ctx, s.qualifyQuery(`
		UPDATE hookbound_deliveries
		SET state = 'in_flight', attempt_count = $2, lease_expires_at = $3, updated_at = $1
		WHERE id = $4`), now, claimed.Attempt, now.Add(lease), claimed.DeliveryID); err != nil {
		return nil, hookbound.NewError(hookbound.CodePersistence, "lease webhook delivery", err)
	}
	if _, err := tx.ExecContext(ctx, s.qualifyQuery(`
		INSERT INTO hookbound_attempts (id, delivery_id, attempt_number, started_at)
		VALUES ($1, $2, $3, $4)`), claimed.AttemptID, claimed.DeliveryID, claimed.Attempt, now); err != nil {
		return nil, hookbound.NewError(hookbound.CodePersistence, "insert webhook attempt", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, hookbound.NewError(hookbound.CodePersistence, "commit delivery claim", err)
	}
	return claimed, nil
}

// RenewDeliveryLease extends an active delivery lease using PostgreSQL's
// authoritative clock. It refuses to resurrect an already-expired lease or a
// claim that no longer owns the current attempt.
func (s *Store) RenewDeliveryLease(ctx context.Context, claimed *ClaimedDelivery, lease time.Duration) error {
	if claimed == nil {
		return hookbound.NewError(hookbound.CodeInvalidConfiguration, "claimed delivery is required", nil)
	}
	if lease <= 0 {
		return hookbound.NewError(hookbound.CodeInvalidConfiguration, "delivery lease duration must be positive", nil)
	}
	var result sql.Result
	var err error
	if s.clock == nil {
		result, err = s.db.ExecContext(ctx, s.qualifyQuery(`
			WITH current_time AS MATERIALIZED (SELECT pg_catalog.clock_timestamp() AS now)
			UPDATE hookbound_deliveries d
			SET lease_expires_at = current_time.now + ($1::bigint * interval '1 microsecond'),
				updated_at = current_time.now
			FROM current_time
			WHERE d.id = $2
			  AND d.state = 'in_flight'
			  AND d.attempt_count = $3
			  AND d.lease_expires_at > current_time.now
			  AND EXISTS (
			      SELECT 1 FROM hookbound_attempts a
			      WHERE a.id = $4 AND a.delivery_id = d.id
			        AND a.attempt_number = d.attempt_count AND a.finished_at IS NULL
			  )`), durationMicrosecondsCeil(lease), claimed.DeliveryID, claimed.Attempt, claimed.AttemptID)
	} else {
		now := s.now()
		result, err = s.db.ExecContext(ctx, s.qualifyQuery(`
			UPDATE hookbound_deliveries d
			SET lease_expires_at = $1, updated_at = $2
			WHERE d.id = $3
			  AND d.state = 'in_flight'
			  AND d.attempt_count = $4
			  AND d.lease_expires_at > $2
			  AND EXISTS (
			      SELECT 1 FROM hookbound_attempts a
			      WHERE a.id = $5 AND a.delivery_id = d.id
			        AND a.attempt_number = d.attempt_count AND a.finished_at IS NULL
			  )`), now.Add(lease), now, claimed.DeliveryID, claimed.Attempt, claimed.AttemptID)
	}
	if err != nil {
		return hookbound.NewError(hookbound.CodePersistence, "renew webhook delivery lease", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return hookbound.NewError(hookbound.CodePersistence, "inspect webhook delivery lease renewal", err)
	}
	if rows != 1 {
		return hookbound.NewError(hookbound.CodeConflict, "delivery lease expired or was lost before renewal", nil)
	}
	return nil
}

func (s *Store) CompleteDelivery(ctx context.Context, claimed *ClaimedDelivery, result hookbound.AttemptResult, sendErr error, retry hookbound.RetryPolicy) error {
	if claimed == nil {
		return hookbound.NewError(hookbound.CodeInvalidConfiguration, "claimed delivery is required", nil)
	}
	result.Outcome = normalizedOutcome(result.Outcome, sendErr)
	responseHeaders, err := json.Marshal(redactedHeaders(result.ResponseHeader, s.sensitiveHeaderNames))
	if err != nil {
		return hookbound.NewError(hookbound.CodeInternal, "encode response headers", err)
	}
	errorCode := result.ErrorCode
	if errorCode == "" && sendErr != nil {
		errorCode = hookbound.ErrorCode(sendErr)
	}
	errorDetail := s.errorDetail(sendErr)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return hookbound.NewError(hookbound.CodePersistence, "begin delivery completion", err)
	}
	defer tx.Rollback()
	now, err := s.authoritativeNow(ctx, tx)
	if err != nil {
		return err
	}
	state, nextAttempt := deliveryTransition(now, claimed.Attempt, result, sendErr, retry)
	attemptResult, err := tx.ExecContext(ctx, s.qualifyQuery(`
		UPDATE hookbound_attempts
		SET finished_at = $1, outcome = $2, status_code = NULLIF($3, 0), duration_ns = $4,
			error_code = NULLIF($5, ''), error_detail = NULLIF($6, ''), response_headers = $7::jsonb,
			response_body = $8, next_attempt_at = $9
		WHERE id = $10 AND delivery_id = $11 AND attempt_number = $12 AND finished_at IS NULL`),
		now, result.Outcome.String(), result.StatusCode, result.Duration.Nanoseconds(), string(errorCode), errorDetail,
		responseHeaders, boundedBytes(result.ResponseBody, s.maxResponseBodyBytes), nullTime(nextAttempt),
		claimed.AttemptID, claimed.DeliveryID, claimed.Attempt)
	if err != nil {
		return hookbound.NewError(hookbound.CodePersistence, "complete webhook attempt", err)
	}
	attemptRows, err := attemptResult.RowsAffected()
	if err != nil {
		return hookbound.NewError(hookbound.CodePersistence, "inspect webhook attempt completion", err)
	}
	if attemptRows != 1 {
		return hookbound.NewError(hookbound.CodeConflict, "webhook attempt was already completed or did not match its delivery", nil)
	}
	completedAt := any(nil)
	if state == DeliveryDelivered || state == DeliveryPermanentFailure || state == DeliveryDisabled || state == DeliveryExhausted {
		completedAt = now
	}
	deliveryResult, err := tx.ExecContext(ctx, s.qualifyQuery(`
		UPDATE hookbound_deliveries
		SET state = $1, next_attempt_at = COALESCE($2, next_attempt_at), lease_expires_at = NULL,
			last_status_code = NULLIF($3, 0), last_error_code = NULLIF($4, ''), updated_at = $5,
			completed_at = $6
		WHERE id = $7 AND state = 'in_flight' AND attempt_count = $8`),
		state, nullTime(nextAttempt), result.StatusCode, string(errorCode), now, completedAt,
		claimed.DeliveryID, claimed.Attempt)
	if err != nil {
		return hookbound.NewError(hookbound.CodePersistence, "complete webhook delivery", err)
	}
	rows, err := deliveryResult.RowsAffected()
	if err != nil {
		return hookbound.NewError(hookbound.CodePersistence, "inspect webhook delivery completion", err)
	}
	if rows != 1 {
		return hookbound.NewError(hookbound.CodeConflict, "delivery lease was lost before completion", nil)
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
	now, err := s.authoritativeNow(ctx, tx)
	if err != nil {
		return nil, err
	}
	claimed := &ClaimedReceipt{StartedAt: now}
	var headersJSON, metadataJSON []byte
	err = tx.QueryRowContext(ctx, s.qualifyQuery(`
		SELECT source, message_id, event_type, event_timestamp, body, content_type, headers, metadata,
		       attempt_count + 1
		FROM hookbound_receipts
		WHERE
			(state IN ('pending','retry') AND next_attempt_at <= $1)
			OR (state = 'processing' AND lease_expires_at <= $1)
		ORDER BY next_attempt_at, received_at
		FOR UPDATE SKIP LOCKED
		LIMIT 1`), now).Scan(
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
	if _, err := tx.ExecContext(ctx, s.qualifyQuery(`
		UPDATE hookbound_receipts
		SET state = 'processing', attempt_count = $1, lease_expires_at = $2, updated_at = $3
		WHERE source = $4 AND message_id = $5`),
		claimed.Attempt, now.Add(lease), now, claimed.Message.Source, claimed.Message.ID); err != nil {
		return nil, hookbound.NewError(hookbound.CodePersistence, "lease webhook receipt", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, hookbound.NewError(hookbound.CodePersistence, "commit receipt claim", err)
	}
	return claimed, nil
}

// RenewReceiptLease extends an active receipt lease using PostgreSQL's
// authoritative clock. It refuses to resurrect an expired or superseded claim.
func (s *Store) RenewReceiptLease(ctx context.Context, claimed *ClaimedReceipt, lease time.Duration) error {
	if claimed == nil {
		return hookbound.NewError(hookbound.CodeInvalidConfiguration, "claimed receipt is required", nil)
	}
	if lease <= 0 {
		return hookbound.NewError(hookbound.CodeInvalidConfiguration, "receipt lease duration must be positive", nil)
	}
	var result sql.Result
	var err error
	if s.clock == nil {
		result, err = s.db.ExecContext(ctx, s.qualifyQuery(`
			WITH current_time AS MATERIALIZED (SELECT pg_catalog.clock_timestamp() AS now)
			UPDATE hookbound_receipts r
			SET lease_expires_at = current_time.now + ($1::bigint * interval '1 microsecond'),
				updated_at = current_time.now
			FROM current_time
			WHERE r.source = $2 AND r.message_id = $3
			  AND r.state = 'processing' AND r.attempt_count = $4
			  AND r.lease_expires_at > current_time.now`),
			durationMicrosecondsCeil(lease), claimed.Message.Source, claimed.Message.ID, claimed.Attempt)
	} else {
		now := s.now()
		result, err = s.db.ExecContext(ctx, s.qualifyQuery(`
			UPDATE hookbound_receipts
			SET lease_expires_at = $1, updated_at = $2
			WHERE source = $3 AND message_id = $4
			  AND state = 'processing' AND attempt_count = $5
			  AND lease_expires_at > $2`),
			now.Add(lease), now, claimed.Message.Source, claimed.Message.ID, claimed.Attempt)
	}
	if err != nil {
		return hookbound.NewError(hookbound.CodePersistence, "renew webhook receipt lease", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return hookbound.NewError(hookbound.CodePersistence, "inspect webhook receipt lease renewal", err)
	}
	if rows != 1 {
		return hookbound.NewError(hookbound.CodeConflict, "receipt lease expired or was lost before renewal", nil)
	}
	return nil
}

func (s *Store) CompleteReceipt(ctx context.Context, claimed *ClaimedReceipt, handlerErr error, retry hookbound.RetryPolicy) error {
	if claimed == nil {
		return hookbound.NewError(hookbound.CodeInvalidConfiguration, "claimed receipt is required", nil)
	}
	now, err := s.authoritativeNow(ctx, s.db)
	if err != nil {
		return err
	}
	state, next := receiptTransition(now, claimed.Attempt, handlerErr, retry)
	processedAt := any(nil)
	if state == ReceiptProcessed || state == ReceiptFailed || state == ReceiptExhausted {
		processedAt = now
	}
	result, err := s.db.ExecContext(ctx, s.qualifyQuery(`
		UPDATE hookbound_receipts
		SET state = $1, next_attempt_at = COALESCE($2, next_attempt_at), lease_expires_at = NULL,
			last_error_code = NULLIF($3, ''), last_error_detail = NULLIF($4, ''),
			processed_at = $5, updated_at = $6
		WHERE source = $7 AND message_id = $8 AND state = 'processing' AND attempt_count = $9`),
		state, nullTime(next), string(hookbound.ErrorCode(handlerErr)), s.errorDetail(handlerErr),
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

func durationMicrosecondsCeil(value time.Duration) int64 {
	microseconds := value / time.Microsecond
	if value%time.Microsecond != 0 {
		microseconds++
	}
	return int64(microseconds)
}

func normalizedOutcome(outcome hookbound.Outcome, sendErr error) hookbound.Outcome {
	if outcome != 0 {
		return outcome
	}
	if sendErr == nil {
		return hookbound.OutcomeRetry
	}
	switch hookbound.ErrorCode(sendErr) {
	case hookbound.CodeInvalidMessage, hookbound.CodeInvalidURL, hookbound.CodeUnsafeDestination, hookbound.CodeInvalidConfiguration:
		return hookbound.OutcomePermanentFailure
	default:
		return hookbound.OutcomeRetry
	}
}

func deliveryTransition(now time.Time, attempt int, result hookbound.AttemptResult, sendErr error, retry hookbound.RetryPolicy) (DeliveryState, time.Time) {
	outcome := normalizedOutcome(result.Outcome, sendErr)
	switch outcome {
	case hookbound.OutcomeDelivered:
		return DeliveryDelivered, time.Time{}
	case hookbound.OutcomeDisableDestination:
		return DeliveryDisabled, time.Time{}
	case hookbound.OutcomePermanentFailure:
		return DeliveryPermanentFailure, time.Time{}
	default:
		policyNext, allowed := retry.Next(now, attempt)
		if !allowed {
			return DeliveryExhausted, time.Time{}
		}
		if !result.RetryAt.IsZero() && result.RetryAt.After(policyNext) {
			return DeliveryRetry, result.RetryAt
		}
		return DeliveryRetry, policyNext
	}
}

func receiptTransition(now time.Time, attempt int, handlerErr error, retry hookbound.RetryPolicy) (ReceiptState, time.Time) {
	if handlerErr == nil {
		return ReceiptProcessed, time.Time{}
	}
	switch hookbound.ErrorCode(handlerErr) {
	case hookbound.CodeInvalidConfiguration, hookbound.CodeInvalidMessage, hookbound.CodeDecode, hookbound.CodeUnknownEvent:
		return ReceiptFailed, time.Time{}
	}
	if next, ok := retry.Next(now, attempt); ok {
		return ReceiptRetry, next
	}
	return ReceiptExhausted, time.Time{}
}

func (s *Store) errorDetail(err error) string {
	if !s.persistErrorDetails {
		return ""
	}
	return truncateError(err, 2048)
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
	value := redactURLQuery(err.Error())
	if len(value) <= maximum {
		return value
	}
	value = value[:maximum]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

var urlWithQuery = regexp.MustCompile(`https?://[^\s"']+\?[^\s"']*`)

func redactURLQuery(value string) string {
	return urlWithQuery.ReplaceAllStringFunc(value, func(raw string) string {
		if index := strings.IndexByte(raw, '?'); index >= 0 {
			return raw[:index] + "?<redacted>"
		}
		return raw
	})
}

var defaultSensitiveHeaders = []string{
	"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie",
	"X-Api-Key", "Api-Key", "X-Auth-Token",
	"Webhook-Signature", "Stripe-Signature", "X-Hub-Signature-256",
}

func containsSensitiveHeaders(headers http.Header, names []string) bool {
	for _, name := range names {
		if len(headers.Values(name)) > 0 {
			return true
		}
	}
	return false
}

func redactedHeaders(headers http.Header, names []string) http.Header {
	clone := headers.Clone()
	for _, name := range names {
		clone.Del(name)
	}
	return clone
}

func boundedBytes(value []byte, maximum int) []byte {
	if maximum <= 0 || len(value) == 0 {
		return nil
	}
	if len(value) > maximum {
		value = value[:maximum]
	}
	return bytes.Clone(value)
}
