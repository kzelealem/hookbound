package postgres

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/hookbound/hookbound"
)

type noJitter struct{}

func (noJitter) Duration(time.Duration) time.Duration { return 0 }

func TestDeliveryTransition(t *testing.T) {
	now := time.Unix(100, 0)
	policy := hookbound.RetryPolicy{Schedule: []time.Duration{time.Minute}, MaxAttempts: 2, Jitter: noJitter{}}

	state, _ := deliveryTransition(now, 1, hookbound.AttemptResult{Outcome: hookbound.OutcomeDelivered}, nil, policy)
	if state != DeliveryDelivered {
		t.Fatalf("unexpected delivered state: %s", state)
	}
	state, next := deliveryTransition(now, 1, hookbound.AttemptResult{Outcome: hookbound.OutcomeRetry}, nil, policy)
	if state != DeliveryRetry || !next.Equal(now.Add(time.Minute)) {
		t.Fatalf("unexpected retry state: %s %s", state, next)
	}
	state, _ = deliveryTransition(now, 2, hookbound.AttemptResult{Outcome: hookbound.OutcomeRetry}, nil, policy)
	if state != DeliveryExhausted {
		t.Fatalf("unexpected exhausted state: %s", state)
	}
	state, _ = deliveryTransition(now, 1, hookbound.AttemptResult{}, hookbound.NewError(hookbound.CodeUnsafeDestination, "unsafe", errors.New("blocked")), policy)
	if state != DeliveryPermanentFailure {
		t.Fatalf("unexpected preflight state: %s", state)
	}
}

func TestMigrationSplit(t *testing.T) {
	statements := splitStatements("-- hookbound:statement\nSELECT 1;\n-- hookbound:statement\nSELECT 2;")
	if len(statements) != 2 {
		t.Fatalf("unexpected statements: %#v", statements)
	}
}

func TestRandomOpaqueID(t *testing.T) {
	id, err := randomOpaqueID("dlv_")
	if err != nil {
		t.Fatal(err)
	}
	if len(id) < 10 || id[:4] != "dlv_" {
		t.Fatalf("unexpected id: %s", id)
	}
}

func TestRetryAfterCannotExceedAttemptBudget(t *testing.T) {
	now := time.Unix(100, 0)
	policy := hookbound.RetryPolicy{Schedule: []time.Duration{time.Minute}, MaxAttempts: 1, Jitter: noJitter{}}
	state, next := deliveryTransition(now, 1, hookbound.AttemptResult{
		Outcome: hookbound.OutcomeRetry,
		RetryAt: now.Add(24 * time.Hour),
	}, nil, policy)
	if state != DeliveryExhausted || !next.IsZero() {
		t.Fatalf("expected exhausted delivery, got state=%s next=%s", state, next)
	}
}

func TestDurableHeaderRedaction(t *testing.T) {
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer secret")
	headers.Set("Cookie", "session=secret")
	headers.Set("X-Request-ID", "public")
	if !containsSensitiveHeaders(headers, defaultSensitiveHeaders) {
		t.Fatal("expected sensitive headers to be detected")
	}
	redacted := redactedHeaders(headers, defaultSensitiveHeaders)
	if redacted.Get("Authorization") != "" || redacted.Get("Cookie") != "" {
		t.Fatalf("sensitive headers were retained: %#v", redacted)
	}
	if redacted.Get("X-Request-ID") != "public" {
		t.Fatal("non-sensitive header was removed")
	}
	if headers.Get("Authorization") == "" {
		t.Fatal("redaction mutated the caller's header map")
	}
}

func TestErrorURLQueryRedaction(t *testing.T) {
	value := truncateError(errors.New("POST https://example.com/hook?token=secret&x=1 failed"), 2048)
	if strings.Contains(value, "secret") || !strings.Contains(value, "?<redacted>") {
		t.Fatalf("unexpected redacted error: %q", value)
	}
}

func TestResponseBodiesAreOptInAndBounded(t *testing.T) {
	body := []byte("sensitive-response")
	if got := boundedBytes(body, 0); got != nil {
		t.Fatalf("expected response persistence to be disabled, got %q", got)
	}
	got := boundedBytes(body, 9)
	if string(got) != "sensitive" {
		t.Fatalf("unexpected bounded body: %q", got)
	}
	got[0] = 'X'
	if body[0] != 's' {
		t.Fatal("bounded body retained mutable source memory")
	}
}

func TestReceiptTransitionDoesNotRetryPermanentHandlerErrors(t *testing.T) {
	now := time.Unix(100, 0)
	policy := hookbound.RetryPolicy{Schedule: []time.Duration{time.Minute}, MaxAttempts: 3, Jitter: noJitter{}}
	for _, code := range []hookbound.Code{
		hookbound.CodeInvalidConfiguration,
		hookbound.CodeInvalidMessage,
		hookbound.CodeDecode,
		hookbound.CodeUnknownEvent,
	} {
		state, next := receiptTransition(now, 1, hookbound.NewError(code, "permanent", nil), policy)
		if state != ReceiptFailed || !next.IsZero() {
			t.Fatalf("code %s was retried: state=%s next=%s", code, state, next)
		}
	}
	state, next := receiptTransition(now, 1, hookbound.NewError(hookbound.CodeHandler, "temporary", nil), policy)
	if state != ReceiptRetry || !next.Equal(now.Add(time.Minute)) {
		t.Fatalf("transient handler error was not retried: state=%s next=%s", state, next)
	}
}

func TestDeliveryTransitionNeverRetriesEarlierThanLocalBackoff(t *testing.T) {
	now := time.Unix(100, 0)
	policy := hookbound.RetryPolicy{Schedule: []time.Duration{time.Minute}, MaxAttempts: 2, Jitter: noJitter{}}
	state, next := deliveryTransition(now, 1, hookbound.AttemptResult{
		Outcome: hookbound.OutcomeRetry,
		RetryAt: now.Add(time.Second),
	}, nil, policy)
	if state != DeliveryRetry || !next.Equal(now.Add(time.Minute)) {
		t.Fatalf("remote Retry-After shortened local backoff: state=%s next=%s", state, next)
	}
}

func TestDurableRedactionRemovesReplayableSignatureHeaders(t *testing.T) {
	headers := http.Header{
		"Webhook-Signature":      {"v1,secret"},
		"Stripe-Signature":       {"t=1,v1=secret"},
		"X-Hub-Signature-256":    {"sha256=secret"},
		"X-Non-Sensitive-Header": {"safe"},
	}
	redacted := redactedHeaders(headers, defaultSensitiveHeaders)
	for _, name := range []string{"Webhook-Signature", "Stripe-Signature", "X-Hub-Signature-256"} {
		if redacted.Get(name) != "" {
			t.Fatalf("signature header %s was retained", name)
		}
	}
	if redacted.Get("X-Non-Sensitive-Header") != "safe" {
		t.Fatal("non-sensitive header was removed")
	}
}

func TestErrorDetailsAreOptInAndUTF8Safe(t *testing.T) {
	store := &Store{}
	if got := store.errorDetail(errors.New("secret diagnostic")); got != "" {
		t.Fatalf("error details should be disabled by default: %q", got)
	}
	store.persistErrorDetails = true
	got := truncateError(errors.New(strings.Repeat("é", 2000)), 2047)
	if !utf8.ValidString(got) || len(got) > 2047 {
		t.Fatalf("truncated error is not valid bounded UTF-8: len=%d", len(got))
	}
}

func TestMigrationChecksumIsStableAndContentSensitive(t *testing.T) {
	first := migrationChecksum([]byte("SELECT 1"))
	if first != migrationChecksum([]byte("SELECT 1")) {
		t.Fatal("migration checksum is not stable")
	}
	if first == migrationChecksum([]byte("SELECT 2")) {
		t.Fatal("migration checksum ignored content changes")
	}
}

func TestDurableWorkerRecoversPanics(t *testing.T) {
	worked, err := runWorkSafely(context.Background(), func(context.Context) (bool, error) {
		panic("worker boom")
	})
	if worked || hookbound.ErrorCode(err) != hookbound.CodeInternal || !strings.Contains(err.Error(), "worker boom") {
		t.Fatalf("unexpected recovered worker panic: worked=%v err=%v", worked, err)
	}

	handlerErr := handleSafely(hookbound.HandlerFunc(func(context.Context, hookbound.VerifiedMessage) error {
		panic("handler boom")
	}), context.Background(), hookbound.VerifiedMessage{})
	if hookbound.ErrorCode(handlerErr) != hookbound.CodeHandler || !strings.Contains(handlerErr.Error(), "handler boom") {
		t.Fatalf("unexpected recovered handler panic: %v", handlerErr)
	}
}

func TestSchemaValidationAndQualification(t *testing.T) {
	t.Parallel()
	for _, schema := range []string{"public", "hookbound", "tenant-one", `tenant"quoted`} {
		normalized, err := normalizeSchema(schema)
		if err != nil {
			t.Fatalf("schema %q rejected: %v", schema, err)
		}
		store := &Store{relations: relationsForSchema(normalized)}
		query := store.qualifyQuery("SELECT * FROM hookbound_messages JOIN hookbound_deliveries USING (message_id)")
		if !strings.Contains(query, qualifiedRelation(schema, "hookbound_messages")) ||
			!strings.Contains(query, qualifiedRelation(schema, "hookbound_deliveries")) {
			t.Fatalf("query was not schema-qualified: %s", query)
		}
	}
	for _, schema := range []string{" leading", "trailing ", "1schema", "bad\x00schema", "pg_catalog", "PG_temp_7", "information_schema", strings.Repeat("x", 64)} {
		if _, err := normalizeSchema(schema); err == nil {
			t.Fatalf("invalid schema %q was accepted", schema)
		}
	}
}

func TestPublicationKeyHashValidationAndStability(t *testing.T) {
	t.Parallel()
	first, err := publicationKeyHash("invoice:tenant-1:42:endpoint-7")
	if err != nil {
		t.Fatal(err)
	}
	second, err := publicationKeyHash("invoice:tenant-1:42:endpoint-7")
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 32 || string(first) != string(second) {
		t.Fatalf("unexpected idempotency hash: %x %x", first, second)
	}
	if other, _ := publicationKeyHash("invoice:tenant-1:43:endpoint-7"); string(first) == string(other) {
		t.Fatal("different idempotency keys produced the same test hash")
	}
	for _, key := range []string{" key", "key ", "bad\nkey", strings.Repeat("k", 513)} {
		if _, err := publicationKeyHash(key); err == nil {
			t.Fatalf("invalid idempotency key %q was accepted", key)
		}
	}
}

func TestRetentionPolicyValidation(t *testing.T) {
	t.Parallel()
	if _, err := normalizeRetentionPolicy(RetentionPolicy{DeliveredRetention: -time.Second}); err == nil {
		t.Fatal("negative retention was accepted")
	}
	if _, err := normalizeRetentionPolicy(RetentionPolicy{BatchSize: maximumCleanupBatchSize + 1}); err == nil {
		t.Fatal("oversized cleanup batch was accepted")
	}
	policy, err := normalizeRetentionPolicy(RetentionPolicy{})
	if err != nil || policy.BatchSize != defaultCleanupBatchSize {
		t.Fatalf("default cleanup policy was not normalized: policy=%+v err=%v", policy, err)
	}
}

func TestCanonicalHeadersMergesCaseVariantsDeterministically(t *testing.T) {
	t.Parallel()
	headers := http.Header{
		"x-test": {"lower"},
		"X-Test": {"upper"},
	}
	canonical := canonicalHeaders(headers)
	if got := canonical.Values("X-Test"); !reflect.DeepEqual(got, []string{"upper", "lower"}) {
		t.Fatalf("unexpected canonical header values: %#v", got)
	}
}

func TestLeaseHeartbeatRenewsAndStops(t *testing.T) {
	t.Parallel()
	var renewals atomic.Int64
	ctx, heartbeat := startLeaseHeartbeat(context.Background(), 5*time.Millisecond, 2*time.Millisecond, func(context.Context) error {
		renewals.Add(1)
		return nil
	})
	select {
	case <-ctx.Done():
		t.Fatal("work context canceled during successful renewals")
	case <-time.After(18 * time.Millisecond):
	}
	if err := heartbeat.Stop(); err != nil {
		t.Fatal(err)
	}
	if renewals.Load() < 2 {
		t.Fatalf("expected repeated renewals, got %d", renewals.Load())
	}
}

func TestLeaseHeartbeatCancelsWorkOnFailureAndPanic(t *testing.T) {
	t.Parallel()
	for _, renew := range []func(context.Context) error{
		func(context.Context) error { return errors.New("database unavailable") },
		func(context.Context) error { panic("renewal boom") },
	} {
		ctx, heartbeat := startLeaseHeartbeat(context.Background(), time.Millisecond, time.Second, renew)
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
			t.Fatal("heartbeat failure did not cancel work")
		}
		if err := heartbeat.Stop(); err == nil {
			t.Fatal("heartbeat failure was not returned")
		}
	}
}

func TestRuntimeRejectsUnsafeLeaseRenewalTiming(t *testing.T) {
	t.Parallel()
	store := &Store{}
	_, err := NewRuntime(RuntimeConfig{
		Store: store, LeaseDuration: time.Second,
		LeaseRenewalInterval: 800 * time.Millisecond,
		LeaseRenewalTimeout:  300 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("unsafe lease renewal timing was accepted")
	}
}

func TestDurationMicrosecondsCeil(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		value time.Duration
		want  int64
	}{
		{name: "sub-microsecond", value: time.Nanosecond, want: 1},
		{name: "exact", value: time.Microsecond, want: 1},
		{name: "rounded", value: time.Microsecond + time.Nanosecond, want: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := durationMicrosecondsCeil(test.value); got != test.want {
				t.Fatalf("durationMicrosecondsCeil(%s) = %d, want %d", test.value, got, test.want)
			}
		})
	}
}
