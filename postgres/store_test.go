package postgres

import (
	"errors"
	"net/http"
	"strings"
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
