package postgres

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

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
	if !containsSensitiveHeaders(headers) {
		t.Fatal("expected sensitive headers to be detected")
	}
	redacted := redactedHeaders(headers)
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
