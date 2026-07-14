package hookbound

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

type fixedID string

func (f fixedID) NewMessageID() (string, error) { return string(f), nil }

type fixedJitter time.Duration

func (f fixedJitter) Duration(time.Duration) time.Duration { return time.Duration(f) }

func TestRandomIDGenerator(t *testing.T) {
	generator := RandomIDGenerator{Reader: bytes.NewReader(make([]byte, 16))}
	id, err := generator.NewMessageID()
	if err != nil {
		t.Fatal(err)
	}
	if id != "msg_aaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("unexpected id: %s", id)
	}
	if err := ValidateMessageID(id); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryTypedHandlerPreservesRaw(t *testing.T) {
	type payload struct {
		Value string `json:"value"`
	}
	registry := NewRegistry()
	var received Message[payload]
	if err := HandleJSON(registry, "thing.created", func(_ context.Context, message Message[payload]) error {
		received = message
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	raw := []byte(`{"value":"ok"}`)
	err := registry.Handle(context.Background(), VerifiedMessage{
		ID:          "msg_test",
		Type:        "thing.created",
		Source:      "test",
		Body:        raw,
		Headers:     http.Header{"X-Test": {"one"}},
		ContentType: "application/json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if received.Data.Value != "ok" || !bytes.Equal(received.Raw, raw) {
		t.Fatalf("unexpected message: %#v", received)
	}
	raw[0] = 'x'
	if received.Raw[0] != '{' {
		t.Fatal("handler retained mutable source body")
	}
}

func TestDefaultClassifier(t *testing.T) {
	now := time.Unix(1000, 0)
	classifier := DefaultClassifier{MaxRetryAfter: time.Hour}

	outcome, retryAt := classifier.Classify(now, &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Header:     http.Header{"Retry-After": {"120"}},
	}, nil)
	if outcome != OutcomeRetry || !retryAt.Equal(now.Add(2*time.Minute)) {
		t.Fatalf("unexpected classification: %s %s", outcome, retryAt)
	}

	outcome, _ = classifier.Classify(now, &http.Response{StatusCode: http.StatusGone, Header: make(http.Header)}, nil)
	if outcome != OutcomeDisableDestination {
		t.Fatalf("unexpected outcome: %s", outcome)
	}
}

func TestRetryPolicy(t *testing.T) {
	policy := RetryPolicy{
		Schedule:    []time.Duration{time.Second, time.Minute},
		MaxAttempts: 3,
		Jitter:      fixedJitter(100 * time.Millisecond),
	}
	now := time.Unix(0, 0)
	next, ok := policy.Next(now, 1)
	if !ok || !next.Equal(now.Add(1100*time.Millisecond)) {
		t.Fatalf("unexpected next retry: %v %v", next, ok)
	}
	if _, ok := policy.Next(now, 3); ok {
		t.Fatal("expected retry exhaustion")
	}
}

func TestErrorCode(t *testing.T) {
	err := NewError(CodeDecode, "decode", errors.New("bad"))
	if got := ErrorCode(err); got != CodeDecode {
		t.Fatalf("unexpected code: %s", got)
	}
}

func TestErrorCodeNilIsEmpty(t *testing.T) {
	if code := ErrorCode(nil); code != "" {
		t.Fatalf("expected empty code for nil error, got %q", code)
	}
}

func TestRegistryPreservesTypedHookboundErrors(t *testing.T) {
	registry := NewRegistry()
	if err := HandleJSON(registry, "thing.created", func(context.Context, Message[struct{}]) error { return nil }); err != nil {
		t.Fatal(err)
	}
	err := registry.Handle(context.Background(), VerifiedMessage{
		ID: "msg_decode", Type: "thing.created", Source: "test", Body: []byte("{"),
	})
	if ErrorCode(err) != CodeDecode {
		t.Fatalf("expected decode error, got %v", err)
	}
}
