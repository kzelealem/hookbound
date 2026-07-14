package hookbound_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hookbound/hookbound"
	"github.com/hookbound/hookbound/standard"
	"github.com/hookbound/hookbound/transport"
)

type fixedClock struct{ value time.Time }

func (c fixedClock) Now() time.Time { return c.value }

type fixedIDGenerator string

func (g fixedIDGenerator) NewMessageID() (string, error) { return string(g), nil }

func TestSenderMakesOneSignedAttempt(t *testing.T) {
	secret, _ := standard.EncodeHMACSecret(bytes.Repeat([]byte{8}, 32))
	keys, _ := standard.StaticHMACKeys(secret)
	signer, _ := standard.NewHMACSigner(keys)
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		verifier, _ := standard.NewVerifier(standard.VerifierConfig{
			HMACKeys:  keys,
			Tolerance: time.Minute,
			ExtractType: func(_ []byte, headers http.Header) (string, error) {
				return headers.Get("X-Hookbound-Event"), nil
			},
		})
		if _, err := verifier.Verify(r.Context(), hookbound.VerifyInput{
			Headers: r.Header, Body: body, ReceivedAt: time.Unix(1000, 0),
		}); err != nil {
			t.Errorf("verify request: %v", err)
		}
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	sender, err := hookbound.NewSender(hookbound.SenderConfig{
		Signer:        signer,
		NetworkPolicy: transport.DevelopmentPolicy(),
		Clock:         fixedClock{time.Unix(1000, 0)},
		IDGenerator:   fixedIDGenerator("msg_sender"),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := sender.Send(context.Background(), hookbound.SendRequest{
		URL: server.URL, EventType: "invoice.paid", Body: []byte(`{"ok":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || result.Outcome != hookbound.OutcomeRetry || result.StatusCode != 503 {
		t.Fatalf("unexpected result: attempts=%d result=%+v", attempts, result)
	}
}

func TestSenderRejectsUnsafeDefaultDestination(t *testing.T) {
	secret, _ := standard.EncodeHMACSecret(bytes.Repeat([]byte{8}, 32))
	keys, _ := standard.StaticHMACKeys(secret)
	signer, _ := standard.NewHMACSigner(keys)
	sender, _ := hookbound.NewSender(hookbound.SenderConfig{Signer: signer})
	_, err := sender.Send(context.Background(), hookbound.SendRequest{
		URL: "http://127.0.0.1/internal", EventType: "test.event", Body: []byte("{}"),
	})
	if hookbound.ErrorCode(err) != hookbound.CodeUnsafeDestination {
		t.Fatalf("unexpected error: %v", err)
	}
}
