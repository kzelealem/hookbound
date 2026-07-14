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
)

func TestReceiverVerifiesPreservesRawAndDeduplicates(t *testing.T) {
	secret, _ := standard.EncodeHMACSecret(bytes.Repeat([]byte{6}, 32))
	keys, _ := standard.StaticHMACKeys(secret)
	signer, _ := standard.NewHMACSigner(keys)
	verifier, _ := standard.NewVerifier(standard.VerifierConfig{HMACKeys: keys, Tolerance: time.Minute})
	registry := hookbound.NewRegistry()
	handled := 0
	raw := []byte(`{"type":"invoice.paid","data":{"id":"inv_1"}}`)
	if err := registry.Register("invoice.paid", hookbound.HandlerFunc(func(_ context.Context, message hookbound.VerifiedMessage) error {
		handled++
		if !bytes.Equal(message.Body, raw) {
			t.Fatalf("raw body changed: %s", message.Body)
		}
		return nil
	})); err != nil {
		t.Fatal(err)
	}
	receiver, err := hookbound.NewReceiver(hookbound.ReceiverConfig{
		Verifier:    verifier,
		Handler:     registry,
		ReplayGuard: hookbound.NewMemoryReplayGuard(100, fixedClock{time.Unix(1000, 0)}),
		Clock:       fixedClock{time.Unix(1000, 0)},
	})
	if err != nil {
		t.Fatal(err)
	}
	headers, _ := signer.Sign(context.Background(), hookbound.SignInput{
		MessageID: "msg_receiver", Timestamp: time.Unix(1000, 0), Body: raw,
	})
	for range 2 {
		request := httptest.NewRequest(http.MethodPost, "/webhooks", bytes.NewReader(raw))
		request.Header = headers.Clone()
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		receiver.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("unexpected status: %d body=%s", response.Code, response.Body.String())
		}
	}
	if handled != 1 {
		t.Fatalf("expected one handler call, got %d", handled)
	}
}

func TestReceiverRejectsOversizedBeforeVerification(t *testing.T) {
	verifier := verifierFunc(func(context.Context, hookbound.VerifyInput) (hookbound.Verification, error) {
		t.Fatal("verifier should not run")
		return hookbound.Verification{}, nil
	})
	receiver, _ := hookbound.NewReceiver(hookbound.ReceiverConfig{
		Verifier:     verifier,
		Handler:      hookbound.HandlerFunc(func(context.Context, hookbound.VerifiedMessage) error { return nil }),
		MaxBodyBytes: 4,
	})
	response := httptest.NewRecorder()
	receiver.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("12345"))))
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("unexpected status: %d", response.Code)
	}
}

type verifierFunc func(context.Context, hookbound.VerifyInput) (hookbound.Verification, error)

func (f verifierFunc) Verify(ctx context.Context, input hookbound.VerifyInput) (hookbound.Verification, error) {
	return f(ctx, input)
}
