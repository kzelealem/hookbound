package hookbound_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/kzelealem/hookbound"
	"github.com/kzelealem/hookbound/standard"
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

func TestReceiverReleasesReplayClaimWhenHandlerFails(t *testing.T) {
	body := []byte(`{"type":"test.failed"}`)
	verifier := verifierFunc(func(context.Context, hookbound.VerifyInput) (hookbound.Verification, error) {
		return hookbound.Verification{ID: "msg_retry", Type: "test.failed", Source: "test", Timestamp: time.Unix(1000, 0)}, nil
	})
	calls := 0
	receiver, err := hookbound.NewReceiver(hookbound.ReceiverConfig{
		Verifier: verifier,
		Handler: hookbound.HandlerFunc(func(context.Context, hookbound.VerifiedMessage) error {
			calls++
			if calls == 1 {
				return errors.New("temporary failure")
			}
			return nil
		}),
		ReplayGuard: hookbound.NewMemoryReplayGuard(10, fixedClock{time.Unix(1000, 0)}),
		Clock:       fixedClock{time.Unix(1000, 0)},
	})
	if err != nil {
		t.Fatal(err)
	}
	first := httptest.NewRecorder()
	receiver.ServeHTTP(first, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	if first.Code != http.StatusInternalServerError {
		t.Fatalf("expected first attempt to fail, got %d", first.Code)
	}
	second := httptest.NewRecorder()
	receiver.ServeHTTP(second, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	if second.Code != http.StatusNoContent || calls != 2 {
		t.Fatalf("expected provider retry to run again, status=%d calls=%d", second.Code, calls)
	}
}

type failingReplayGuard struct {
	commitErr  error
	releaseErr error
}

func (g failingReplayGuard) Claim(context.Context, string, string, time.Time) (bool, error) {
	return true, nil
}

func (g failingReplayGuard) Commit(context.Context, string, string, time.Time) error {
	return g.commitErr
}

func (g failingReplayGuard) Release(context.Context, string, string) error {
	return g.releaseErr
}

func TestReceiverDoesNotAcknowledgeConcurrentMessageBeforeHandlerCommits(t *testing.T) {
	body := []byte(`{"type":"test.concurrent"}`)
	verifier := verifierFunc(func(context.Context, hookbound.VerifyInput) (hookbound.Verification, error) {
		return hookbound.Verification{ID: "msg_concurrent", Type: "test.concurrent", Source: "test", Timestamp: time.Unix(1000, 0)}, nil
	})
	entered := make(chan struct{})
	unblock := make(chan struct{})
	var calls int
	var mu sync.Mutex
	receiver, err := hookbound.NewReceiver(hookbound.ReceiverConfig{
		Verifier: verifier,
		Handler: hookbound.HandlerFunc(func(context.Context, hookbound.VerifiedMessage) error {
			mu.Lock()
			calls++
			call := calls
			mu.Unlock()
			if call == 1 {
				close(entered)
				<-unblock
				return errors.New("temporary failure")
			}
			return nil
		}),
		ReplayGuard: hookbound.NewMemoryReplayGuard(10, fixedClock{time.Unix(1000, 0)}),
		Clock:       fixedClock{time.Unix(1000, 0)},
	})
	if err != nil {
		t.Fatal(err)
	}

	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		receiver.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
		firstDone <- response
	}()
	<-entered

	secondDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		receiver.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
		secondDone <- response
	}()
	select {
	case response := <-secondDone:
		t.Fatalf("duplicate completed before the active handler: status=%d", response.Code)
	case <-time.After(25 * time.Millisecond):
	}

	close(unblock)
	first := <-firstDone
	second := <-secondDone
	if first.Code != http.StatusInternalServerError {
		t.Fatalf("expected first attempt to fail, got %d", first.Code)
	}
	if second.Code != http.StatusNoContent {
		t.Fatalf("expected waiting duplicate to retry after release, got %d", second.Code)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 2 {
		t.Fatalf("expected two serialized handler calls, got %d", calls)
	}
}

func TestReceiverDoesNotAcknowledgeReplayCommitFailure(t *testing.T) {
	receiver, err := hookbound.NewReceiver(hookbound.ReceiverConfig{
		Verifier: verifierFunc(func(context.Context, hookbound.VerifyInput) (hookbound.Verification, error) {
			return hookbound.Verification{ID: "msg_commit", Type: "test.commit", Source: "test", Timestamp: time.Unix(1000, 0)}, nil
		}),
		Handler:     hookbound.HandlerFunc(func(context.Context, hookbound.VerifiedMessage) error { return nil }),
		ReplayGuard: failingReplayGuard{commitErr: errors.New("store unavailable")},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	receiver.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/", http.NoBody))
	if response.Code < 500 {
		t.Fatalf("replay commit failure was acknowledged with %d", response.Code)
	}
}

func TestReceiverDoesNotAcknowledgeHandlerAndReleaseFailure(t *testing.T) {
	receiver, err := hookbound.NewReceiver(hookbound.ReceiverConfig{
		Verifier: verifierFunc(func(context.Context, hookbound.VerifyInput) (hookbound.Verification, error) {
			return hookbound.Verification{ID: "msg_release", Type: "test.release", Source: "test", Timestamp: time.Unix(1000, 0)}, nil
		}),
		Handler:     hookbound.HandlerFunc(func(context.Context, hookbound.VerifiedMessage) error { return errors.New("handler failed") }),
		ReplayGuard: failingReplayGuard{releaseErr: errors.New("store unavailable")},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	receiver.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/", http.NoBody))
	if response.Code < 500 {
		t.Fatalf("handler and replay release failure was acknowledged with %d", response.Code)
	}
}

func TestReceiverReleasesReplayClaimWhenHandlerPanics(t *testing.T) {
	body := []byte(`{"type":"test.panic"}`)
	verifier := verifierFunc(func(context.Context, hookbound.VerifyInput) (hookbound.Verification, error) {
		return hookbound.Verification{ID: "msg_panic", Type: "test.panic", Source: "test", Timestamp: time.Unix(1000, 0)}, nil
	})
	calls := 0
	receiver, err := hookbound.NewReceiver(hookbound.ReceiverConfig{
		Verifier: verifier,
		Handler: hookbound.HandlerFunc(func(context.Context, hookbound.VerifiedMessage) error {
			calls++
			if calls == 1 {
				panic("boom")
			}
			return nil
		}),
		ReplayGuard: hookbound.NewMemoryReplayGuard(10, fixedClock{time.Unix(1000, 0)}),
		Clock:       fixedClock{time.Unix(1000, 0)},
	})
	if err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected handler panic")
			}
		}()
		receiver.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	}()

	response := httptest.NewRecorder()
	receiver.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	if response.Code != http.StatusNoContent || calls != 2 {
		t.Fatalf("panic left replay claim stuck: status=%d calls=%d", response.Code, calls)
	}
}
