package testkit

import (
	"bytes"
	"context"
	"net/http"
	"testing"

	"github.com/kzelealem/hookbound"
)

func RequireAttempts(t testing.TB, endpoint *Endpoint, expected int) {
	t.Helper()
	actual := len(endpoint.Requests())
	if actual != expected {
		t.Fatalf("expected %d webhook attempts, got %d", expected, actual)
	}
}

func RequireStableMessageID(t testing.TB, requests []CapturedRequest, headerName string) string {
	t.Helper()
	if len(requests) == 0 {
		t.Fatal("expected at least one captured webhook request")
	}
	if headerName == "" {
		headerName = "Webhook-Id"
	}
	expected := requests[0].Header.Get(headerName)
	if expected == "" {
		t.Fatalf("first request is missing %s", headerName)
	}
	for index, request := range requests[1:] {
		if actual := request.Header.Get(headerName); actual != expected {
			t.Fatalf("request %d has message ID %q; expected %q", index+2, actual, expected)
		}
	}
	return expected
}

func RequireBody(t testing.TB, request CapturedRequest, expected []byte) {
	t.Helper()
	if !bytes.Equal(request.Body, expected) {
		t.Fatalf("unexpected webhook body\nactual:   %q\nexpected: %q", request.Body, expected)
	}
}

func RequireHeader(t testing.TB, request CapturedRequest, name, expected string) {
	t.Helper()
	if actual := request.Header.Get(name); actual != expected {
		t.Fatalf("unexpected %s header: got %q, want %q", name, actual, expected)
	}
}

func RequireVerified(t testing.TB, verifier hookbound.Verifier, request CapturedRequest) hookbound.Verification {
	t.Helper()
	if verifier == nil {
		t.Fatal("verifier is required")
	}
	verification, err := verifier.Verify(context.Background(), hookbound.VerifyInput{
		Headers: request.Header.Clone(), Body: bytes.Clone(request.Body), ReceivedAt: request.ReceivedAt,
	})
	if err != nil {
		t.Fatalf("expected captured request to verify: %v", err)
	}
	return verification
}

func NewRequest(method, target string, body []byte, headers http.Header) *http.Request {
	request, err := http.NewRequest(method, target, bytes.NewReader(body))
	if err != nil {
		panic(err)
	}
	request.Header = headers.Clone()
	return request
}
