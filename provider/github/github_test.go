package github

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/kzelealem/hookbound"
)

func TestVerifier(t *testing.T) {
	body := []byte(`{"action":"opened","number":1}`)
	mac := hmac.New(sha256.New, []byte("secret"))
	_, _ = mac.Write(body)
	headers := http.Header{
		HeaderDelivery:  {"delivery_1"},
		HeaderEvent:     {"pull_request"},
		HeaderSignature: {"sha256=" + hex.EncodeToString(mac.Sum(nil))},
	}
	verifier, _ := NewVerifier(hookbound.StaticSecret("secret"))
	verified, err := verifier.Verify(context.Background(), hookbound.VerifyInput{Headers: headers, Body: body, ReceivedAt: time.Unix(1, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if verified.Type != "pull_request.opened" || verified.ID != "delivery_1" {
		t.Fatalf("unexpected verification: %#v", verified)
	}
}
