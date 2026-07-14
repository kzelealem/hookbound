package stripe

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kzelealem/hookbound"
)

func TestVerifier(t *testing.T) {
	timestamp := time.Unix(1000, 0)
	body := []byte(`{"id":"evt_1","type":"invoice.paid"}`)
	content := append([]byte(strconv.FormatInt(timestamp.Unix(), 10)+"."), body...)
	mac := hmac.New(sha256.New, []byte("whsec_test"))
	_, _ = mac.Write(content)
	headers := http.Header{HeaderSignature: {"t=1000,v1=" + hex.EncodeToString(mac.Sum(nil))}}
	verifier, _ := NewVerifier(hookbound.StaticSecret("whsec_test"))
	verified, err := verifier.Verify(context.Background(), hookbound.VerifyInput{Headers: headers, Body: body, ReceivedAt: timestamp})
	if err != nil {
		t.Fatal(err)
	}
	if verified.ID != "evt_1" || verified.Type != "invoice.paid" {
		t.Fatalf("unexpected verification: %#v", verified)
	}
}

func TestVerifierRejectsFarFutureTimestampWithoutDurationOverflow(t *testing.T) {
	future := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	body := []byte(`{"id":"evt_future","type":"invoice.paid"}`)
	content := append([]byte(strconv.FormatInt(future.Unix(), 10)+"."), body...)
	mac := hmac.New(sha256.New, []byte("whsec_test"))
	_, _ = mac.Write(content)
	headers := http.Header{HeaderSignature: {"t=" + strconv.FormatInt(future.Unix(), 10) + ",v1=" + hex.EncodeToString(mac.Sum(nil))}}
	verifier, _ := NewVerifier(hookbound.StaticSecret("whsec_test"))
	_, err := verifier.Verify(context.Background(), hookbound.VerifyInput{
		Headers:    headers,
		Body:       body,
		ReceivedAt: time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC),
	})
	if hookbound.ErrorCode(err) != hookbound.CodeExpiredSignature {
		t.Fatalf("expected expired signature, got %v", err)
	}
}

func TestVerifierRejectsDuplicateTimestampComponents(t *testing.T) {
	verifier, _ := NewVerifier(hookbound.StaticSecret("whsec_test"))
	_, err := verifier.Verify(context.Background(), hookbound.VerifyInput{
		Headers:    http.Header{HeaderSignature: {"t=1000,t=1001,v1=" + strings.Repeat("00", sha256.Size)}},
		Body:       []byte(`{}`),
		ReceivedAt: time.Unix(1000, 0),
	})
	if hookbound.ErrorCode(err) != hookbound.CodeInvalidSignature {
		t.Fatalf("expected invalid signature, got %v", err)
	}
}

func TestNilVerifierReturnsConfigurationError(t *testing.T) {
	var verifier *Verifier
	_, err := verifier.Verify(context.Background(), hookbound.VerifyInput{Headers: make(http.Header)})
	if hookbound.ErrorCode(err) != hookbound.CodeInvalidConfiguration {
		t.Fatalf("expected invalid configuration, got %v", err)
	}
}
