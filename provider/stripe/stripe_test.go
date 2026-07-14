package stripe

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/hookbound/hookbound"
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
