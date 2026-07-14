// Package stripe verifies inbound Stripe webhook signatures without importing
// Stripe's full API SDK.
package stripe

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/hookbound/hookbound"
)

const HeaderSignature = "Stripe-Signature"

type Verifier struct {
	Secret    hookbound.SecretProvider
	Tolerance time.Duration
}

func NewVerifier(secret hookbound.SecretProvider) (*Verifier, error) {
	if secret == nil {
		return nil, hookbound.NewError(hookbound.CodeInvalidConfiguration, "Stripe endpoint secret is required", nil)
	}
	return &Verifier{Secret: secret, Tolerance: 5 * time.Minute}, nil
}

func (v *Verifier) Verify(ctx context.Context, input hookbound.VerifyInput) (hookbound.Verification, error) {
	values := input.Headers.Values(HeaderSignature)
	if len(values) != 1 {
		return hookbound.Verification{}, hookbound.NewError(hookbound.CodeInvalidSignature, "exactly one Stripe-Signature header is required", nil)
	}
	timestamp, signatures, err := parseHeader(values[0])
	if err != nil {
		return hookbound.Verification{}, err
	}
	if v.Tolerance > 0 {
		delta := input.ReceivedAt.Sub(timestamp)
		if delta < 0 {
			delta = -delta
		}
		if delta > v.Tolerance {
			return hookbound.Verification{}, hookbound.NewError(hookbound.CodeExpiredSignature, "Stripe signature timestamp is outside the allowed tolerance", nil)
		}
	}
	secret, err := v.Secret.Secret(ctx)
	if err != nil || secret == "" {
		return hookbound.Verification{}, hookbound.NewError(hookbound.CodeInternal, "resolve Stripe endpoint secret", err)
	}
	content := append([]byte(strconv.FormatInt(timestamp.Unix(), 10)+"."), input.Body...)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(content)
	expected := mac.Sum(nil)
	valid := 0
	for _, signature := range signatures {
		if len(signature) == len(expected) {
			valid |= subtle.ConstantTimeCompare(signature, expected)
		}
	}
	if valid != 1 {
		return hookbound.Verification{}, hookbound.NewError(hookbound.CodeInvalidSignature, "Stripe signature did not match", nil)
	}
	var envelope struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(input.Body, &envelope); err != nil {
		return hookbound.Verification{}, hookbound.NewError(hookbound.CodeDecode, "decode Stripe event metadata", err)
	}
	if err := hookbound.ValidateMessageID(envelope.ID); err != nil {
		return hookbound.Verification{}, err
	}
	if err := hookbound.ValidateEventType(envelope.Type); err != nil {
		return hookbound.Verification{}, err
	}
	return hookbound.Verification{ID: envelope.ID, Type: envelope.Type, Source: "stripe", Timestamp: timestamp}, nil
}

func parseHeader(value string) (time.Time, [][]byte, error) {
	var timestamp time.Time
	var signatures [][]byte
	for _, component := range strings.Split(value, ",") {
		key, raw, found := strings.Cut(strings.TrimSpace(component), "=")
		if !found {
			continue
		}
		switch key {
		case "t":
			seconds, err := strconv.ParseInt(raw, 10, 64)
			if err != nil {
				return time.Time{}, nil, hookbound.NewError(hookbound.CodeInvalidSignature, "invalid Stripe timestamp", err)
			}
			timestamp = time.Unix(seconds, 0)
		case "v1":
			decoded, err := hex.DecodeString(raw)
			if err != nil {
				return time.Time{}, nil, hookbound.NewError(hookbound.CodeInvalidSignature, "invalid Stripe v1 signature", err)
			}
			signatures = append(signatures, decoded)
		}
	}
	if timestamp.IsZero() || len(signatures) == 0 || len(signatures) > 16 {
		return time.Time{}, nil, hookbound.NewError(hookbound.CodeInvalidSignature, "Stripe signature header is incomplete", nil)
	}
	return timestamp, signatures, nil
}
