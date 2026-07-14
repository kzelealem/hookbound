// Package github verifies inbound GitHub webhooks without importing the
// complete GitHub SDK.
package github

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/kzelealem/hookbound"
)

const (
	HeaderDelivery  = "X-Github-Delivery"
	HeaderEvent     = "X-Github-Event"
	HeaderSignature = "X-Hub-Signature-256"
)

type Verifier struct {
	Secret        hookbound.SecretProvider
	IncludeAction bool
}

func NewVerifier(secret hookbound.SecretProvider) (*Verifier, error) {
	if secret == nil {
		return nil, hookbound.NewError(hookbound.CodeInvalidConfiguration, "GitHub webhook secret is required", nil)
	}
	return &Verifier{Secret: secret, IncludeAction: true}, nil
}

func (v *Verifier) Verify(ctx context.Context, input hookbound.VerifyInput) (hookbound.Verification, error) {
	if v == nil || v.Secret == nil {
		return hookbound.Verification{}, hookbound.NewError(hookbound.CodeInvalidConfiguration, "GitHub verifier is not configured", nil)
	}
	delivery, err := single(input.Headers, HeaderDelivery)
	if err != nil {
		return hookbound.Verification{}, err
	}
	if err := hookbound.ValidateMessageID(delivery); err != nil {
		return hookbound.Verification{}, err
	}
	event, err := single(input.Headers, HeaderEvent)
	if err != nil {
		return hookbound.Verification{}, err
	}
	signature, err := single(input.Headers, HeaderSignature)
	if err != nil {
		return hookbound.Verification{}, err
	}
	encoded, found := strings.CutPrefix(signature, "sha256=")
	if !found || len(encoded) != sha256.Size*2 {
		return hookbound.Verification{}, hookbound.NewError(hookbound.CodeInvalidSignature, "invalid GitHub signature format", nil)
	}
	received, err := hex.DecodeString(encoded)
	if err != nil {
		return hookbound.Verification{}, hookbound.NewError(hookbound.CodeInvalidSignature, "decode GitHub signature", err)
	}
	secret, err := v.Secret.Secret(ctx)
	if err != nil || secret == "" {
		return hookbound.Verification{}, hookbound.NewError(hookbound.CodeInternal, "resolve GitHub webhook secret", err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(input.Body)
	if subtle.ConstantTimeCompare(received, mac.Sum(nil)) != 1 {
		return hookbound.Verification{}, hookbound.NewError(hookbound.CodeInvalidSignature, "GitHub signature did not match", nil)
	}

	eventType := event
	metadata := map[string]string{"github_event": event}
	if v.IncludeAction {
		var envelope struct {
			Action string `json:"action"`
		}
		if json.Unmarshal(input.Body, &envelope) == nil && envelope.Action != "" {
			eventType += "." + envelope.Action
			metadata["github_action"] = envelope.Action
		}
	}
	if err := hookbound.ValidateEventType(eventType); err != nil {
		return hookbound.Verification{}, err
	}
	return hookbound.Verification{
		ID: delivery, Type: eventType, Source: "github", Timestamp: input.ReceivedAt, Metadata: metadata,
	}, nil
}

func single(headers http.Header, name string) (string, error) {
	values := headers.Values(name)
	if len(values) != 1 || strings.TrimSpace(values[0]) == "" || strings.ContainsAny(values[0], "\r\n\x00") {
		return "", hookbound.NewError(hookbound.CodeInvalidSignature, "required GitHub webhook header is missing or ambiguous", nil)
	}
	return strings.TrimSpace(values[0]), nil
}
