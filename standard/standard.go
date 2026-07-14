// Package standard implements the Standard Webhooks signature profile using
// only Go's standard cryptography packages.
package standard

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hookbound/hookbound"
)

const (
	HeaderID        = "Webhook-Id"
	HeaderTimestamp = "Webhook-Timestamp"
	HeaderSignature = "Webhook-Signature"

	HMACSecretPrefix   = "whsec_"
	PrivateKeyPrefix   = "whsk_"
	PublicKeyPrefix    = "whpk_"
	hmacSignatureID    = "v1"
	ed25519SignatureID = "v1a"
)

var rawBase64 = base64.RawStdEncoding

// HMACKeyProvider resolves active signing or verification keys at request
// time. Returning more than one key enables zero-downtime rotation.
type HMACKeyProvider interface {
	HMACKeys(context.Context) ([][]byte, error)
}

type HMACKeyProviderFunc func(context.Context) ([][]byte, error)

func (f HMACKeyProviderFunc) HMACKeys(ctx context.Context) ([][]byte, error) {
	return f(ctx)
}

type staticHMACKeys struct{ keys [][]byte }

func (s staticHMACKeys) HMACKeys(context.Context) ([][]byte, error) {
	return cloneKeys(s.keys), nil
}

// StaticHMACKeys parses serialized whsec_ keys and returns an immutable key
// provider suitable for signing or verification.
func StaticHMACKeys(secrets ...string) (HMACKeyProvider, error) {
	if len(secrets) == 0 {
		return nil, hookbound.NewError(hookbound.CodeInvalidConfiguration, "at least one HMAC key is required", nil)
	}
	keys := make([][]byte, 0, len(secrets))
	for _, secret := range secrets {
		key, err := ParseHMACSecret(secret)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return staticHMACKeys{keys: keys}, nil
}

func ParseHMACSecret(value string) ([]byte, error) {
	encoded := strings.TrimSpace(value)
	if strings.HasPrefix(encoded, HMACSecretPrefix) {
		encoded = strings.TrimPrefix(encoded, HMACSecretPrefix)
	}
	key, err := decodeBase64(encoded)
	if err != nil {
		return nil, hookbound.NewError(hookbound.CodeInvalidConfiguration, "decode Standard Webhooks HMAC key", err)
	}
	if len(key) < 24 || len(key) > 64 {
		return nil, hookbound.NewError(hookbound.CodeInvalidConfiguration, "HMAC key must contain 24 to 64 bytes", nil)
	}
	return key, nil
}

func EncodeHMACSecret(key []byte) (string, error) {
	if len(key) < 24 || len(key) > 64 {
		return "", hookbound.NewError(hookbound.CodeInvalidConfiguration, "HMAC key must contain 24 to 64 bytes", nil)
	}
	return HMACSecretPrefix + rawBase64.EncodeToString(key), nil
}

func GenerateHMACSecret(reader io.Reader) (string, error) {
	if reader == nil {
		reader = rand.Reader
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		return "", hookbound.NewError(hookbound.CodeInternal, "generate HMAC key", err)
	}
	return EncodeHMACSecret(key)
}

// HMACSigner signs attempts using all active keys.
type HMACSigner struct{ provider HMACKeyProvider }

func NewHMACSigner(provider HMACKeyProvider) (*HMACSigner, error) {
	if provider == nil {
		return nil, hookbound.NewError(hookbound.CodeInvalidConfiguration, "HMAC key provider is required", nil)
	}
	return &HMACSigner{provider: provider}, nil
}

func (s *HMACSigner) Sign(ctx context.Context, input hookbound.SignInput) (http.Header, error) {
	if s == nil || s.provider == nil {
		return nil, hookbound.NewError(hookbound.CodeInvalidConfiguration, "HMAC signer is not configured", nil)
	}
	if err := hookbound.ValidateMessageID(input.MessageID); err != nil {
		return nil, err
	}
	if input.Timestamp.IsZero() {
		return nil, hookbound.NewError(hookbound.CodeInvalidMessage, "attempt timestamp is required", nil)
	}
	keys, err := s.provider.HMACKeys(ctx)
	if err != nil {
		return nil, hookbound.NewError(hookbound.CodeInternal, "resolve HMAC signing keys", err)
	}
	if err := validateHMACKeys(keys); err != nil {
		return nil, err
	}

	timestamp := strconv.FormatInt(input.Timestamp.Unix(), 10)
	content := signedContent(input.MessageID, timestamp, input.Body)
	signatures := make([]string, 0, len(keys))
	for _, key := range keys {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(content)
		signatures = append(signatures, hmacSignatureID+","+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	}
	return http.Header{
		HeaderID:        {input.MessageID},
		HeaderTimestamp: {timestamp},
		HeaderSignature: {strings.Join(signatures, " ")},
	}, nil
}

// Ed25519Signer signs attempts through crypto.Signer, which permits local keys
// and KMS/HSM-backed implementations.
type Ed25519Signer struct{ signers []crypto.Signer }

func NewEd25519Signer(signers ...crypto.Signer) (*Ed25519Signer, error) {
	if len(signers) == 0 {
		return nil, hookbound.NewError(hookbound.CodeInvalidConfiguration, "at least one Ed25519 signer is required", nil)
	}
	for _, signer := range signers {
		if signer == nil {
			return nil, hookbound.NewError(hookbound.CodeInvalidConfiguration, "Ed25519 signer is nil", nil)
		}
		if _, ok := signer.Public().(ed25519.PublicKey); !ok {
			return nil, hookbound.NewError(hookbound.CodeInvalidConfiguration, "signer does not expose an Ed25519 public key", nil)
		}
	}
	return &Ed25519Signer{signers: append([]crypto.Signer(nil), signers...)}, nil
}

func (s *Ed25519Signer) Sign(_ context.Context, input hookbound.SignInput) (http.Header, error) {
	if s == nil || len(s.signers) == 0 {
		return nil, hookbound.NewError(hookbound.CodeInvalidConfiguration, "Ed25519 signer is not configured", nil)
	}
	if err := hookbound.ValidateMessageID(input.MessageID); err != nil {
		return nil, err
	}
	if input.Timestamp.IsZero() {
		return nil, hookbound.NewError(hookbound.CodeInvalidMessage, "attempt timestamp is required", nil)
	}

	timestamp := strconv.FormatInt(input.Timestamp.Unix(), 10)
	content := signedContent(input.MessageID, timestamp, input.Body)
	signatures := make([]string, 0, len(s.signers))
	for _, signer := range s.signers {
		signature, err := signer.Sign(rand.Reader, content, crypto.Hash(0))
		if err != nil {
			return nil, hookbound.NewError(hookbound.CodeInternal, "sign with Ed25519 key", err)
		}
		signatures = append(signatures, ed25519SignatureID+","+base64.StdEncoding.EncodeToString(signature))
	}
	return http.Header{
		HeaderID:        {input.MessageID},
		HeaderTimestamp: {timestamp},
		HeaderSignature: {strings.Join(signatures, " ")},
	}, nil
}

// EventTypeExtractor derives an application event type after signature
// verification. It must not be used to decide whether a payload is authentic.
type EventTypeExtractor func([]byte, http.Header) (string, error)

func JSONTypeField(body []byte, _ http.Header) (string, error) {
	var envelope struct {
		Type string `json:"type"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&envelope); err != nil {
		return "", hookbound.NewError(hookbound.CodeDecode, "decode Standard Webhooks event type", err)
	}
	if err := hookbound.ValidateEventType(envelope.Type); err != nil {
		return "", err
	}
	return envelope.Type, nil
}

type VerifierConfig struct {
	HMACKeys    HMACKeyProvider
	PublicKeys  func(context.Context) ([]ed25519.PublicKey, error)
	Tolerance   time.Duration
	Source      string
	ExtractType EventTypeExtractor
	AllowNoType bool
}

type Verifier struct{ config VerifierConfig }

func NewVerifier(config VerifierConfig) (*Verifier, error) {
	if config.HMACKeys == nil && config.PublicKeys == nil {
		return nil, hookbound.NewError(hookbound.CodeInvalidConfiguration, "verification keys are required", nil)
	}
	if config.Tolerance == 0 {
		config.Tolerance = 5 * time.Minute
	}
	if config.Tolerance < 0 {
		return nil, hookbound.NewError(hookbound.CodeInvalidConfiguration, "signature tolerance cannot be negative", nil)
	}
	if config.Source == "" {
		config.Source = "standard-webhooks"
	}
	if config.ExtractType == nil && !config.AllowNoType {
		config.ExtractType = JSONTypeField
	}
	return &Verifier{config: config}, nil
}

func NewHMACVerifier(provider HMACKeyProvider) (*Verifier, error) {
	return NewVerifier(VerifierConfig{HMACKeys: provider})
}

func (v *Verifier) Verify(ctx context.Context, input hookbound.VerifyInput) (hookbound.Verification, error) {
	if v == nil {
		return hookbound.Verification{}, hookbound.NewError(hookbound.CodeInvalidConfiguration, "verifier is nil", nil)
	}
	messageID, err := singleHeader(input.Headers, HeaderID)
	if err != nil {
		return hookbound.Verification{}, err
	}
	if err := hookbound.ValidateMessageID(messageID); err != nil {
		return hookbound.Verification{}, err
	}
	timestampText, err := singleHeader(input.Headers, HeaderTimestamp)
	if err != nil {
		return hookbound.Verification{}, err
	}
	timestampSeconds, err := strconv.ParseInt(timestampText, 10, 64)
	if err != nil {
		return hookbound.Verification{}, hookbound.NewError(hookbound.CodeInvalidSignature, "invalid webhook timestamp", err)
	}
	timestamp := time.Unix(timestampSeconds, 0)
	receivedAt := input.ReceivedAt
	if receivedAt.IsZero() {
		receivedAt = time.Now()
	}
	if tolerance := v.config.Tolerance; tolerance > 0 && outsideTolerance(receivedAt, timestamp, tolerance) {
		return hookbound.Verification{}, hookbound.NewError(hookbound.CodeExpiredSignature, "webhook timestamp is outside the allowed tolerance", nil)
	}

	signatureValues := input.Headers.Values(HeaderSignature)
	if len(signatureValues) == 0 {
		return hookbound.Verification{}, hookbound.NewError(hookbound.CodeInvalidSignature, "webhook signature is required", nil)
	}
	signatures, err := parseSignatures(strings.Join(signatureValues, " "))
	if err != nil {
		return hookbound.Verification{}, err
	}
	content := signedContent(messageID, timestampText, input.Body)
	valid, err := v.verifyAny(ctx, content, signatures)
	if err != nil {
		return hookbound.Verification{}, err
	}
	if !valid {
		return hookbound.Verification{}, hookbound.NewError(hookbound.CodeInvalidSignature, "webhook signature did not match a trusted key", nil)
	}

	eventType := "unknown"
	if v.config.ExtractType != nil {
		eventType, err = v.config.ExtractType(input.Body, input.Headers.Clone())
		if err != nil {
			return hookbound.Verification{}, err
		}
	}
	return hookbound.Verification{
		ID:        messageID,
		Type:      eventType,
		Source:    v.config.Source,
		Timestamp: timestamp,
	}, nil
}

func (v *Verifier) verifyAny(ctx context.Context, content []byte, signatures []parsedSignature) (bool, error) {
	valid := 0
	if v.config.HMACKeys != nil {
		keys, err := v.config.HMACKeys.HMACKeys(ctx)
		if err != nil {
			return false, hookbound.NewError(hookbound.CodeInternal, "resolve HMAC verification keys", err)
		}
		if err := validateHMACKeys(keys); err != nil {
			return false, err
		}
		for _, key := range keys {
			mac := hmac.New(sha256.New, key)
			_, _ = mac.Write(content)
			expected := mac.Sum(nil)
			for _, signature := range signatures {
				if signature.version == hmacSignatureID && len(signature.value) == len(expected) {
					valid |= subtle.ConstantTimeCompare(signature.value, expected)
				}
			}
		}
	}
	if v.config.PublicKeys != nil {
		keys, err := v.config.PublicKeys(ctx)
		if err != nil {
			return false, hookbound.NewError(hookbound.CodeInternal, "resolve Ed25519 verification keys", err)
		}
		if len(keys) == 0 || len(keys) > 16 {
			return false, hookbound.NewError(hookbound.CodeInvalidConfiguration, "between one and sixteen Ed25519 public keys are required", nil)
		}
		for _, key := range keys {
			if len(key) != ed25519.PublicKeySize {
				return false, hookbound.NewError(hookbound.CodeInvalidConfiguration, "invalid Ed25519 public key length", nil)
			}
			for _, signature := range signatures {
				if signature.version == ed25519SignatureID && ed25519.Verify(key, content, signature.value) {
					valid = 1
				}
			}
		}
	}
	return valid == 1, nil
}

func EncodePrivateKey(key ed25519.PrivateKey) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", hookbound.NewError(hookbound.CodeInvalidConfiguration, "invalid Ed25519 private key length", nil)
	}
	return PrivateKeyPrefix + rawBase64.EncodeToString(key), nil
}

func ParsePrivateKey(value string) (ed25519.PrivateKey, error) {
	encoded := strings.TrimPrefix(strings.TrimSpace(value), PrivateKeyPrefix)
	decoded, err := decodeBase64(encoded)
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, hookbound.NewError(hookbound.CodeInvalidConfiguration, "invalid Ed25519 private key", err)
	}
	return ed25519.PrivateKey(decoded), nil
}

func EncodePublicKey(key ed25519.PublicKey) (string, error) {
	if len(key) != ed25519.PublicKeySize {
		return "", hookbound.NewError(hookbound.CodeInvalidConfiguration, "invalid Ed25519 public key length", nil)
	}
	return PublicKeyPrefix + rawBase64.EncodeToString(key), nil
}

func ParsePublicKey(value string) (ed25519.PublicKey, error) {
	encoded := strings.TrimPrefix(strings.TrimSpace(value), PublicKeyPrefix)
	decoded, err := decodeBase64(encoded)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, hookbound.NewError(hookbound.CodeInvalidConfiguration, "invalid Ed25519 public key", err)
	}
	return ed25519.PublicKey(decoded), nil
}

func GenerateEd25519KeyPair(reader io.Reader) (publicKey, privateKey string, err error) {
	if reader == nil {
		reader = rand.Reader
	}
	public, private, err := ed25519.GenerateKey(reader)
	if err != nil {
		return "", "", hookbound.NewError(hookbound.CodeInternal, "generate Ed25519 key pair", err)
	}
	publicEncoded, err := EncodePublicKey(public)
	if err != nil {
		return "", "", err
	}
	privateEncoded, err := EncodePrivateKey(private)
	if err != nil {
		return "", "", err
	}
	return publicEncoded, privateEncoded, nil
}

func outsideTolerance(receivedAt, timestamp time.Time, tolerance time.Duration) bool {
	if timestamp.After(receivedAt) {
		return timestamp.Sub(receivedAt) > tolerance
	}
	return receivedAt.Sub(timestamp) > tolerance
}

type parsedSignature struct {
	version string
	value   []byte
}

func parseSignatures(value string) ([]parsedSignature, error) {
	fields := strings.Fields(value)
	if len(fields) == 0 || len(fields) > 32 {
		return nil, hookbound.NewError(hookbound.CodeInvalidSignature, "invalid number of webhook signatures", nil)
	}
	parsed := make([]parsedSignature, 0, len(fields))
	for _, field := range fields {
		version, encoded, found := strings.Cut(field, ",")
		if !found || encoded == "" || len(encoded) > 256 {
			return nil, hookbound.NewError(hookbound.CodeInvalidSignature, "malformed webhook signature", nil)
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, hookbound.NewError(hookbound.CodeInvalidSignature, "decode webhook signature", err)
		}
		parsed = append(parsed, parsedSignature{version: version, value: decoded})
	}
	return parsed, nil
}

func singleHeader(headers http.Header, name string) (string, error) {
	values := headers.Values(name)
	if len(values) != 1 || strings.TrimSpace(values[0]) == "" {
		return "", hookbound.NewError(hookbound.CodeInvalidSignature, fmt.Sprintf("exactly one %s header is required", name), nil)
	}
	value := strings.TrimSpace(values[0])
	if strings.ContainsAny(value, "\r\n\x00") {
		return "", hookbound.NewError(hookbound.CodeInvalidSignature, fmt.Sprintf("invalid %s header", name), nil)
	}
	return value, nil
}

func signedContent(messageID, timestamp string, body []byte) []byte {
	content := make([]byte, 0, len(messageID)+len(timestamp)+len(body)+2)
	content = append(content, messageID...)
	content = append(content, '.')
	content = append(content, timestamp...)
	content = append(content, '.')
	content = append(content, body...)
	return content
}

func validateHMACKeys(keys [][]byte) error {
	if len(keys) == 0 || len(keys) > 16 {
		return hookbound.NewError(hookbound.CodeInvalidConfiguration, "between one and sixteen HMAC keys are required", nil)
	}
	for _, key := range keys {
		if len(key) < 24 || len(key) > 64 {
			return hookbound.NewError(hookbound.CodeInvalidConfiguration, "HMAC key must contain 24 to 64 bytes", nil)
		}
	}
	return nil
}

func cloneKeys(keys [][]byte) [][]byte {
	clone := make([][]byte, len(keys))
	for index, key := range keys {
		clone[index] = append([]byte(nil), key...)
	}
	return clone
}

func decodeBase64(value string) ([]byte, error) {
	for _, encoding := range []*base64.Encoding{base64.RawStdEncoding, base64.StdEncoding, base64.RawURLEncoding, base64.URLEncoding} {
		decoded, err := encoding.DecodeString(value)
		if err == nil {
			return decoded, nil
		}
	}
	return nil, errors.New("invalid base64")
}
