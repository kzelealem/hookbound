package standard

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/hookbound/hookbound"
)

func TestHMACSignAndVerify(t *testing.T) {
	secret, err := EncodeHMACSecret(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := StaticHMACKeys(secret)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewHMACSigner(keys)
	if err != nil {
		t.Fatal(err)
	}
	attemptedAt := time.Unix(1_674_087_231, 0)
	body := []byte(`{"type":"contact.created","data":{"id":"one"}}`)
	headers, err := signer.Sign(context.Background(), hookbound.SignInput{
		MessageID: "msg_test",
		Timestamp: attemptedAt,
		Body:      body,
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(VerifierConfig{HMACKeys: keys, Tolerance: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifier.Verify(context.Background(), hookbound.VerifyInput{
		Headers:    headers,
		Body:       body,
		ReceivedAt: attemptedAt.Add(30 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if verified.ID != "msg_test" || verified.Type != "contact.created" {
		t.Fatalf("unexpected verification: %#v", verified)
	}
}

func TestHMACRotation(t *testing.T) {
	oldSecret, _ := EncodeHMACSecret(bytes.Repeat([]byte{1}, 32))
	newSecret, _ := EncodeHMACSecret(bytes.Repeat([]byte{2}, 32))
	both, _ := StaticHMACKeys(newSecret, oldSecret)
	oldOnly, _ := StaticHMACKeys(oldSecret)
	signer, _ := NewHMACSigner(both)
	headers, err := signer.Sign(context.Background(), hookbound.SignInput{
		MessageID: "msg_rotation",
		Timestamp: time.Unix(100, 0),
		Body:      []byte(`{"type":"rotated"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier, _ := NewVerifier(VerifierConfig{HMACKeys: oldOnly, Tolerance: time.Hour})
	_, err = verifier.Verify(context.Background(), hookbound.VerifyInput{
		Headers:    headers,
		Body:       []byte(`{"type":"rotated"}`),
		ReceivedAt: time.Unix(100, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRejectsTamperedBodyAndExpiredTimestamp(t *testing.T) {
	secret, _ := EncodeHMACSecret(bytes.Repeat([]byte{3}, 32))
	keys, _ := StaticHMACKeys(secret)
	signer, _ := NewHMACSigner(keys)
	headers, _ := signer.Sign(context.Background(), hookbound.SignInput{
		MessageID: "msg_tamper",
		Timestamp: time.Unix(100, 0),
		Body:      []byte(`{"type":"safe"}`),
	})
	verifier, _ := NewVerifier(VerifierConfig{HMACKeys: keys, Tolerance: time.Minute})

	_, err := verifier.Verify(context.Background(), hookbound.VerifyInput{
		Headers: headers, Body: []byte(`{"type":"unsafe"}`), ReceivedAt: time.Unix(100, 0),
	})
	if hookbound.ErrorCode(err) != hookbound.CodeInvalidSignature {
		t.Fatalf("unexpected tamper error: %v", err)
	}
	_, err = verifier.Verify(context.Background(), hookbound.VerifyInput{
		Headers: headers, Body: []byte(`{"type":"safe"}`), ReceivedAt: time.Unix(1000, 0),
	})
	if hookbound.ErrorCode(err) != hookbound.CodeExpiredSignature {
		t.Fatalf("unexpected expiry error: %v", err)
	}
}

func TestEd25519SignAndVerify(t *testing.T) {
	seed := bytes.Repeat([]byte{9}, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	signer, err := NewEd25519Signer(private)
	if err != nil {
		t.Fatal(err)
	}
	headers, err := signer.Sign(context.Background(), hookbound.SignInput{
		MessageID: "msg_asymmetric",
		Timestamp: time.Unix(500, 0),
		Body:      []byte(`{"type":"secure.event"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(VerifierConfig{
		PublicKeys: func(context.Context) ([]ed25519.PublicKey, error) { return []ed25519.PublicKey{public}, nil },
		Tolerance:  time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(context.Background(), hookbound.VerifyInput{
		Headers: headers, Body: []byte(`{"type":"secure.event"}`), ReceivedAt: time.Unix(500, 0),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestKnownHMACShape(t *testing.T) {
	key := bytes.Repeat([]byte{4}, 32)
	secret, _ := EncodeHMACSecret(key)
	parsed, err := ParseHMACSecret(secret)
	if err != nil || !bytes.Equal(parsed, key) {
		t.Fatalf("round trip failed: %v", err)
	}
	keys, _ := StaticHMACKeys(secret)
	signer, _ := NewHMACSigner(keys)
	headers, err := signer.Sign(context.Background(), hookbound.SignInput{
		MessageID: "msg_known", Timestamp: time.Unix(42, 0), Body: []byte("{}"),
	})
	if err != nil {
		t.Fatal(err)
	}
	value := headers.Get(HeaderSignature)
	if len(value) < 4 || value[:3] != "v1," {
		t.Fatalf("unexpected signature: %s", value)
	}
	if _, err := base64.StdEncoding.DecodeString(value[3:]); err != nil {
		t.Fatal(err)
	}
}

func TestDuplicateIdentityHeaderRejected(t *testing.T) {
	secret, _ := EncodeHMACSecret(bytes.Repeat([]byte{5}, 32))
	keys, _ := StaticHMACKeys(secret)
	verifier, _ := NewHMACVerifier(keys)
	headers := http.Header{
		HeaderID:        {"msg_one", "msg_two"},
		HeaderTimestamp: {"100"},
		HeaderSignature: {"v1," + base64.StdEncoding.EncodeToString(make([]byte, 32))},
	}
	_, err := verifier.Verify(context.Background(), hookbound.VerifyInput{Headers: headers, Body: []byte("{}"), ReceivedAt: time.Unix(100, 0)})
	if hookbound.ErrorCode(err) != hookbound.CodeInvalidSignature {
		t.Fatalf("unexpected error: %v", err)
	}
}

func FuzzSignatureParser(f *testing.F) {
	f.Add("v1,K5oZfzN95Z9UVu1EsfQmfVNQhnkZ2pj9o9NDN/H/pI4=")
	f.Add("")
	f.Fuzz(func(t *testing.T, value string) {
		_, _ = parseSignatures(value)
	})
}

func TestVerifierRejectsFarFutureTimestampWithoutDurationOverflow(t *testing.T) {
	secret, _ := EncodeHMACSecret(bytes.Repeat([]byte{1}, 32))
	keys, _ := StaticHMACKeys(secret)
	signer, _ := NewHMACSigner(keys)
	verifier, _ := NewVerifier(VerifierConfig{HMACKeys: keys, Tolerance: 5 * time.Minute, AllowNoType: true})
	future := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	body := []byte(`{}`)
	headers, err := signer.Sign(context.Background(), hookbound.SignInput{MessageID: "msg_future", Timestamp: future, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifier.Verify(context.Background(), hookbound.VerifyInput{
		Headers:    headers,
		Body:       body,
		ReceivedAt: time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC),
	})
	if hookbound.ErrorCode(err) != hookbound.CodeExpiredSignature {
		t.Fatalf("expected expired signature, got %v", err)
	}
}

func TestVerifierRejectsExcessivePublicKeyRotationSet(t *testing.T) {
	verifier, err := NewVerifier(VerifierConfig{
		PublicKeys: func(context.Context) ([]ed25519.PublicKey, error) {
			return make([]ed25519.PublicKey, 17), nil
		},
		AllowNoType: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	headers := http.Header{
		HeaderID:        {"msg_keys"},
		HeaderTimestamp: {"1000"},
		HeaderSignature: {"v1a," + base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))},
	}
	_, err = verifier.Verify(context.Background(), hookbound.VerifyInput{Headers: headers, Body: []byte(`{}`), ReceivedAt: time.Unix(1000, 0)})
	if hookbound.ErrorCode(err) != hookbound.CodeInvalidConfiguration {
		t.Fatalf("expected invalid configuration, got %v", err)
	}
}

func TestJSONTypeFieldRejectsTrailingData(t *testing.T) {
	_, err := JSONTypeField([]byte(`{"type":"invoice.paid"} trailing`), nil)
	if hookbound.ErrorCode(err) != hookbound.CodeDecode {
		t.Fatalf("expected decode failure, got %v", err)
	}
}

func TestEd25519SignerRejectsExcessiveRotationSet(t *testing.T) {
	signers := make([]crypto.Signer, 17)
	for index := range signers {
		_, private, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		signers[index] = private
	}
	if _, err := NewEd25519Signer(signers...); hookbound.ErrorCode(err) != hookbound.CodeInvalidConfiguration {
		t.Fatalf("expected invalid configuration, got %v", err)
	}
}
