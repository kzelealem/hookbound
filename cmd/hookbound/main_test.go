package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestGenerateSecret(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"generate-secret"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.TrimSpace(stdout.String()), "whsec_") {
		t.Fatalf("unexpected secret: %q", stdout.String())
	}
}

func TestGenerateKeyPair(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"generate-keypair"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var result map[string]string
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(result["public_key"], "whpk_") || !strings.HasPrefix(result["private_key"], "whsk_") {
		t.Fatalf("unexpected key pair: %#v", result)
	}
}

func TestSignThenVerify(t *testing.T) {
	secretOutput := new(bytes.Buffer)
	if err := run([]string{"generate-secret"}, secretOutput, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOOKBOUND_TEST_SECRET", strings.TrimSpace(secretOutput.String()))
	bodyFile := t.TempDir() + "/payload.json"
	if err := os.WriteFile(bodyFile, []byte(`{"type":"invoice.paid.v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var signed bytes.Buffer
	if err := run([]string{"sign", "--secret-env", "HOOKBOUND_TEST_SECRET", "--body", bodyFile, "--id", "msg_cli_test"}, &signed, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		MessageID string              `json:"message_id"`
		Timestamp int64               `json:"timestamp"`
		Headers   map[string][]string `json:"headers"`
	}
	if err := json.Unmarshal(signed.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	var verified bytes.Buffer
	if err := run([]string{
		"verify", "--secret-env", "HOOKBOUND_TEST_SECRET", "--body", bodyFile,
		"--id", envelope.MessageID,
		"--timestamp", strconv.FormatInt(envelope.Timestamp, 10),
		"--signature", envelope.Headers["Webhook-Signature"][0],
		"--type", "invoice.paid.v1",
	}, &verified, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(verified.String(), `"valid":true`) {
		t.Fatalf("unexpected verification output: %s", verified.String())
	}
}

func TestVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"version"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "hookbound") {
		t.Fatalf("unexpected version output: %q", stdout.String())
	}
}
