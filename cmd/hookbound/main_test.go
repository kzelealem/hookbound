package main

import (
	"bytes"
	"encoding/json"
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

func TestVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"version"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "hookbound") {
		t.Fatalf("unexpected version output: %q", stdout.String())
	}
}
