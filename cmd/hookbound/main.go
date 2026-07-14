package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hookbound/hookbound"
	"github.com/hookbound/hookbound/standard"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "hookbound:", err)
		os.Exit(1)
	}
}

func run(arguments []string, stdout, stderr io.Writer) error {
	if len(arguments) == 0 {
		printUsage(stderr)
		return errors.New("a command is required")
	}
	switch arguments[0] {
	case "version":
		_, err := fmt.Fprintf(stdout, "hookbound %s (commit %s, built %s)\n", version, commit, date)
		return err
	case "generate-secret":
		secret, err := standard.GenerateHMACSecret(rand.Reader)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, secret)
		return err
	case "generate-keypair":
		publicKey, privateKey, err := standard.GenerateEd25519KeyPair(rand.Reader)
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(map[string]string{
			"public_key": publicKey, "private_key": privateKey,
		})
	case "sign":
		return sign(arguments[1:], stdout, stderr)
	case "verify":
		return verify(arguments[1:], stdout, stderr)
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown command %q", arguments[0])
	}
}

func sign(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("sign", flag.ContinueOnError)
	flags.SetOutput(stderr)
	bodyPath := flags.String("body", "-", "payload file, or - for stdin")
	messageID := flags.String("id", "", "stable message ID; generated when omitted")
	timestamp := flags.Int64("timestamp", 0, "attempt timestamp as Unix seconds; defaults to now")
	secretEnv := flags.String("secret-env", "HOOKBOUND_SECRET", "environment variable containing a whsec_ key")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	secret, err := requiredEnvironment(*secretEnv)
	if err != nil {
		return err
	}
	keys, err := standard.StaticHMACKeys(secret)
	if err != nil {
		return err
	}
	signer, err := standard.NewHMACSigner(keys)
	if err != nil {
		return err
	}
	body, err := readBody(*bodyPath)
	if err != nil {
		return err
	}
	id := strings.TrimSpace(*messageID)
	if id == "" {
		id, err = (hookbound.RandomIDGenerator{}).NewMessageID()
		if err != nil {
			return err
		}
	}
	attemptedAt := time.Now().UTC()
	if *timestamp != 0 {
		attemptedAt = time.Unix(*timestamp, 0).UTC()
	}
	headers, err := signer.Sign(context.Background(), hookbound.SignInput{
		MessageID: id, Timestamp: attemptedAt, Body: body,
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(map[string]any{
		"message_id": id,
		"timestamp":  attemptedAt.Unix(),
		"headers":    headers,
	})
}

func verify(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	bodyPath := flags.String("body", "-", "payload file, or - for stdin")
	messageID := flags.String("id", "", "Webhook-Id header value")
	timestamp := flags.String("timestamp", "", "Webhook-Timestamp header value")
	signature := flags.String("signature", "", "Webhook-Signature header value")
	eventType := flags.String("type", "", "optional event type when the payload has no type field")
	tolerance := flags.Duration("tolerance", 5*time.Minute, "maximum timestamp skew")
	secretEnv := flags.String("secret-env", "HOOKBOUND_SECRET", "environment variable containing a whsec_ key")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	secret, err := requiredEnvironment(*secretEnv)
	if err != nil {
		return err
	}
	keys, err := standard.StaticHMACKeys(secret)
	if err != nil {
		return err
	}
	config := standard.VerifierConfig{HMACKeys: keys, Tolerance: *tolerance}
	if *eventType != "" {
		config.ExtractType = func([]byte, http.Header) (string, error) { return *eventType, nil }
	}
	verifier, err := standard.NewVerifier(config)
	if err != nil {
		return err
	}
	body, err := readBody(*bodyPath)
	if err != nil {
		return err
	}
	headers := make(http.Header)
	headers.Set(standard.HeaderID, *messageID)
	headers.Set(standard.HeaderTimestamp, *timestamp)
	headers.Set(standard.HeaderSignature, *signature)
	verification, err := verifier.Verify(context.Background(), hookbound.VerifyInput{
		Headers: headers, Body: body, ReceivedAt: time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(map[string]any{
		"valid":      true,
		"message_id": verification.ID,
		"event_type": verification.Type,
		"source":     verification.Source,
		"timestamp":  verification.Timestamp.Unix(),
	})
}

func readBody(path string) ([]byte, error) {
	if path == "" || path == "-" {
		return io.ReadAll(os.Stdin)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read body %q: %w", path, err)
	}
	return body, nil
}

func requiredEnvironment(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("secret environment variable name is required")
	}
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return "", fmt.Errorf("environment variable %s is empty", strconv.Quote(name))
	}
	return value, nil
}

func printUsage(writer io.Writer) {
	fmt.Fprintln(writer, `Hookbound — secure webhooks, both ways.

Usage:
  hookbound version
  hookbound generate-secret
  hookbound generate-keypair
  hookbound sign [--body payload.json] [--id msg_...] [--timestamp unix]
  hookbound verify --id msg_... --timestamp unix --signature v1,... [--body payload.json]

Signing secrets are read from HOOKBOUND_SECRET by default. Use --secret-env to
select another environment variable; secrets are intentionally not accepted as
command-line flag values.`)
}
