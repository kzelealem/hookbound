package hookbound

import (
	"context"
	"net/http"
	"time"
)

// SignInput contains the exact bytes and attempt metadata to authenticate.
type SignInput struct {
	MessageID string
	Timestamp time.Time
	Body      []byte
	Headers   http.Header
}

// Signer adds cryptographic authentication headers to an outbound attempt.
type Signer interface {
	Sign(context.Context, SignInput) (http.Header, error)
}

// VerifyInput contains the exact received bytes and headers.
type VerifyInput struct {
	Headers    http.Header
	Body       []byte
	ReceivedAt time.Time
}

// Verification identifies a payload after successful cryptographic checking.
type Verification struct {
	ID        string
	Type      string
	Source    string
	Timestamp time.Time
	Metadata  map[string]string
}

// Verifier authenticates an inbound payload and extracts stable metadata.
type Verifier interface {
	Verify(context.Context, VerifyInput) (Verification, error)
}
