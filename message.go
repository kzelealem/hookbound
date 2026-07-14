package hookbound

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Message contains a verified inbound payload decoded into T. Raw always
// contains the exact bytes that were cryptographically verified.
type Message[T any] struct {
	ID          string
	Type        string
	Source      string
	Timestamp   time.Time
	Data        T
	Raw         []byte
	ContentType string
	Headers     http.Header
	Metadata    map[string]string
}

// VerifiedMessage is the immutable transport representation passed between a
// verifier, receiver, and handler. Clone it before retaining it beyond a call.
type VerifiedMessage struct {
	ID          string
	Type        string
	Source      string
	Timestamp   time.Time
	Body        []byte
	ContentType string
	Headers     http.Header
	Metadata    map[string]string
}

func (m VerifiedMessage) Clone() VerifiedMessage {
	return VerifiedMessage{
		ID:          m.ID,
		Type:        m.Type,
		Source:      m.Source,
		Timestamp:   m.Timestamp,
		Body:        bytes.Clone(m.Body),
		ContentType: m.ContentType,
		Headers:     m.Headers.Clone(),
		Metadata:    cloneStringMap(m.Metadata),
	}
}

func (m VerifiedMessage) Validate() error {
	if err := ValidateMessageID(m.ID); err != nil {
		return err
	}
	if err := ValidateEventType(m.Type); err != nil {
		return err
	}
	if strings.TrimSpace(m.Source) == "" {
		return NewError(CodeInvalidMessage, "message source is required", nil)
	}
	return nil
}

// SendRequest describes one direct or durable webhook delivery. Body is sent
// exactly as supplied and must not be mutated while Send is in progress.
type SendRequest struct {
	ID          string
	URL         string
	EventType   string
	Body        []byte
	ContentType string
	Headers     http.Header
	Auth        Authenticator
}

func (r SendRequest) Validate() error {
	if r.ID != "" {
		if err := ValidateMessageID(r.ID); err != nil {
			return err
		}
	}
	if err := ValidateEventType(r.EventType); err != nil {
		return err
	}
	if strings.TrimSpace(r.URL) == "" {
		return NewError(CodeInvalidURL, "destination URL is required", nil)
	}
	if strings.ContainsAny(r.ContentType, "\r\n\x00") {
		return NewError(CodeInvalidMessage, "content type contains forbidden characters", nil)
	}
	return validateHeaders(r.Headers)
}

func validateHeaders(headers http.Header) error {
	for name, values := range headers {
		if !validHeaderName(name) {
			return NewError(CodeInvalidMessage, "invalid HTTP header name", nil)
		}
		switch strings.ToLower(name) {
		case "host", "content-length", "connection", "transfer-encoding":
			return NewError(CodeInvalidMessage, "HTTP header cannot be set by webhook payload", nil)
		}
		for _, value := range values {
			for index := 0; index < len(value); index++ {
				character := value[index]
				if character == '\t' || character >= 0x20 && character != 0x7f {
					continue
				}
				return NewError(CodeInvalidMessage, "HTTP header value contains forbidden characters", nil)
			}
		}
	}
	return nil
}

func validHeaderName(name string) bool {
	if name == "" || strings.TrimSpace(name) != name {
		return false
	}
	for index := 0; index < len(name); index++ {
		character := name[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(character)) {
			continue
		}
		return false
	}
	return true
}

// JSONBody serializes a value once and returns the exact bytes to store, sign,
// and send. Encoding errors are wrapped with CodeInvalidMessage.
func JSONBody(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, NewError(CodeInvalidMessage, "encode JSON payload", err)
	}
	body := bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'})
	return bytes.Clone(body), nil
}

func ValidateEventType(eventType string) error {
	if eventType == "" {
		return NewError(CodeInvalidMessage, "event type is required", nil)
	}
	if len(eventType) > 200 {
		return NewError(CodeInvalidMessage, "event type is too long", nil)
	}
	for _, r := range eventType {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			continue
		}
		return NewError(CodeInvalidMessage, "event type contains unsupported characters", nil)
	}
	return nil
}

func cloneStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	clone := make(map[string]string, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}
