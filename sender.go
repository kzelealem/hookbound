package hookbound

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hookbound/hookbound/transport"
)

const defaultUserAgent = "hookbound-go/0.1"

// SenderConfig configures one-attempt outbound delivery.
type SenderConfig struct {
	Signer        Signer
	Authenticator Authenticator
	NetworkPolicy transport.Policy
	// UnsafeHTTPClient bypasses Hookbound's DNS/IP dial enforcement. Prefer
	// NetworkPolicy. This escape hatch is intended for trusted, application-
	// controlled destinations and specialized test transports only.
	UnsafeHTTPClient *http.Client
	Clock            Clock
	IDGenerator      IDGenerator
	Classifier       Classifier
	Timeout          time.Duration
	MaxResponseBytes int64
	UserAgent        string
}

// Sender performs exactly one external HTTP attempt for each Send call.
type Sender struct {
	signer        Signer
	authenticator Authenticator
	client        *http.Client
	clock         Clock
	ids           IDGenerator
	classifier    Classifier
	maxResponse   int64
	userAgent     string
	networkPolicy transport.Policy
}

func NewSender(config SenderConfig) (*Sender, error) {
	if config.Signer == nil {
		return nil, NewError(CodeInvalidConfiguration, "signer is required", nil)
	}
	client := config.UnsafeHTTPClient
	if client == nil {
		client = transport.NewClient(config.NetworkPolicy)
	} else if client.CheckRedirect == nil {
		// Clone the client value so the caller's object is not mutated.
		clone := *client
		clone.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
		client = &clone
	}
	if config.Timeout <= 0 {
		config.Timeout = 20 * time.Second
	}
	if client.Timeout == 0 {
		clone := *client
		clone.Timeout = config.Timeout
		client = &clone
	}
	if config.MaxResponseBytes <= 0 {
		config.MaxResponseBytes = 64 << 10
	}
	if config.UserAgent == "" {
		config.UserAgent = defaultUserAgent
	}
	classifier := config.Classifier
	if classifier == nil {
		classifier = DefaultClassifier{}
	}
	return &Sender{
		signer:        config.Signer,
		authenticator: config.Authenticator,
		client:        client,
		clock:         clockOrSystem(config.Clock),
		ids:           idGeneratorOrRandom(config.IDGenerator),
		classifier:    classifier,
		maxResponse:   config.MaxResponseBytes,
		userAgent:     config.UserAgent,
		networkPolicy: config.NetworkPolicy,
	}, nil
}

func (s *Sender) Send(ctx context.Context, request SendRequest) (AttemptResult, error) {
	if s == nil {
		return AttemptResult{}, NewError(CodeInvalidConfiguration, "sender is nil", nil)
	}
	if err := request.Validate(); err != nil {
		return AttemptResult{}, err
	}
	if request.ID == "" {
		id, err := s.ids.NewMessageID()
		if err != nil {
			return AttemptResult{}, err
		}
		request.ID = id
	}
	if _, err := transport.ValidateURL(request.URL, s.networkPolicy); err != nil {
		return AttemptResult{}, NewError(CodeUnsafeDestination, "destination URL is not permitted", err)
	}

	attemptedAt := s.clock.Now().UTC()
	result := AttemptResult{MessageID: request.ID, AttemptedAt: attemptedAt}
	body := bytes.Clone(request.Body)
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, request.URL, bytes.NewReader(body))
	if err != nil {
		return result, NewError(CodeInvalidURL, "create webhook request", err)
	}
	if err := copyHeaders(httpRequest.Header, request.Headers); err != nil {
		return result, err
	}
	contentType := request.ContentType
	if contentType == "" {
		contentType = "application/json"
	}
	httpRequest.Header.Set("Content-Type", contentType)
	httpRequest.Header.Set("User-Agent", s.userAgent)
	httpRequest.Header.Set("X-Hookbound-Event", request.EventType)

	signedHeaders, err := s.signer.Sign(ctx, SignInput{
		MessageID: request.ID,
		Timestamp: attemptedAt,
		Body:      body,
		Headers:   httpRequest.Header.Clone(),
	})
	if err != nil {
		return result, err
	}
	if err := copyHeaders(httpRequest.Header, signedHeaders); err != nil {
		return result, err
	}
	authenticator := request.Auth
	if authenticator == nil {
		authenticator = s.authenticator
	}
	if authenticator != nil {
		if err := authenticator.Apply(ctx, httpRequest); err != nil {
			return result, err
		}
	}

	started := time.Now()
	response, transportErr := s.client.Do(httpRequest)
	result.Duration = time.Since(started)
	outcome, retryAt := s.classifier.Classify(attemptedAt, response, transportErr)
	result.Outcome = outcome
	result.RetryAt = retryAt
	if transportErr != nil {
		result.ErrorCode = CodeTransport
		return result, NewError(CodeTransport, "send webhook", transportErr)
	}
	defer response.Body.Close()
	result.StatusCode = response.StatusCode
	result.ResponseHeader = safeResponseHeaders(response.Header)

	limited := io.LimitReader(response.Body, s.maxResponse+1)
	responseBody, readErr := io.ReadAll(limited)
	if int64(len(responseBody)) > s.maxResponse {
		result.ResponseBody = bytes.Clone(responseBody[:s.maxResponse])
		result.ErrorCode = CodeBodyTooLarge
		return result, NewError(CodeBodyTooLarge, "webhook response exceeded configured limit", nil)
	}
	result.ResponseBody = responseBody
	if readErr != nil {
		result.ErrorCode = CodeResponseRead
		return result, NewError(CodeResponseRead, "read webhook response", readErr)
	}
	return result, nil
}

func copyHeaders(destination, source http.Header) error {
	for name, values := range source {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
		if canonical == "" || strings.ContainsAny(canonical, "\r\n") {
			return NewError(CodeInvalidMessage, "invalid HTTP header name", nil)
		}
		switch strings.ToLower(canonical) {
		case "host", "content-length", "connection", "transfer-encoding":
			return NewError(CodeInvalidMessage, fmt.Sprintf("header %s cannot be set by webhook payload", canonical), nil)
		}
		destination.Del(canonical)
		for _, value := range values {
			if strings.ContainsAny(value, "\r\n\x00") {
				return NewError(CodeInvalidMessage, fmt.Sprintf("header %s contains forbidden characters", canonical), nil)
			}
			destination.Add(canonical, value)
		}
	}
	return nil
}

func safeResponseHeaders(source http.Header) http.Header {
	clone := source.Clone()
	for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie"} {
		clone.Del(name)
	}
	return clone
}

func IsTransportError(err error) bool {
	return ErrorCode(err) == CodeTransport || errors.Is(err, transport.ErrUnsafeDestination)
}
