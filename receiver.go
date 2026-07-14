package hookbound

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// ErrorResponder converts internal receiver failures into deliberately terse
// HTTP responses. It must not expose secrets or signature details.
type ErrorResponder func(http.ResponseWriter, *http.Request, error)

type ReceiverConfig struct {
	Verifier       Verifier
	Handler        Handler
	ReplayGuard    ReplayGuard
	Clock          Clock
	MaxBodyBytes   int64
	ReplayTTL      time.Duration
	SuccessStatus  int
	ErrorResponder ErrorResponder
}

// Receiver owns the inbound body lifecycle: bound, read once, verify exact
// bytes, claim replay identity, then dispatch.
type Receiver struct {
	verifier      Verifier
	handler       Handler
	replayGuard   ReplayGuard
	clock         Clock
	maxBody       int64
	replayTTL     time.Duration
	successStatus int
	respondError  ErrorResponder
}

func NewReceiver(config ReceiverConfig) (*Receiver, error) {
	if config.Verifier == nil {
		return nil, NewError(CodeInvalidConfiguration, "verifier is required", nil)
	}
	if config.Handler == nil {
		return nil, NewError(CodeInvalidConfiguration, "handler is required", nil)
	}
	if config.MaxBodyBytes <= 0 {
		config.MaxBodyBytes = 1 << 20
	}
	if config.ReplayTTL <= 0 {
		config.ReplayTTL = 10 * time.Minute
	}
	if config.SuccessStatus == 0 {
		config.SuccessStatus = http.StatusNoContent
	}
	if config.SuccessStatus < 200 || config.SuccessStatus > 299 {
		return nil, NewError(CodeInvalidConfiguration, "success status must be 2xx", nil)
	}
	if config.ErrorResponder == nil {
		config.ErrorResponder = defaultErrorResponder
	}
	return &Receiver{
		verifier:      config.Verifier,
		handler:       config.Handler,
		replayGuard:   config.ReplayGuard,
		clock:         clockOrSystem(config.Clock),
		maxBody:       config.MaxBodyBytes,
		replayTTL:     config.ReplayTTL,
		successStatus: config.SuccessStatus,
		respondError:  config.ErrorResponder,
	}, nil
}

func (r *Receiver) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if encoding := strings.TrimSpace(request.Header.Get("Content-Encoding")); encoding != "" && !strings.EqualFold(encoding, "identity") {
		r.respondError(writer, request, NewError(CodeInvalidMessage, "compressed webhook bodies are not accepted", nil))
		return
	}
	if request.ContentLength > r.maxBody {
		r.respondError(writer, request, NewError(CodeBodyTooLarge, "webhook body exceeds configured limit", nil))
		return
	}

	body, err := readBounded(request.Body, r.maxBody)
	if err != nil {
		r.respondError(writer, request, err)
		return
	}
	receivedAt := r.clock.Now().UTC()
	verification, err := r.verifier.Verify(request.Context(), VerifyInput{
		Headers:    request.Header.Clone(),
		Body:       body,
		ReceivedAt: receivedAt,
	})
	if err != nil {
		r.respondError(writer, request, err)
		return
	}
	message := VerifiedMessage{
		ID:          verification.ID,
		Type:        verification.Type,
		Source:      verification.Source,
		Timestamp:   verification.Timestamp,
		Body:        bytes.Clone(body),
		ContentType: request.Header.Get("Content-Type"),
		Headers:     request.Header.Clone(),
		Metadata:    cloneStringMap(verification.Metadata),
	}
	if err := message.Validate(); err != nil {
		r.respondError(writer, request, err)
		return
	}

	if r.replayGuard != nil {
		claimed, err := r.replayGuard.Claim(request.Context(), message.Source, message.ID, receivedAt.Add(r.replayTTL))
		if err != nil {
			r.respondError(writer, request, err)
			return
		}
		if !claimed {
			writer.WriteHeader(r.successStatus)
			return
		}
	}
	if err := r.handle(request.Context(), message); err != nil {
		if r.replayGuard != nil {
			if releaseErr := r.replayGuard.Release(request.Context(), message.Source, message.ID); releaseErr != nil {
				err = NewError(CodeHandler, "handle webhook and release replay claim", errors.Join(err, releaseErr))
			}
		}
		r.respondError(writer, request, err)
		return
	}
	if committer, ok := r.replayGuard.(ReplayCommitter); ok {
		if err := committer.Commit(request.Context(), message.Source, message.ID, r.clock.Now().UTC().Add(r.replayTTL)); err != nil {
			r.respondError(writer, request, NewError(CodeReplay, "commit replay claim", err))
			return
		}
	}
	writer.WriteHeader(r.successStatus)
}

func (r *Receiver) handle(ctx context.Context, message VerifiedMessage) (err error) {
	if r.replayGuard != nil {
		defer func() {
			if recovered := recover(); recovered != nil {
				releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
				_ = r.replayGuard.Release(releaseCtx, message.Source, message.ID)
				cancel()
				panic(recovered)
			}
		}()
	}
	return r.handler.Handle(ctx, message)
}

func readBounded(reader io.ReadCloser, maximum int64) ([]byte, error) {
	if reader == nil {
		return nil, nil
	}
	defer reader.Close()
	body, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, NewError(CodeInvalidMessage, "read webhook body", err)
	}
	if int64(len(body)) > maximum {
		return nil, NewError(CodeBodyTooLarge, "webhook body exceeds configured limit", nil)
	}
	return body, nil
}

func defaultErrorResponder(writer http.ResponseWriter, _ *http.Request, err error) {
	status := http.StatusInternalServerError
	message := "webhook processing failed"
	switch ErrorCode(err) {
	case CodeInvalidSignature, CodeExpiredSignature:
		status = http.StatusUnauthorized
		message = "invalid webhook"
	case CodeInvalidMessage, CodeDecode:
		status = http.StatusBadRequest
		message = "invalid webhook"
	case CodeBodyTooLarge:
		status = http.StatusRequestEntityTooLarge
		message = "webhook body too large"
	case CodeUnknownEvent:
		status = http.StatusUnprocessableEntity
		message = "unsupported webhook event"
	}
	if status == http.StatusNoContent {
		writer.WriteHeader(status)
		return
	}
	http.Error(writer, message, status)
}

func IsClientWebhookError(err error) bool {
	code := ErrorCode(err)
	return code == CodeInvalidSignature || code == CodeExpiredSignature ||
		code == CodeInvalidMessage || code == CodeDecode || code == CodeBodyTooLarge ||
		errors.Is(err, http.ErrBodyReadAfterClose)
}
