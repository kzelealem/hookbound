package hookbound

import (
	"errors"
	"fmt"
)

// Code is a stable, machine-readable error category.
type Code string

const (
	CodeInvalidConfiguration Code = "invalid_configuration"
	CodeInvalidMessage       Code = "invalid_message"
	CodeInvalidURL           Code = "invalid_url"
	CodeUnsafeDestination    Code = "unsafe_destination"
	CodeBodyTooLarge         Code = "body_too_large"
	CodeInvalidSignature     Code = "invalid_signature"
	CodeExpiredSignature     Code = "expired_signature"
	CodeReplay               Code = "replay"
	CodeUnknownEvent         Code = "unknown_event"
	CodeDecode               Code = "decode_failed"
	CodeHandler              Code = "handler_failed"
	CodeTransport            Code = "transport_failed"
	CodeResponseRead         Code = "response_read_failed"
	CodePersistence          Code = "persistence_failed"
	CodeConflict             Code = "conflict"
	CodeInternal             Code = "internal"
)

var ErrIDGeneration = errors.New("hookbound: message id generation failed")

// Error preserves a stable error code without exposing sensitive details in
// user-facing HTTP responses.
type Error struct {
	Code    Code
	Message string
	Cause   error
}

func NewError(code Code, message string, cause error) *Error {
	return &Error{Code: code, Message: message, Cause: cause}
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Cause == nil {
		return fmt.Sprintf("hookbound: %s: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("hookbound: %s: %s: %v", e.Code, e.Message, e.Cause)
}

func (e *Error) Unwrap() error { return e.Cause }

func ErrorCode(err error) Code {
	if err == nil {
		return ""
	}
	var coded *Error
	if errors.As(err, &coded) {
		return coded.Code
	}
	return CodeInternal
}
