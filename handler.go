package hookbound

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// Handler processes one already verified message.
type Handler interface {
	Handle(context.Context, VerifiedMessage) error
}

type HandlerFunc func(context.Context, VerifiedMessage) error

func (f HandlerFunc) Handle(ctx context.Context, message VerifiedMessage) error {
	return f(ctx, message)
}

// Registry dispatches verified messages by event type. Registration is safe
// before serving; handlers may run concurrently.
type Registry struct {
	mu       sync.RWMutex
	handlers map[string]Handler
	any      Handler
}

func NewRegistry() *Registry {
	return &Registry{handlers: make(map[string]Handler)}
}

func (r *Registry) Register(eventType string, handler Handler) error {
	if r == nil {
		return NewError(CodeInvalidConfiguration, "registry is nil", nil)
	}
	if err := ValidateEventType(eventType); err != nil {
		return err
	}
	if handler == nil {
		return NewError(CodeInvalidConfiguration, "handler is required", nil)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.handlers[eventType]; exists {
		return NewError(CodeConflict, fmt.Sprintf("handler already registered for %q", eventType), nil)
	}
	r.handlers[eventType] = handler
	return nil
}

func (r *Registry) RegisterAny(handler Handler) error {
	if r == nil || handler == nil {
		return NewError(CodeInvalidConfiguration, "registry and handler are required", nil)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.any != nil {
		return NewError(CodeConflict, "catch-all handler already registered", nil)
	}
	r.any = handler
	return nil
}

func (r *Registry) Handle(ctx context.Context, message VerifiedMessage) error {
	r.mu.RLock()
	handler := r.handlers[message.Type]
	if handler == nil {
		handler = r.any
	}
	r.mu.RUnlock()
	if handler == nil {
		return NewError(CodeUnknownEvent, fmt.Sprintf("no handler for event type %q", message.Type), nil)
	}
	if err := handler.Handle(ctx, message.Clone()); err != nil {
		return NewError(CodeHandler, "handle webhook", err)
	}
	return nil
}

// HandleJSON registers a typed JSON handler while preserving the exact raw
// bytes on Message.Raw.
func HandleJSON[T any](registry *Registry, eventType string, fn func(context.Context, Message[T]) error) error {
	if fn == nil {
		return NewError(CodeInvalidConfiguration, "JSON handler is required", nil)
	}
	return registry.Register(eventType, HandlerFunc(func(ctx context.Context, verified VerifiedMessage) error {
		var data T
		if err := json.Unmarshal(verified.Body, &data); err != nil {
			return NewError(CodeDecode, "decode JSON webhook", err)
		}
		return fn(ctx, Message[T]{
			ID:          verified.ID,
			Type:        verified.Type,
			Source:      verified.Source,
			Timestamp:   verified.Timestamp,
			Data:        data,
			Raw:         append([]byte(nil), verified.Body...),
			ContentType: verified.ContentType,
			Headers:     verified.Headers.Clone(),
			Metadata:    cloneStringMap(verified.Metadata),
		})
	}))
}
