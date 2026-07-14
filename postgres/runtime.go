package postgres

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"github.com/hookbound/hookbound"
)

type RuntimeConfig struct {
	Store             *Store
	Sender            *hookbound.Sender
	InboundHandler    hookbound.Handler
	RetryPolicy       hookbound.RetryPolicy
	LeaseDuration     time.Duration
	PollInterval      time.Duration
	CompletionTimeout time.Duration
	OutboundWorkers   int
	InboundWorkers    int
	Logger            *slog.Logger
}

// Runtime coordinates durable inbox and outbox workers. NewRuntime starts no
// goroutines; callers explicitly invoke Run.
type Runtime struct {
	store         *Store
	sender        *hookbound.Sender
	inbound       hookbound.Handler
	retry         hookbound.RetryPolicy
	lease         time.Duration
	poll          time.Duration
	completion    time.Duration
	outboundCount int
	inboundCount  int
	logger        *slog.Logger
}

func NewRuntime(config RuntimeConfig) (*Runtime, error) {
	if config.Store == nil {
		return nil, hookbound.NewError(hookbound.CodeInvalidConfiguration, "durable store is required", nil)
	}
	if config.Sender == nil && config.OutboundWorkers != 0 {
		return nil, hookbound.NewError(hookbound.CodeInvalidConfiguration, "sender is required for outbound workers", nil)
	}
	if config.InboundHandler == nil && config.InboundWorkers != 0 {
		return nil, hookbound.NewError(hookbound.CodeInvalidConfiguration, "inbound handler is required for inbound workers", nil)
	}
	if config.RetryPolicy.MaxAttempts == 0 && len(config.RetryPolicy.Schedule) == 0 {
		config.RetryPolicy = hookbound.StandardRetryPolicy()
	}
	if config.LeaseDuration <= 0 {
		config.LeaseDuration = time.Minute
	}
	if config.PollInterval <= 0 {
		config.PollInterval = 250 * time.Millisecond
	}
	if config.CompletionTimeout <= 0 {
		config.CompletionTimeout = 10 * time.Second
	}
	if config.OutboundWorkers < 0 || config.InboundWorkers < 0 {
		return nil, hookbound.NewError(hookbound.CodeInvalidConfiguration, "worker counts cannot be negative", nil)
	}
	if config.OutboundWorkers == 0 && config.Sender != nil {
		config.OutboundWorkers = 4
	}
	if config.InboundWorkers == 0 && config.InboundHandler != nil {
		config.InboundWorkers = 4
	}
	if config.Logger == nil {
		config.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Runtime{
		store: config.Store, sender: config.Sender, inbound: config.InboundHandler,
		retry: config.RetryPolicy, lease: config.LeaseDuration, poll: config.PollInterval, completion: config.CompletionTimeout,
		outboundCount: config.OutboundWorkers, inboundCount: config.InboundWorkers, logger: config.Logger,
	}, nil
}

// Receiver creates a verify-persist-ack HTTP handler. Business processing is
// performed by inbound workers in Run.
func (r *Runtime) Receiver(verifier hookbound.Verifier) (*hookbound.Receiver, error) {
	return hookbound.NewReceiver(hookbound.ReceiverConfig{Verifier: verifier, Handler: r.store})
}

func (r *Runtime) Run(ctx context.Context) error {
	if r == nil {
		return hookbound.NewError(hookbound.CodeInvalidConfiguration, "runtime is nil", nil)
	}
	var wait sync.WaitGroup
	for index := 0; index < r.outboundCount; index++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			r.runLoop(ctx, "outbound", worker, r.WorkOutboundOnce)
		}(index)
	}
	for index := 0; index < r.inboundCount; index++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			r.runLoop(ctx, "inbound", worker, r.WorkInboundOnce)
		}(index)
	}
	<-ctx.Done()
	wait.Wait()
	return nil
}

func (r *Runtime) runLoop(ctx context.Context, kind string, worker int, work func(context.Context) (bool, error)) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		worked, err := runWorkSafely(ctx, work)
		if err != nil && ctx.Err() == nil {
			r.logger.ErrorContext(ctx, "hookbound durable worker failed", "kind", kind, "worker", worker, "error", err)
		}
		delay := time.Duration(0)
		if !worked || err != nil {
			delay = r.poll
		}
		timer.Reset(delay)
	}
}

func (r *Runtime) WorkOutboundOnce(ctx context.Context) (bool, error) {
	if r == nil || r.sender == nil {
		return false, hookbound.NewError(hookbound.CodeInvalidConfiguration, "outbound sender is not configured", nil)
	}
	claimed, err := r.store.ClaimDelivery(ctx, r.lease)
	if err != nil || claimed == nil {
		return false, err
	}
	result, sendErr := sendSafely(r.sender, ctx, hookbound.SendRequest{
		ID: claimed.MessageID, URL: claimed.Destination, EventType: claimed.EventType,
		Body: claimed.Body, ContentType: claimed.ContentType, Headers: claimed.Headers,
	})
	completionCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.completion)
	defer cancel()
	if err := r.store.CompleteDelivery(completionCtx, claimed, result, sendErr, r.retry); err != nil {
		return true, err
	}
	return true, nil
}

func (r *Runtime) WorkInboundOnce(ctx context.Context) (bool, error) {
	if r.inbound == nil {
		return false, nil
	}
	claimed, err := r.store.ClaimReceipt(ctx, r.lease)
	if err != nil || claimed == nil {
		return false, err
	}
	handlerErr := handleSafely(r.inbound, ctx, claimed.Message)
	completionCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.completion)
	defer cancel()
	if err := r.store.CompleteReceipt(completionCtx, claimed, handlerErr, r.retry); err != nil {
		return true, err
	}
	return true, nil
}

func runWorkSafely(ctx context.Context, work func(context.Context) (bool, error)) (worked bool, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = hookbound.NewError(hookbound.CodeInternal, "durable worker panicked", panicCause(recovered))
		}
	}()
	return work(ctx)
}

func sendSafely(sender *hookbound.Sender, ctx context.Context, request hookbound.SendRequest) (result hookbound.AttemptResult, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result.ErrorCode = hookbound.CodeInternal
			err = hookbound.NewError(hookbound.CodeInternal, "outbound delivery panicked", panicCause(recovered))
		}
	}()
	return sender.Send(ctx, request)
}

func handleSafely(handler hookbound.Handler, ctx context.Context, message hookbound.VerifiedMessage) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = hookbound.NewError(hookbound.CodeHandler, "inbound handler panicked", panicCause(recovered))
		}
	}()
	return handler.Handle(ctx, message)
}

func panicCause(recovered any) error {
	return fmt.Errorf("panic: %v\n%s", recovered, debug.Stack())
}
