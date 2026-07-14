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
	Store                *Store
	Sender               *hookbound.Sender
	InboundHandler       hookbound.Handler
	RetryPolicy          hookbound.RetryPolicy
	LeaseDuration        time.Duration
	LeaseRenewalInterval time.Duration
	LeaseRenewalTimeout  time.Duration
	PollInterval         time.Duration
	CompletionTimeout    time.Duration
	OutboundWorkers      int
	InboundWorkers       int
	Logger               *slog.Logger
}

// Runtime coordinates durable inbox and outbox workers. NewRuntime starts no
// goroutines; callers explicitly invoke Run.
type Runtime struct {
	store          *Store
	sender         *hookbound.Sender
	inbound        hookbound.Handler
	retry          hookbound.RetryPolicy
	lease          time.Duration
	renewal        time.Duration
	renewalTimeout time.Duration
	poll           time.Duration
	completion     time.Duration
	outboundCount  int
	inboundCount   int
	logger         *slog.Logger
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
	if config.LeaseRenewalInterval < 0 || config.LeaseRenewalTimeout < 0 {
		return nil, hookbound.NewError(hookbound.CodeInvalidConfiguration, "lease renewal durations cannot be negative", nil)
	}
	if config.LeaseRenewalInterval == 0 {
		config.LeaseRenewalInterval = config.LeaseDuration / 3
	}
	if config.LeaseRenewalInterval <= 0 || config.LeaseRenewalInterval >= config.LeaseDuration {
		return nil, hookbound.NewError(hookbound.CodeInvalidConfiguration, "lease renewal interval must be positive and shorter than the lease", nil)
	}
	if config.LeaseRenewalTimeout == 0 {
		config.LeaseRenewalTimeout = minDuration(5*time.Second, config.LeaseRenewalInterval)
	}
	if config.LeaseRenewalTimeout >= config.LeaseDuration-config.LeaseRenewalInterval {
		return nil, hookbound.NewError(hookbound.CodeInvalidConfiguration, "lease renewal interval plus timeout must be shorter than the lease", nil)
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
		retry: config.RetryPolicy, lease: config.LeaseDuration, renewal: config.LeaseRenewalInterval,
		renewalTimeout: config.LeaseRenewalTimeout, poll: config.PollInterval, completion: config.CompletionTimeout,
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
	workCtx, heartbeat := startLeaseHeartbeat(ctx, r.renewal, r.renewalTimeout, func(renewCtx context.Context) error {
		return r.store.RenewDeliveryLease(renewCtx, claimed, r.lease)
	})
	result, sendErr := sendSafely(r.sender, workCtx, hookbound.SendRequest{
		ID: claimed.MessageID, URL: claimed.Destination, EventType: claimed.EventType,
		Body: claimed.Body, ContentType: claimed.ContentType, Headers: claimed.Headers,
	})
	if err := heartbeat.Stop(); err != nil {
		return true, err
	}
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
	workCtx, heartbeat := startLeaseHeartbeat(ctx, r.renewal, r.renewalTimeout, func(renewCtx context.Context) error {
		return r.store.RenewReceiptLease(renewCtx, claimed, r.lease)
	})
	handlerErr := handleSafely(r.inbound, workCtx, claimed.Message)
	if err := heartbeat.Stop(); err != nil {
		return true, err
	}
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

type leaseHeartbeat struct {
	stop     chan struct{}
	done     chan struct{}
	cancel   context.CancelFunc
	stopOnce sync.Once
	err      error
}

func startLeaseHeartbeat(
	parent context.Context,
	interval time.Duration,
	timeout time.Duration,
	renew func(context.Context) error,
) (context.Context, *leaseHeartbeat) {
	workCtx, cancel := context.WithCancel(parent)
	heartbeat := &leaseHeartbeat{
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
		cancel: cancel,
	}
	go heartbeat.run(workCtx, interval, timeout, renew)
	return workCtx, heartbeat
}

func (h *leaseHeartbeat) run(ctx context.Context, interval, timeout time.Duration, renew func(context.Context) error) {
	defer close(h.done)
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-h.stop:
			return
		case <-timer.C:
		}
		renewCtx, cancel := context.WithTimeout(ctx, timeout)
		err := renewLeaseSafely(renew, renewCtx)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			h.err = hookbound.NewError(hookbound.CodePersistence, "renew durable worker lease", err)
			h.cancel()
			return
		}
		timer.Reset(interval)
	}
}

func (h *leaseHeartbeat) Stop() error {
	if h == nil {
		return nil
	}
	h.stopOnce.Do(func() {
		close(h.stop)
		h.cancel()
	})
	<-h.done
	return h.err
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

func renewLeaseSafely(renew func(context.Context) error, ctx context.Context) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = hookbound.NewError(hookbound.CodeInternal, "lease renewal panicked", panicCause(recovered))
		}
	}()
	return renew(ctx)
}
