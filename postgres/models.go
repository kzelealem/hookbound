package postgres

import (
	"net/http"
	"time"

	"github.com/kzelealem/hookbound"
)

type DeliveryState string

const (
	DeliveryPending          DeliveryState = "pending"
	DeliveryInFlight         DeliveryState = "in_flight"
	DeliveryRetry            DeliveryState = "retry"
	DeliveryDelivered        DeliveryState = "delivered"
	DeliveryPermanentFailure DeliveryState = "permanent_failure"
	DeliveryDisabled         DeliveryState = "disabled"
	DeliveryExhausted        DeliveryState = "exhausted"
)

type ReceiptState string

const (
	ReceiptPending    ReceiptState = "pending"
	ReceiptProcessing ReceiptState = "processing"
	ReceiptRetry      ReceiptState = "retry"
	ReceiptProcessed  ReceiptState = "processed"
	ReceiptFailed     ReceiptState = "failed"
	ReceiptExhausted  ReceiptState = "exhausted"
)

// EnqueueOptions controls durable publication behavior.
type EnqueueOptions struct {
	// IdempotencyKey identifies one destination-specific publication. Reusing
	// the key with byte-for-byte equivalent immutable content returns the
	// original publication; reusing it with different content fails. Keys are
	// SHA-256 hashed before persistence.
	IdempotencyKey string
}

type Publication struct {
	MessageID  string
	DeliveryID string
}

type ClaimedDelivery struct {
	DeliveryID  string
	AttemptID   string
	Attempt     int
	MessageID   string
	Destination string
	EventType   string
	Body        []byte
	ContentType string
	Headers     http.Header
	StartedAt   time.Time
}

type ClaimedReceipt struct {
	Message   hookbound.VerifiedMessage
	Attempt   int
	StartedAt time.Time
}

// RetentionPolicy controls one bounded cleanup pass. A zero retention duration
// disables that category. Attempts are removed automatically with deliveries.
type RetentionPolicy struct {
	DeliveredRetention      time.Duration
	FailedDeliveryRetention time.Duration
	ReceiptRetention        time.Duration
	OrphanMessageRetention  time.Duration
	BatchSize               int
}

// CleanupResult reports rows removed by one bounded cleanup pass.
type CleanupResult struct {
	DeliveredDeliveries int64
	FailedDeliveries    int64
	Receipts            int64
	OrphanMessages      int64
}

// Total returns the total number of primary records removed. Cascaded attempt
// rows are intentionally not included.
func (r CleanupResult) Total() int64 {
	return r.DeliveredDeliveries + r.FailedDeliveries + r.Receipts + r.OrphanMessages
}
