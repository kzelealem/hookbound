package postgres

import (
	"net/http"
	"time"

	"github.com/hookbound/hookbound"
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
