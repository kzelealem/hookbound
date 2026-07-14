package hookbound

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Outcome is the webhook-specific interpretation of one HTTP attempt.
type Outcome uint8

const (
	OutcomeDelivered Outcome = iota + 1
	OutcomeRetry
	OutcomePermanentFailure
	OutcomeDisableDestination
)

func (o Outcome) String() string {
	switch o {
	case OutcomeDelivered:
		return "delivered"
	case OutcomeRetry:
		return "retry"
	case OutcomePermanentFailure:
		return "permanent_failure"
	case OutcomeDisableDestination:
		return "disable_destination"
	default:
		return "unknown"
	}
}

// AttemptResult captures one and only one outbound HTTP attempt.
type AttemptResult struct {
	MessageID      string
	AttemptedAt    time.Time
	Outcome        Outcome
	StatusCode     int
	Duration       time.Duration
	RetryAt        time.Time
	ResponseHeader http.Header
	ResponseBody   []byte
	ErrorCode      Code
}

// Classifier maps HTTP and network results into webhook delivery semantics.
type Classifier interface {
	Classify(now time.Time, response *http.Response, err error) (Outcome, time.Time)
}

// DefaultClassifier follows conservative Standard Webhooks guidance while
// treating deterministic client errors as permanent by default.
type DefaultClassifier struct {
	MaxRetryAfter time.Duration
}

func (c DefaultClassifier) Classify(now time.Time, response *http.Response, err error) (Outcome, time.Time) {
	if err != nil {
		var networkError net.Error
		if errors.As(err, &networkError) {
			return OutcomeRetry, time.Time{}
		}
		return OutcomeRetry, time.Time{}
	}
	if response == nil {
		return OutcomeRetry, time.Time{}
	}

	status := response.StatusCode
	switch {
	case status >= 200 && status <= 299:
		return OutcomeDelivered, time.Time{}
	case status == http.StatusGone:
		return OutcomeDisableDestination, time.Time{}
	case status == http.StatusRequestTimeout || status == http.StatusTooEarly || status == http.StatusTooManyRequests:
		return OutcomeRetry, c.retryAfter(now, response.Header.Get("Retry-After"))
	case status >= 500:
		return OutcomeRetry, c.retryAfter(now, response.Header.Get("Retry-After"))
	default:
		return OutcomePermanentFailure, time.Time{}
	}
}

func (c DefaultClassifier) retryAfter(now time.Time, value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	maximum := c.MaxRetryAfter
	if maximum <= 0 {
		maximum = 24 * time.Hour
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds >= 0 {
		if seconds > int64(maximum/time.Second) {
			return now.Add(maximum)
		}
		return now.Add(time.Duration(seconds) * time.Second)
	}
	if parsed, err := http.ParseTime(value); err == nil && parsed.After(now) {
		if parsed.Sub(now) > maximum {
			return now.Add(maximum)
		}
		return parsed
	}
	return time.Time{}
}
