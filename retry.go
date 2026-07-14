package hookbound

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"time"
)

// Jitter supplies a value in [0, max].
type Jitter interface {
	Duration(max time.Duration) time.Duration
}

type CryptoJitter struct{}

func (CryptoJitter) Duration(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	var bytes [8]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return max / 2
	}
	value := binary.LittleEndian.Uint64(bytes[:])
	return time.Duration(value % uint64(max+1))
}

// RetryPolicy calculates the next automatic attempt. Attempt is one-based and
// represents the attempt that just completed.
type RetryPolicy struct {
	Schedule    []time.Duration
	MaxAttempts int
	Jitter      Jitter
}

func StandardRetryPolicy() RetryPolicy {
	return RetryPolicy{
		Schedule: []time.Duration{
			5 * time.Second,
			5 * time.Minute,
			30 * time.Minute,
			2 * time.Hour,
			5 * time.Hour,
			10 * time.Hour,
			14 * time.Hour,
			20 * time.Hour,
			24 * time.Hour,
		},
		MaxAttempts: 10,
		Jitter:      CryptoJitter{},
	}
}

func (p RetryPolicy) Next(now time.Time, attempt int) (time.Time, bool) {
	if attempt <= 0 {
		return time.Time{}, false
	}
	maximum := p.MaxAttempts
	if maximum <= 0 {
		maximum = len(p.Schedule) + 1
	}
	if attempt >= maximum {
		return time.Time{}, false
	}
	if len(p.Schedule) == 0 {
		return time.Time{}, false
	}
	index := attempt - 1
	if index >= len(p.Schedule) {
		index = len(p.Schedule) - 1
	}
	delay := p.Schedule[index]
	if delay < 0 || delay > time.Duration(math.MaxInt64/2) {
		return time.Time{}, false
	}
	jitter := p.Jitter
	if jitter == nil {
		jitter = CryptoJitter{}
	}
	return now.Add(delay + jitter.Duration(delay/5)), true
}
