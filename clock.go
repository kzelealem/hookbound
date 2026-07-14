package hookbound

import "time"

// Clock supplies time to security- and retry-sensitive code.
// Tests should inject a deterministic implementation.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func clockOrSystem(clock Clock) Clock {
	if clock == nil {
		return systemClock{}
	}
	return clock
}
