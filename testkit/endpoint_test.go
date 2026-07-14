package testkit

import (
	"net/http"
	"testing"
	"time"
)

func TestEndpointScriptsAndCapturesRequests(t *testing.T) {
	endpoint := NewEndpoint(t, Reply(http.StatusServiceUnavailable), Reply(http.StatusNoContent))
	for expected, status := range []int{http.StatusServiceUnavailable, http.StatusNoContent, http.StatusNoContent} {
		request, err := http.NewRequest(http.MethodPost, endpoint.URL()+"/webhook", http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-Attempt", string(rune('1'+expected)))
		response, err := endpoint.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != status {
			t.Fatalf("unexpected status: got %d want %d", response.StatusCode, status)
		}
	}
	RequireAttempts(t, endpoint, 3)
	if request, ok := endpoint.LastRequest(); !ok || request.URL != "/webhook" {
		t.Fatalf("unexpected last request: %#v", request)
	}
}

func TestFixedClock(t *testing.T) {
	clock := NewFixedClock(time.Unix(100, 0))
	clock.Advance(time.Minute)
	if got := clock.Now(); !got.Equal(time.Unix(160, 0)) {
		t.Fatalf("unexpected clock: %s", got)
	}
}
