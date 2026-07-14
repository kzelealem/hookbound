package transport

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

type fixedResolver []netip.Addr

func (r fixedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), r...), nil
}

type failingResolver struct{ err error }

func (r failingResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, r.err
}

func TestValidateURL(t *testing.T) {
	if _, err := ValidateURL("http://example.com/hook", DefaultPolicy()); !errors.Is(err, ErrUnsafeDestination) {
		t.Fatalf("expected plain HTTP rejection: %v", err)
	}
	if _, err := ValidateURL("https://user:pass@example.com/hook", DefaultPolicy()); !errors.Is(err, ErrUnsafeDestination) {
		t.Fatalf("expected credentials rejection: %v", err)
	}
	if _, err := ValidateURL("https://example.com:8443/hook", DefaultPolicy()); !errors.Is(err, ErrUnsafeDestination) {
		t.Fatalf("expected port rejection: %v", err)
	}
}

func TestRejectsPrivateAndMixedDNS(t *testing.T) {
	policy := DefaultPolicy()
	policy.Resolver = fixedResolver{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("127.0.0.1")}
	dial := dialContext(policy.normalized())
	_, err := dial(context.Background(), "tcp", "example.com:443")
	if !errors.Is(err, ErrUnsafeDestination) {
		t.Fatalf("expected unsafe destination: %v", err)
	}
}

func TestDevelopmentPolicyAllowsLoopback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client := NewClient(DevelopmentPolicy())
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected status: %d", response.StatusCode)
	}
}

func TestResolverFailure(t *testing.T) {
	policy := DefaultPolicy()
	policy.Resolver = failingResolver{err: errors.New("dns unavailable")}
	_, err := dialContext(policy.normalized())(context.Background(), "tcp", "example.com:443")
	if err == nil {
		t.Fatal("expected resolver failure")
	}
}

func FuzzValidateURL(f *testing.F) {
	f.Add("https://example.com/webhooks")
	f.Add("http://127.0.0.1/admin")
	f.Fuzz(func(t *testing.T, value string) {
		_, _ = ValidateURL(value, DefaultPolicy())
	})
}

func TestZeroPolicyStillRestrictsPorts(t *testing.T) {
	if _, err := ValidateURL("https://example.com:8443/webhook", Policy{}); err == nil {
		t.Fatal("expected zero policy to retain secure port defaults")
	}
	if _, err := ValidateURL("https://example.com/webhook", Policy{}); err != nil {
		t.Fatalf("expected default HTTPS port to be accepted: %v", err)
	}
}

func TestDevelopmentPolicyAllowsArbitraryPort(t *testing.T) {
	if _, err := ValidateURL("http://127.0.0.1:49152/webhook", DevelopmentPolicy()); err != nil {
		t.Fatalf("expected explicit development policy to allow local port: %v", err)
	}
}

func TestTransportDoesNotUseEnvironmentProxyByDefault(t *testing.T) {
	transport := NewTransport(DefaultPolicy())
	if transport.Proxy != nil {
		t.Fatal("expected proxying to be opt-in")
	}
}
