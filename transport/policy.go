// Package transport provides an SSRF-aware HTTP transport for outbound
// webhook delivery.
package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var ErrUnsafeDestination = errors.New("hookbound transport: unsafe destination")

// Resolver is implemented by net.Resolver and deterministic test resolvers.
type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// Policy controls which destinations the transport may dial.
type Policy struct {
	AllowPlainHTTP bool
	AllowAnyPort   bool
	AllowedPorts   map[uint16]struct{}
	AllowedCIDRs   []netip.Prefix
	Resolver       Resolver
	Proxy          func(*http.Request) (*url.URL, error)
	Dialer         *net.Dialer
	TLSConfig      *tls.Config

	DialTimeout           time.Duration
	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration
	IdleConnTimeout       time.Duration
	MaxIdleConns          int
	MaxIdleConnsPerHost   int
}

func DefaultPolicy() Policy {
	return Policy{
		AllowedPorts:          map[uint16]struct{}{443: {}},
		DialTimeout:           10 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
	}
}

// DevelopmentPolicy explicitly permits local HTTP destinations. It must not
// be used for untrusted URLs or production multi-tenant delivery.
func DevelopmentPolicy() Policy {
	policy := DefaultPolicy()
	policy.AllowPlainHTTP = true
	policy.AllowAnyPort = true
	policy.AllowedPorts = nil
	policy.AllowedCIDRs = []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	}
	return policy
}

func (p Policy) normalized() Policy {
	defaults := DefaultPolicy()
	if p.Resolver == nil {
		p.Resolver = net.DefaultResolver
	}
	if p.AllowAnyPort {
		p.AllowedPorts = nil
	} else {
		ports := p.AllowedPorts
		if len(ports) == 0 {
			ports = defaults.AllowedPorts
		}
		p.AllowedPorts = make(map[uint16]struct{}, len(ports))
		for port := range ports {
			p.AllowedPorts[port] = struct{}{}
		}
	}
	p.AllowedCIDRs = append([]netip.Prefix(nil), p.AllowedCIDRs...)
	if p.DialTimeout <= 0 {
		p.DialTimeout = defaults.DialTimeout
	}
	if p.TLSHandshakeTimeout <= 0 {
		p.TLSHandshakeTimeout = defaults.TLSHandshakeTimeout
	}
	if p.ResponseHeaderTimeout <= 0 {
		p.ResponseHeaderTimeout = defaults.ResponseHeaderTimeout
	}
	if p.IdleConnTimeout <= 0 {
		p.IdleConnTimeout = defaults.IdleConnTimeout
	}
	if p.MaxIdleConns <= 0 {
		p.MaxIdleConns = defaults.MaxIdleConns
	}
	if p.MaxIdleConnsPerHost <= 0 {
		p.MaxIdleConnsPerHost = defaults.MaxIdleConnsPerHost
	}
	if p.Dialer == nil {
		p.Dialer = &net.Dialer{Timeout: p.DialTimeout, KeepAlive: 30 * time.Second}
	} else {
		dialer := *p.Dialer
		p.Dialer = &dialer
	}
	if p.TLSConfig == nil {
		p.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		p.TLSConfig = p.TLSConfig.Clone()
		if p.TLSConfig.MinVersion < tls.VersionTLS12 {
			p.TLSConfig.MinVersion = tls.VersionTLS12
		}
	}
	return p
}

// Clone returns an immutable policy snapshot with secure defaults applied.
// Mutable maps, slices, dialers, and TLS configuration are copied.
func (p Policy) Clone() Policy {
	return p.normalized()
}

// ValidateURL performs syntax, scheme, credential, and port checks. Network
// addresses are validated again immediately before dialing.
func ValidateURL(rawURL string, policy Policy) (*url.URL, error) {
	policy = policy.normalized()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: parse URL: %v", ErrUnsafeDestination, err)
	}
	if parsed.Scheme != "https" && (!policy.AllowPlainHTTP || parsed.Scheme != "http") {
		return nil, fmt.Errorf("%w: scheme %q is not allowed", ErrUnsafeDestination, parsed.Scheme)
	}
	if parsed.Hostname() == "" {
		return nil, fmt.Errorf("%w: hostname is required", ErrUnsafeDestination)
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("%w: URL credentials are forbidden", ErrUnsafeDestination)
	}
	if parsed.Fragment != "" {
		return nil, fmt.Errorf("%w: URL fragments are forbidden", ErrUnsafeDestination)
	}
	if strings.ContainsAny(parsed.Host, "\r\n\x00") {
		return nil, fmt.Errorf("%w: invalid host", ErrUnsafeDestination)
	}
	port, err := effectivePort(parsed)
	if err != nil {
		return nil, err
	}
	if !policy.AllowAnyPort {
		if _, allowed := policy.AllowedPorts[port]; !allowed {
			return nil, fmt.Errorf("%w: port %d is not allowed", ErrUnsafeDestination, port)
		}
	}
	return parsed, nil
}

// NewClient creates an HTTP client that refuses redirects and validates every
// destination at dial time.
func NewClient(policy Policy) *http.Client {
	policy = policy.normalized()
	return &http.Client{
		Transport: NewTransport(policy),
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func NewTransport(policy Policy) *http.Transport {
	policy = policy.normalized()
	transport := &http.Transport{
		Proxy:                 policy.Proxy,
		DialContext:           dialContext(policy),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          policy.MaxIdleConns,
		MaxIdleConnsPerHost:   policy.MaxIdleConnsPerHost,
		IdleConnTimeout:       policy.IdleConnTimeout,
		TLSHandshakeTimeout:   policy.TLSHandshakeTimeout,
		ResponseHeaderTimeout: policy.ResponseHeaderTimeout,
		TLSClientConfig:       policy.TLSConfig,
		ExpectContinueTimeout: time.Second,
	}
	return transport
}

func dialContext(policy Policy) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("%w: split destination: %v", ErrUnsafeDestination, err)
		}
		addresses, err := resolve(ctx, policy.Resolver, host)
		if err != nil {
			return nil, fmt.Errorf("resolve destination: %w", err)
		}
		if len(addresses) == 0 {
			return nil, fmt.Errorf("resolve destination: no addresses")
		}
		for _, address := range addresses {
			if err := validateAddress(address, policy.AllowedCIDRs); err != nil {
				return nil, err
			}
		}

		var dialErrors []error
		for _, resolved := range addresses {
			connection, err := policy.Dialer.DialContext(ctx, network, net.JoinHostPort(resolved.String(), port))
			if err == nil {
				return connection, nil
			}
			dialErrors = append(dialErrors, err)
		}
		return nil, errors.Join(dialErrors...)
	}
}

func resolve(ctx context.Context, resolver Resolver, host string) ([]netip.Addr, error) {
	if parsed, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{parsed.Unmap()}, nil
	}
	ips, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	addresses := make([]netip.Addr, 0, len(ips))
	seen := make(map[netip.Addr]struct{}, len(ips))
	for _, ip := range ips {
		address := ip.Unmap()
		if _, exists := seen[address]; exists {
			continue
		}
		seen[address] = struct{}{}
		addresses = append(addresses, address)
	}
	return addresses, nil
}

func validateAddress(address netip.Addr, allowed []netip.Prefix) error {
	for _, prefix := range allowed {
		if prefix.Contains(address) {
			return nil
		}
	}
	if !address.IsValid() || address.IsUnspecified() || address.IsLoopback() ||
		address.IsPrivate() || address.IsLinkLocalUnicast() ||
		address.IsLinkLocalMulticast() || address.IsMulticast() {
		return fmt.Errorf("%w: address %s is not publicly routable", ErrUnsafeDestination, address)
	}
	for _, prefix := range reservedPrefixes {
		if prefix.Contains(address) {
			return fmt.Errorf("%w: address %s is reserved", ErrUnsafeDestination, address)
		}
	}
	return nil
}

var reservedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func effectivePort(parsed *url.URL) (uint16, error) {
	portText := parsed.Port()
	if portText == "" {
		if parsed.Scheme == "https" {
			return 443, nil
		}
		return 80, nil
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return 0, fmt.Errorf("%w: invalid port", ErrUnsafeDestination)
	}
	return uint16(port), nil
}

// IsTemporary reports whether an error is plausibly transient. It is provided
// for delivery classifiers and avoids relying solely on deprecated Temporary.
func IsTemporary(err error) bool {
	if err == nil {
		return false
	}
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
		return dnsError.IsTimeout || dnsError.IsTemporary
	}
	var networkError net.Error
	if errors.As(err, &networkError) {
		return networkError.Timeout()
	}
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EPIPE)
}
