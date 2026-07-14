package hookbound

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

// SecretProvider resolves credentials at attempt time, allowing callers to
// integrate a KMS or secret manager without storing plaintext in destinations.
type SecretProvider interface {
	Secret(context.Context) (string, error)
}

type SecretProviderFunc func(context.Context) (string, error)

func (f SecretProviderFunc) Secret(ctx context.Context) (string, error) {
	return f(ctx)
}

// StaticSecret stores a fixed credential. Prefer an external provider for
// long-lived production secrets.
type StaticSecret string

func (s StaticSecret) Secret(context.Context) (string, error) { return string(s), nil }

// Authenticator adds transport authentication after signature headers are set.
type Authenticator interface {
	Apply(context.Context, *http.Request) error
}

type authFunc func(context.Context, *http.Request) error

func (f authFunc) Apply(ctx context.Context, request *http.Request) error {
	return f(ctx, request)
}

func BearerAuth(provider SecretProvider) Authenticator {
	return authFunc(func(ctx context.Context, request *http.Request) error {
		secret, err := resolveSecret(ctx, provider)
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+secret)
		return nil
	})
}

func BasicAuth(username string, password SecretProvider) Authenticator {
	return authFunc(func(ctx context.Context, request *http.Request) error {
		if username == "" || strings.ContainsRune(username, ':') || containsHeaderControl(username) {
			return NewError(CodeInvalidConfiguration, "invalid basic authentication username", nil)
		}
		secret, err := resolveSecret(ctx, password)
		if err != nil {
			return err
		}
		credential := base64.StdEncoding.EncodeToString([]byte(username + ":" + secret))
		request.Header.Set("Authorization", "Basic "+credential)
		return nil
	})
}

func HeaderAuth(name string, provider SecretProvider) (Authenticator, error) {
	canonical := http.CanonicalHeaderKey(name)
	if !validHeaderName(name) {
		return nil, NewError(CodeInvalidConfiguration, "invalid authentication header name", nil)
	}
	return authFunc(func(ctx context.Context, request *http.Request) error {
		secret, err := resolveSecret(ctx, provider)
		if err != nil {
			return err
		}
		request.Header.Set(canonical, secret)
		return nil
	}), nil
}

func resolveSecret(ctx context.Context, provider SecretProvider) (string, error) {
	if provider == nil {
		return "", NewError(CodeInvalidConfiguration, "secret provider is required", nil)
	}
	secret, err := provider.Secret(ctx)
	if err != nil {
		return "", NewError(CodeInternal, "resolve secret", err)
	}
	if secret == "" {
		return "", NewError(CodeInvalidConfiguration, "resolved secret is empty", nil)
	}
	if containsHeaderControl(secret) {
		return "", NewError(CodeInvalidConfiguration, fmt.Sprintf("resolved secret contains forbidden characters for %T", provider), nil)
	}
	return secret, nil
}

func containsHeaderControl(value string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character == '\t' || character >= 0x20 && character != 0x7f {
			continue
		}
		return true
	}
	return false
}
