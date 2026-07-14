// Package testkit provides deterministic webhook endpoints, captured requests,
// clocks, identifiers, and assertions for Hookbound integrations.
package testkit

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// Response describes one scripted endpoint response.
type Response struct {
	Status  int
	Headers http.Header
	Body    []byte
	Delay   time.Duration
}

// Reply returns a response script with an empty body.
func Reply(status int) Response { return Response{Status: status} }

// ReplyBody returns a response script with a copied body.
func ReplyBody(status int, body []byte) Response {
	return Response{Status: status, Body: bytes.Clone(body)}
}

// ReplyWithHeaders returns a response script with copied headers.
func ReplyWithHeaders(status int, headers http.Header) Response {
	return Response{Status: status, Headers: headers.Clone()}
}

// CapturedRequest is an immutable snapshot of one received HTTP request.
type CapturedRequest struct {
	Method     string
	URL        string
	Host       string
	Header     http.Header
	Body       []byte
	ReceivedAt time.Time
}

func (r CapturedRequest) Clone() CapturedRequest {
	return CapturedRequest{
		Method: r.Method, URL: r.URL, Host: r.Host,
		Header: r.Header.Clone(), Body: bytes.Clone(r.Body), ReceivedAt: r.ReceivedAt,
	}
}

// Endpoint is a scripted in-process HTTP endpoint safe for concurrent tests.
type Endpoint struct {
	server *httptest.Server

	mu        sync.Mutex
	responses []Response
	requests  []CapturedRequest
	next      int
}

// NewEndpoint creates an HTTP test endpoint. Once scripts are exhausted, the
// final response is repeated. With no scripts it returns 204.
func NewEndpoint(t testing.TB, responses ...Response) *Endpoint {
	t.Helper()
	endpoint := &Endpoint{responses: cloneResponses(responses)}
	endpoint.server = httptest.NewServer(http.HandlerFunc(endpoint.serveHTTP))
	t.Cleanup(endpoint.Close)
	return endpoint
}

func (e *Endpoint) URL() string {
	if e == nil || e.server == nil {
		return ""
	}
	return e.server.URL
}

func (e *Endpoint) Client() *http.Client {
	if e == nil || e.server == nil {
		return nil
	}
	return e.server.Client()
}

func (e *Endpoint) Close() {
	if e != nil && e.server != nil {
		e.server.Close()
	}
}

func (e *Endpoint) Requests() []CapturedRequest {
	e.mu.Lock()
	defer e.mu.Unlock()
	requests := make([]CapturedRequest, len(e.requests))
	for index := range e.requests {
		requests[index] = e.requests[index].Clone()
	}
	return requests
}

func (e *Endpoint) Request(index int) (CapturedRequest, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if index < 0 || index >= len(e.requests) {
		return CapturedRequest{}, false
	}
	return e.requests[index].Clone(), true
}

func (e *Endpoint) LastRequest() (CapturedRequest, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.requests) == 0 {
		return CapturedRequest{}, false
	}
	return e.requests[len(e.requests)-1].Clone(), true
}

func (e *Endpoint) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	body, _ := io.ReadAll(request.Body)
	_ = request.Body.Close()

	e.mu.Lock()
	e.requests = append(e.requests, CapturedRequest{
		Method:     request.Method,
		URL:        request.URL.String(),
		Host:       request.Host,
		Header:     request.Header.Clone(),
		Body:       bytes.Clone(body),
		ReceivedAt: time.Now().UTC(),
	})
	response := Response{Status: http.StatusNoContent}
	if len(e.responses) > 0 {
		index := e.next
		if index >= len(e.responses) {
			index = len(e.responses) - 1
		} else {
			e.next++
		}
		response = cloneResponse(e.responses[index])
	}
	e.mu.Unlock()

	if response.Delay > 0 {
		timer := time.NewTimer(response.Delay)
		defer timer.Stop()
		select {
		case <-request.Context().Done():
			return
		case <-timer.C:
		}
	}
	for name, values := range response.Headers {
		for _, value := range values {
			writer.Header().Add(name, value)
		}
	}
	status := response.Status
	if status == 0 {
		status = http.StatusNoContent
	}
	writer.WriteHeader(status)
	_, _ = writer.Write(response.Body)
}

func cloneResponses(source []Response) []Response {
	result := make([]Response, len(source))
	for index := range source {
		result[index] = cloneResponse(source[index])
	}
	return result
}

func cloneResponse(source Response) Response {
	return Response{
		Status: source.Status, Headers: source.Headers.Clone(),
		Body: bytes.Clone(source.Body), Delay: source.Delay,
	}
}
