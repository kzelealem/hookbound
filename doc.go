// Package hookbound provides secure inbound and outbound webhook primitives.
//
// Direct sends perform exactly one HTTP attempt. The receiver preserves and
// verifies the exact raw request body before dispatch. The optional postgres
// package adds durable inbox/outbox processing without changing these protocol
// semantics.
package hookbound
