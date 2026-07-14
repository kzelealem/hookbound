SHELL := /bin/sh

.PHONY: fmt vet test test-race build verify

fmt:
	@test -z "$$(gofmt -l .)" || (gofmt -d .; exit 1)

vet:
	go vet ./...

test:
	go test ./...

test-race:
	go test -race ./...

build:
	go build ./...

verify: fmt vet test-race build
