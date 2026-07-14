SHELL := /bin/sh

POSTGRES_IMAGE ?= postgres:17-alpine

.PHONY: fmt vet test test-race test-postgres-integration check-actions build verify verify-all

fmt:
	@test -z "$$(gofmt -l .)" || (gofmt -d .; exit 1)

vet:
	go vet ./...

test:
	go test -shuffle=on -count=1 ./...

test-race:
	go test -race -shuffle=on -count=1 ./...

test-postgres-integration:
	cd integration/postgres && HOOKBOUND_POSTGRES_IMAGE="$(POSTGRES_IMAGE)" go test -tags=integration -race -shuffle=on -count=1 ./...

check-actions:
	./scripts/check-workflow-pins.sh

build:
	go build ./...

verify: fmt vet test-race check-actions build

verify-all: verify test-postgres-integration
