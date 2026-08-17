# Load .env if it exists. All variables from it become available to make targets.
-include .env
export

VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X main.buildVersion=$(VERSION) -X main.buildDate=$(BUILD_DATE)

.PHONY: test lint build proto-tools

test:
	go test ./... -count=1

lint:
	golangci-lint run ./...

# Build server and client binaries with version info.
build:
	go build -ldflags "$(LDFLAGS)" -o bin/server ./cmd/server
	go build -ldflags "$(LDFLAGS)" -o bin/client ./cmd/client

# Install protoc plugins with pinned versions.
proto-tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2
