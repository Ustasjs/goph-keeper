# Load .env if it exists. All variables from it become available to make targets.
-include .env
export

VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X main.buildVersion=$(VERSION) -X main.buildDate=$(BUILD_DATE)

.PHONY: run test lint build build-all cert clean proto proto-tools

run:
	go run ./cmd/server

test:
	go test ./... -count=1

lint:
	golangci-lint run ./...

# Make a self-signed certificate for local TLS.
cert:
	go run ./cmd/certgen -cert dev-cert.pem -key dev-key.pem

# Build server and client binaries with version info.
build:
	go build -ldflags "$(LDFLAGS)" -o bin/server ./cmd/server
	go build -ldflags "$(LDFLAGS)" -o bin/client ./cmd/client

# Build the client for every supported platform. The server
# stays local: it runs where the database is.
build-all:
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/client-linux-amd64    ./cmd/client
	GOOS=darwin  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/client-darwin-amd64   ./cmd/client
	GOOS=darwin  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o bin/client-darwin-arm64   ./cmd/client
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/client-windows-amd64.exe ./cmd/client
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/server-linux-amd64    ./cmd/server

clean:
	rm -rf bin

# Generate Go code from proto files into pkg/proto.
proto:
	protoc -I api/proto \
		--go_out=.      --go_opt=module=github.com/ustasjs/goph-keeper \
		--go-grpc_out=. --go-grpc_opt=module=github.com/ustasjs/goph-keeper \
		api/proto/gophkeeper/v1/gophkeeper.proto

# Install protoc plugins with pinned versions.
proto-tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2
