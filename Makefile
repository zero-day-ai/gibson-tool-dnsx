# Gibson Tool: dnsx
# Self-contained Makefile for proto generation and building

PROTOC ?= protoc
PROTO_DIR := proto
GEN_DIR := gen

# Find SDK proto directory via go module
SDK_PROTO := $(shell go list -m -f '{{.Dir}}' github.com/zero-day-ai/sdk 2>/dev/null)/api/proto

.PHONY: all build test proto proto-clean proto-deps

all: proto build

# Install protoc plugins
proto-deps:
	@go install google.golang.org/protobuf/cmd/protoc-gen-go@latest

# Generate Go code from proto files
proto: proto-deps $(GEN_DIR)
	@echo "Generating protos for dnsx..."
	$(PROTOC) \
		--proto_path=$(PROTO_DIR) \
		--proto_path=$(SDK_PROTO) \
		--go_out=$(GEN_DIR) \
		--go_opt=paths=source_relative \
		$(wildcard $(PROTO_DIR)/*.proto)

$(GEN_DIR):
	mkdir -p $(GEN_DIR)

# Clean generated proto files
proto-clean:
	rm -rf $(GEN_DIR)

build:
	go build ./...

test:
	go test ./...
