include ../../proto.mk

.PHONY: all build test

all: proto build

build:
	go build ./...

test:
	go test ./...
