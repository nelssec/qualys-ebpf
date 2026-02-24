.PHONY: build build-linux build-all docker run clean test

BINARY_NAME=eventgen
VERSION=1.0.0
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"

build:
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/main.go

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-amd64 ./cmd/main.go
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-arm64 ./cmd/main.go

build-all: build build-linux

docker:
	docker build -t qualys/eventgen:$(VERSION) -t qualys/eventgen:latest .

run:
	go run ./cmd/main.go -i

run-all:
	go run ./cmd/main.go -all -delay 1s

list:
	go run ./cmd/main.go -list

clean:
	rm -rf bin/

test:
	go run ./cmd/main.go -event QCR001
