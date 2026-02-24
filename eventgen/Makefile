.PHONY: build build-linux build-all docker docker-production docker-eventgen run clean test

BINARY_NAME=qcr
VERSION=1.0.3
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"

build:
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/main.go

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-amd64 ./cmd/main.go
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-arm64 ./cmd/main.go

build-all: build build-linux

docker-production:
	docker build --target production -t qualys/qcr:$(VERSION) -t qualys/qcr:latest .

docker-eventgen:
	docker build --target eventgen -t qualys/qcr-eventgen:$(VERSION) -t qualys/qcr-eventgen:latest .

docker: docker-production docker-eventgen

run:
	./bin/$(BINARY_NAME)

events:
	./bin/$(BINARY_NAME) events -i

events-list:
	./bin/$(BINARY_NAME) events -list

events-all:
	./bin/$(BINARY_NAME) events -all -delay 1s

drift-list:
	./bin/$(BINARY_NAME) drift list

drift-detect:
	./bin/$(BINARY_NAME) drift generate -mode detect

drift-enforce:
	./bin/$(BINARY_NAME) drift generate -mode enforce

clean:
	rm -rf bin/ drift-policies/

test:
	./bin/$(BINARY_NAME) events -event QCR001
