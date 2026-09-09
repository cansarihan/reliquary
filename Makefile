BINARY   := reliquary
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
GOFILES  := $(shell find . -name '*.go' -not -path './vendor/*')

.PHONY: all build test race cover lint fmt vet tidy run demo demo-down docker clean

all: lint test build

build:
	@mkdir -p bin
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/reliquary

test:
	go test ./...

race:
	go test -race ./...

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

lint:
	golangci-lint run

fmt:
	gofmt -w $(GOFILES)

vet:
	go vet ./...

tidy:
	go mod tidy

run: build
	./bin/$(BINARY) serve

demo:
	docker compose -f deploy/docker-compose.yml up --build -d
	@echo "panel: http://127.0.0.1:18140"

demo-down:
	docker compose -f deploy/docker-compose.yml down -v

docker:
	docker build -t reliquary:$(VERSION) .

clean:
	rm -rf bin dist coverage.out coverage.html
