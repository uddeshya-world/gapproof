SHELL := /bin/bash
.DEFAULT_GOAL := build

VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo v0.0.0-dev)
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE      ?= $(shell git log -1 --format=%cI 2>/dev/null || echo unknown)
# Go Cryptographic Module snapshot. The Go toolchain marks v1.0.0 as "certified"
# (GOROOT/lib/fips140/certified.txt); verify the CMVP certificate before claiming it.
GOFIPS140 ?= v1.0.0
LDFLAGS   := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.2
# 25 MiB (M0 acceptance)
MAX_BIN_BYTES := 26214400
BIN := bin/gapproof

.PHONY: build test lint e2e size clean

build: ## static binary in FIPS 140-3 module mode
	CGO_ENABLED=0 GOFIPS140=$(GOFIPS140) go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/gapproof
	@$(MAKE) --no-print-directory size

size:
	@bytes=$$(wc -c < $(BIN) | tr -d ' '); \
	echo "$(BIN): $$bytes bytes (limit $(MAX_BIN_BYTES))"; \
	test $$bytes -le $(MAX_BIN_BYTES) || { echo "binary too large"; exit 1; }

test: ## unit tests (TestNoEgress skips without a container engine)
	go test -count=1 -cover ./...

lint:
	@unformatted=$$(gofmt -l .); test -z "$$unformatted" || { echo "gofmt needed:"; echo "$$unformatted"; exit 1; }
	go vet ./...
	go run $(STATICCHECK) ./...

e2e: ## container tests; fails (not skips) without Docker/Podman. M4 adds the demo scans.
	GAPPROOF_REQUIRE_CONTAINER=1 go test -count=1 -run 'TestNoEgress|TestRealDockerSave' -v ./...

clean:
	rm -rf bin dist
