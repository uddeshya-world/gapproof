SHELL := /bin/bash
.DEFAULT_GOAL := build

VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo v0.0.0-dev)
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE      ?= $(shell git log -1 --format=%cI 2>/dev/null || echo unknown)
# Go Cryptographic Module snapshot. The Go toolchain marks v1.0.0 as "certified"
# (GOROOT/lib/fips140/certified.txt); verify the CMVP certificate before claiming it.
GOFIPS140 ?= v1.0.0
# Harness image pin (spec §3.1): written by `make harness`, baked into later builds.
HARNESS_PIN_FILE := dist/harness.pin
HARNESS_PIN := $(shell cat $(HARNESS_PIN_FILE) 2>/dev/null)
HPKG      := github.com/uddeshya-world/gapproof/internal/harness
LDFLAGS   := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE) \
             $(if $(HARNESS_PIN),-X $(HPKG).PinnedConfigDigest=$(word 1,$(HARNESS_PIN)) -X $(HPKG).PinnedLayers=$(word 2,$(HARNESS_PIN)))
HARNESS_ARCH ?= $(shell go env GOARCH)
HARNESS_TAR  := dist/gapproof-harness-$(VERSION)-linux-$(HARNESS_ARCH).oci.tar
ENGINE ?= $(shell command -v docker || command -v podman)
STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.2
# 25 MiB (M0 acceptance)
MAX_BIN_BYTES := 26214400
BIN := bin/gapproof

.PHONY: build test lint e2e size clean harness

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
	@unformatted=$$(gofmt -l cmd internal rules); test -z "$$unformatted" || { echo "gofmt needed:"; echo "$$unformatted"; exit 1; }
	go vet ./...
	go run $(STATICCHECK) ./...

e2e: harness build ## container tests (fail, never skip): no-egress, real images, the M3 egress harness
	./$(BIN) harness load $(HARNESS_TAR)
	GAPPROOF_REQUIRE_CONTAINER=1 go test -count=1 -run 'TestNoEgress|TestRealDockerSave|TestRealCryptographyWheel|TestEgressProbe|TestCancelCleansUp' -v ./...

harness: ## build the harness image tarball and pin it (needs Docker/Podman)
	mkdir -p dist/harness-ctx
	CGO_ENABLED=0 GOOS=linux GOARCH=$(HARNESS_ARCH) GOFIPS140=$(GOFIPS140) go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o dist/harness-ctx/gapproof ./cmd/gapproof
	cp deploy/harness/Dockerfile dist/harness-ctx/
	$(ENGINE) build --platform linux/$(HARNESS_ARCH) -t gapproof-harness:build dist/harness-ctx
	$(ENGINE) save -o $(HARNESS_TAR) gapproof-harness:build
	go run ./cmd/gapproof harness digest $(HARNESS_TAR) > $(HARNESS_PIN_FILE)
	@echo "pinned: $$(cat $(HARNESS_PIN_FILE) | cut -c1-80)…  rebuild with 'make build', then: bin/gapproof harness load $(HARNESS_TAR)"

clean:
	rm -rf bin dist
