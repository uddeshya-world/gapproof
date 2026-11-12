SHELL := /bin/bash
.DEFAULT_GOAL := build

VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo v0.0.0-dev)
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE      ?= $(shell git log -1 --format=%cI 2>/dev/null || echo unknown)
# Go Cryptographic Module snapshot. The Go toolchain marks v1.0.0 as "certified"
# (GOROOT/lib/fips140/certified.txt); verify the CMVP certificate before claiming it.
GOFIPS140 ?= v1.0.0
# Harness image pin (spec §3.1): written by `make harness`, baked into later builds.
HARNESS_PIN_FILE ?= dist/harness.pin
HARNESS_PIN := $(shell cat $(HARNESS_PIN_FILE) 2>/dev/null)
HPKG      := github.com/uddeshya-world/gapproof/internal/harness
LDFLAGS   := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE) \
             $(if $(HARNESS_PIN),-X $(HPKG).PinnedConfigDigest=$(word 1,$(HARNESS_PIN)) -X $(HPKG).PinnedLayers=$(word 2,$(HARNESS_PIN))) \
             $(if $(LICENCE_PUB),-X github.com/uddeshya-world/gapproof/internal/licence.PublicKey=$(LICENCE_PUB))
# LICENCE_PUB: base64 Ed25519 public key that release builds pin for Pro licences
# (the private key never lives in this repo). Unset = development build, free features only.
HARNESS_ARCH ?= $(shell go env GOARCH)
HARNESS_DIR  ?= dist
HARNESS_TAR  := $(HARNESS_DIR)/gapproof-harness-$(VERSION)-linux-$(HARNESS_ARCH).oci.tar
ENGINE ?= $(shell command -v docker || command -v podman)
STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.2
# 25 MiB (M0 acceptance)
MAX_BIN_BYTES := 26214400
BIN := bin/gapproof

.PHONY: build test lint e2e size clean harness demo demo-images demo-scan demo-e2e

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
	go run -exec "env GOOS=linux" $(STATICCHECK) ./... # analyse the shipped (Linux) target

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

release-harness: ## release: build + pin the harness for amd64 and arm64 into release-assets/ (goreleaser reads release-assets/harness.env)
	rm -rf release-assets && mkdir -p release-assets
	for a in amd64 arm64; do \
	  $(MAKE) harness HARNESS_ARCH=$$a HARNESS_DIR=release-assets HARNESS_PIN_FILE=release-assets/harness-$$a.pin || exit 1; \
	  set -- $$(cat release-assets/harness-$$a.pin); \
	  echo "HARNESS_CFG_$$a=$$1" >> release-assets/harness.env; \
	  echo "HARNESS_LAYERS_$$a=$$2" >> release-assets/harness.env; \
	done
	cd release-assets && sha256sum gapproof-harness-*.oci.tar > harness-checksums.sha256

# Demo targets (spec §4). Building the images uses the network (pip); the
# scans never do: images are saved locally and run with all egress blocked.
DEMO_OBSERVE ?= 3m
DEMO_ARCH    ?= $(shell go env GOARCH)
DEMO_TAG     ?= dev
DEMO_SCAN     = ./$(BIN) scan --observe $(DEMO_OBSERVE)

demo: harness ## build both demo images, then scan them into evidence/{leaky,fixed}-rag (< 15 min)
	@$(MAKE) --no-print-directory build   # second make so the fresh harness pin is baked in
	./$(BIN) harness load $(HARNESS_TAR)
	@$(MAKE) --no-print-directory demo-images demo-scan

# No provenance/SBOM attestations: with them, `docker save` writes an OCI index
# whose identity gapproof can't match to the loaded image (see demo/README.md).
DEMO_BUILD = $(ENGINE) build --provenance=false --sbom=false

demo-images:
	-$(ENGINE) rmi gapproof-demo/leaky-rag:$(DEMO_TAG) gapproof-demo/fixed-rag:$(DEMO_TAG) 2>/dev/null
	$(DEMO_BUILD) -t gapproof-demo/leaky-rag:$(DEMO_TAG) demo/leaky-rag
	$(DEMO_BUILD) -t gapproof-demo/fixed-rag:$(DEMO_TAG) demo/fixed-rag

demo-scan:
	rm -rf evidence/leaky-rag evidence/fixed-rag && mkdir -p evidence
	$(DEMO_SCAN) --image gapproof-demo/leaky-rag:$(DEMO_TAG) --workload demo/leaky-rag/workload.sh \
	  --agents demo/leaky-rag/agents.yaml --out evidence/leaky-rag
	$(DEMO_SCAN) --image gapproof-demo/fixed-rag:$(DEMO_TAG) --workload demo/fixed-rag/workload.sh \
	  --agents demo/fixed-rag/agents.yaml --scope demo/fixed-rag/gapproof.scope.yaml \
	  --waivers demo/fixed-rag/gapproof.waivers.$(DEMO_ARCH).yaml --out evidence/fixed-rag

demo-e2e: ## after `make demo`: assert levels + findings, rescan both and require byte-identical evidence.json
	GAPPROOF_DEMO_E2E=1 DEMO_OBSERVE=$(DEMO_OBSERVE) DEMO_ARCH=$(DEMO_ARCH) DEMO_TAG=$(DEMO_TAG) \
	  go test -count=1 -timeout 30m -run TestDemoApps -v ./cmd/gapproof

clean:
	rm -rf bin dist release-assets
