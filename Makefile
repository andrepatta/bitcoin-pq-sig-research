BINDIR     := build/bin
BIN        := $(BINDIR)/qbitcoind
CLI        := $(BINDIR)/qbitcoin-cli
MINER      := $(BINDIR)/qbitcoin-miner
PKG        := ./cmd/qbitcoind
CLI_PKG    := ./cmd/qbitcoin-cli
MINER_PKG  := ./cmd/qbitcoin-miner
DATADIR    ?= ./data
GOFLAGS    ?=
LDFLAGS    ?= -s -w

# Pinned tool versions. Single source of truth — CI reads these via `make lint`.
GOLANGCI_LINT_VERSION := v2.11.4
GOLANGCI_LINT         := $(BINDIR)/golangci-lint

.PHONY: build cli miner all run clean tidy vet lint lint-gofmt lint-golangci test fmt install release help

build: ## Build the qbitcoind binary into build/bin/
	@mkdir -p $(BINDIR)
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN) $(PKG)

cli: ## Build the qbitcoin-cli binary into build/bin/
	@mkdir -p $(BINDIR)
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(CLI) $(CLI_PKG)

miner: ## Build the qbitcoin-miner binary into build/bin/
	@mkdir -p $(BINDIR)
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(MINER) $(MINER_PKG)

all: build cli miner ## Build all three binaries

release: GOFLAGS += -trimpath
release: all ## Build stripped, reproducible binaries

run: build ## Build and run with default flags
	$(BIN) -datadir $(DATADIR)

install: ## Install all binaries into $GOBIN
	go install $(GOFLAGS) -ldflags "$(LDFLAGS)" $(PKG) $(CLI_PKG) $(MINER_PKG)

tidy: ## go mod tidy
	go mod tidy

vet: ## go vet
	go vet ./...

lint: lint-gofmt lint-golangci ## Run gofmt + golangci-lint (mirrors .github/workflows/lint.yml)

lint-gofmt: ## Fail if any Go files in the main module need formatting
	@dirs=$$(go list -f '{{.Dir}}' ./...); \
	out=$$(gofmt -l $$dirs); \
	if [ -n "$$out" ]; then \
		echo "gofmt: these files are not formatted (run 'make fmt'):"; \
		echo "$$out"; \
		exit 1; \
	fi

lint-golangci: $(GOLANGCI_LINT) ## Run pinned golangci-lint against the whole module
	$(GOLANGCI_LINT) run ./...

# Install the pinned golangci-lint into build/bin. Re-installs when the
# on-disk binary's version doesn't match GOLANGCI_LINT_VERSION, so bumping
# the version in this Makefile is sufficient to roll the toolchain.
$(GOLANGCI_LINT):
	@mkdir -p $(BINDIR)
	@if [ ! -x "$(GOLANGCI_LINT)" ] || ! "$(GOLANGCI_LINT)" --version 2>/dev/null | grep -q "$(patsubst v%,%,$(GOLANGCI_LINT_VERSION))"; then \
		echo "installing golangci-lint $(GOLANGCI_LINT_VERSION) → $(GOLANGCI_LINT)"; \
		GOBIN=$(abspath $(BINDIR)) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION); \
	fi

fmt: ## gofmt -s -w
	gofmt -s -w .

test: ## Run all tests
	go test ./...

clean: ## Remove build/ and local data dirs
	rm -rf build data data2

help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
