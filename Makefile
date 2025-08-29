# Wraith Package Scanner Makefile
default: help

# Build configuration
BINARY_NAME = wraith
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS = -ldflags "-X main.version=$(VERSION)"

.PHONY: help
help: ## Show this help
	@echo "Usage: make [target]\n"
	@cat ${MAKEFILE_LIST} | grep "[#]# " | grep -v grep | sort | column -t -s '##' | sed -e 's/^/ /'
	@echo ""

.PHONY: build
build: ## Build the binary
	go build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/wraith

.PHONY: deps
deps: ## Install Go dependencies
	go mod download
	go mod tidy

.PHONY: clean
clean: ## Clean build artifacts
	rm -f $(BINARY_NAME)
	go clean

.PHONY: test-all
test-all: ## Run all tests (unit + integration)
	go test -v ./...

.PHONY: test
test: ## Run unit tests only (fast, no OSV-Scanner required)
	go test -v ./pkg/... -short

.PHONY: test-integration
test-integration: ## Run integration tests (requires OSV-Scanner)
	@which osv-scanner || (echo "❌ osv-scanner not found in PATH." && exit 1)
	go test -v ./pkg/... -run "Integration"

.PHONY: test-demo
test-demo: ## Run live demo with real lockfiles
	@which osv-scanner || (echo "❌ osv-scanner not found in PATH." && exit 1)
	go test -v ./pkg/... -run "QuickScan"

.PHONY: lint
lint: ## Run linter
	@which golangci-lint || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	golangci-lint run

