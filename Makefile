GO ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
BIN := bin

# Static, path-stripped, symbol-stripped. Two people building the same commit
# should get identical bytes, so a published binary can be checked against the
# published source. That property is doing real work here: this project asks
# people to run something on a computer in their house.
BUILD_FLAGS := -trimpath -ldflags="-s -w -buildid="
export CGO_ENABLED = 0

.PHONY: all build test check vet fmt fmt-check tidy clean install-local e2e

all: check build

build:
	@mkdir -p $(BIN)
	$(GO) build $(BUILD_FLAGS) -o $(BIN)/mm-agent   ./cmd/mm-agent
	$(GO) build $(BUILD_FLAGS) -o $(BIN)/mm-gateway ./cmd/mm-gateway
	$(GO) build $(BUILD_FLAGS) -o $(BIN)/mm-edge    ./cmd/mm-edge
	@echo "built $(VERSION) into $(BIN)/"

test:
	$(GO) test ./...

# The end-to-end test alone: a real gateway, edge and agent in one process,
# with a request pushed through the whole path.
e2e:
	$(GO) test -v -count=1 ./internal/e2e/

vet:
	$(GO) vet ./...

fmt:
	gofmt -w ./cmd ./internal

fmt-check:
	@unformatted=$$(gofmt -l ./cmd ./internal); \
	if [ -n "$$unformatted" ]; then \
		echo "These files need gofmt:"; echo "$$unformatted"; exit 1; \
	fi

tidy:
	$(GO) mod tidy

check: fmt-check vet test

# Install the two server binaries locally, for testing a node without the
# full VPS installer.
install-local: build
	install -m 0755 $(BIN)/mm-gateway /usr/local/bin/mm-gateway
	install -m 0755 $(BIN)/mm-edge    /usr/local/bin/mm-edge

clean:
	rm -rf $(BIN)
