# Development tasks for guard.
#
# guard never executes the commands it assesses, and nothing here runs one
# either -- `make test` and `make test-bench` only parse and analyze strings.

BINARY := guard
CMD    := ./cmd/guard
PKGS   := ./...
COVER  := coverage.out

.DEFAULT_GOAL := help
.PHONY: help build test test-bench test-cover check clean

## help:       list the targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  make /'

## build:      compile the binary to ./guard
build:
	go build -o $(BINARY) $(CMD)

## test:       run the suite under the race detector
#
# -race is the default rather than a separate target because the server shares
# one knowledge base across every request, and a test asserts that is safe.
# A guarantee nobody checks is not a guarantee.
test:
	go test -race $(PKGS)

## test-bench: measure time and allocations for the parse -> assess flow
#
# -run '^$$' skips the tests, so only benchmarks run. Use -count=10 and
# benchstat to compare a change against a baseline; the README records one.
test-bench:
	go test $(PKGS) -bench . -benchmem -run '^$$'

## test-cover: report statement coverage across all packages
#
# -coverpkg=./... counts what the whole suite exercises, not just what each
# package's own tests touch. Without it the cross-package tests -- the CLI
# driving the analyzer, the server driving the API -- would not be credited.
test-cover:
	go test $(PKGS) -covermode=atomic -coverpkg=$(PKGS) -coverprofile=$(COVER)
	@echo
	@go tool cover -func=$(COVER) | tail -1
	@echo "  line detail: go tool cover -html=$(COVER)"

## check:      vet, and fail on anything unformatted
check:
	go vet $(PKGS)
	@test -z "$$(gofmt -l . )" || { echo "unformatted:"; gofmt -l .; exit 1; }

## clean:      remove build and coverage artifacts
clean:
	rm -f $(BINARY) $(COVER)
