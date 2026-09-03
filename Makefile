# Development tasks for guard.
#
# guard never executes the commands it assesses, and nothing here runs one
# either -- `make test` and `make test-bench` only parse and analyze strings.

BINARY := guard
CMD    := ./cmd/guard
PKGS   := ./...
COVER  := coverage.out
ADDR   ?= 127.0.0.1:8080

IMAGE     ?= guard
TAG       ?= dev
PLATFORMS ?= linux/amd64,linux/arm64
BUILDER   ?= guard-builder
OCI       := guard-oci.tar

# Where a multi-arch build puts its result.
#
# A manifest list cannot go into the classic docker image store -- `--load`
# fails with "docker exporter does not currently support exporting manifest
# lists" -- so the default writes an OCI archive, which works with no registry
# and no containerd image store. Set DOCKER_OUTPUT=--push to publish instead.
DOCKER_OUTPUT ?= --output=type=oci,dest=$(OCI)

.DEFAULT_GOAL := help
.PHONY: help build test test-integration test-bench test-cover check clean docker docker-local dev.run

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

## test-integration: smoke-test the built binary end to end
#
# Builds ./guard and runs it: real argv, real stdin, real exit codes, a real
# listening socket and a real SIGTERM. Everything else in the suite is
# in-process, so main() and ListenAndServe have no other coverage.
#
# `make test` includes these, since ./... covers them.
test-integration:
	go test ./test/integration -v

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

## dev.run:    run the HTTP server from source, with no build step
#
# Loopback by default, unlike the container image: on a host there is no
# network namespace to be the boundary, so the server should not be reachable
# from off the machine.
#
#   make dev.run
#   make dev.run ADDR=127.0.0.1:9000
#   GUARD_KB=./my-knowledge.yaml make dev.run
dev.run:
	go run $(CMD) serve --addr $(ADDR)

## docker:     build the multi-arch distroless image
#
# The default docker driver cannot build more than one platform, so this uses
# a docker-container builder, created on first use. The build cross-compiles
# from the build platform rather than emulating the target, so two
# architectures cost roughly one architecture's time.
#
#   make docker                             -> ./guard-oci.tar
#   make docker DOCKER_OUTPUT=--push \
#        IMAGE=ghcr.io/you/guard TAG=v1     -> pushed to a registry
docker:
	@docker buildx inspect $(BUILDER) >/dev/null 2>&1 || \
	  docker buildx create --name $(BUILDER) --driver docker-container >/dev/null
	docker buildx build --builder $(BUILDER) --platform $(PLATFORMS) \
	  -t $(IMAGE):$(TAG) $(DOCKER_OUTPUT) .

## docker-local: build for this machine only, loaded and ready to run
#
# What you want while developing: a manifest list is not runnable locally, a
# single-platform image is.
#
#   make docker-local && docker run --rm -p 8080:8080 $(IMAGE):$(TAG)
docker-local:
	docker buildx build -t $(IMAGE):$(TAG) --load .

## clean:      remove build and coverage artifacts
clean:
	rm -f $(BINARY) $(COVER) $(OCI)
