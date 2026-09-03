# syntax=docker/dockerfile:1

# ------------------------------------------------------------------ build
#
# Pinned to the BUILD platform and cross-compiled from there, so a multi-arch
# build compiles twice natively instead of running a second toolchain under
# emulation.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build

WORKDIR /src

# Dependencies first: a source-only change then reuses this layer.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags='-s -w' -o /out/guard ./cmd/guard

# ---------------------------------------------------------------- runtime
#
# distroless/static: no shell, no package manager, nothing but the binary and
# the config. Fitting for a tool whose whole claim is that it never executes
# anything -- there is nothing in here for it to execute.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/guard /usr/local/bin/guard

# The base is embedded in the binary too, but shipping it as a file and
# pointing --kb at it makes the file authoritative: mount your own over
# /etc/guard/knowledge.yaml and the container runs your policy, with
# /api/v1/knowledge naming which one it loaded.
COPY pkg/knowledge/knowledge.yaml /etc/guard/knowledge.yaml

# Set as an environment default rather than a CMD flag. Explicit arguments
# replace CMD wholesale, so `docker run guard config check` would otherwise
# quietly validate the embedded base instead of the mounted one.
ENV GUARD_KB=/etc/guard/knowledge.yaml

EXPOSE 8080

# `docker run guard` serves; `docker run guard assess '<cmd>'` assesses.
#
# --addr :8080 rather than the CLI's loopback default: inside a container
# loopback is unreachable from outside it, and the network namespace is the
# boundary that the loopback default provides on a host.
ENTRYPOINT ["/usr/local/bin/guard"]
CMD ["serve", "--addr", ":8080"]
