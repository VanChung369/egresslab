
# Stage 1: Build the Go application on Linux.
FROM golang:1.27-alpine3.23 AS builder

WORKDIR /src

# Copy the module definition.
COPY go.mod ./

# Copy the Go application source.
COPY cmd/ ./cmd/
COPY internal/ ./internal/

# Run tests before building the executable.
RUN go test ./...

# Build a Linux executable without CGO.
RUN CGO_ENABLED=0 go build \
    -trimpath \
    -o /out/egresslab-agent \
    ./cmd/egresslab-agent


# Stage 2: Minimal runtime environment.
FROM alpine:3.23

# The Agent needs iproute2 to inspect Linux interfaces.
RUN apk add --no-cache \
    iproute2 \
    ca-certificates

# Copy only the compiled executable.
COPY --from=builder \
    /out/egresslab-agent \
    /usr/local/bin/egresslab-agent

# Run as an unprivileged user.
USER 65532:65532

# Start the Network Agent.
ENTRYPOINT ["/usr/local/bin/egresslab-agent"]
