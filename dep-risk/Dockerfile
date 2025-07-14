# Multi-stage build for optimal size and security
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o dep-risk ./cmd/action

# Install scanning tools
FROM alpine:3.18 AS tools

# Install syft
RUN wget -qO- https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Install osv-scanner (detect architecture)
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then ARCH="amd64"; elif [ "$ARCH" = "aarch64" ]; then ARCH="arm64"; fi && \
    wget -qO- https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_${ARCH} -O /usr/local/bin/osv-scanner && \
    chmod +x /usr/local/bin/osv-scanner

# Final stage - use alpine for debugging and tool compatibility
FROM alpine:3.18

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Copy scanning tools
COPY --from=tools /usr/local/bin/syft /usr/local/bin/syft
COPY --from=tools /usr/local/bin/osv-scanner /usr/local/bin/osv-scanner

# Copy our application
COPY --from=builder /app/dep-risk /usr/local/bin/dep-risk

# Create non-root user
RUN addgroup -g 65532 -S nonroot && adduser -u 65532 -S nonroot -G nonroot
USER nonroot:nonroot

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/dep-risk"]
