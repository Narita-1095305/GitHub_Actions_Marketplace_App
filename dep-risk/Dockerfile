# Multi-stage build for optimal size and security
FROM golang:1.21-alpine AS builder

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

# Install osv-scanner
RUN wget -qO- https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64 -O /usr/local/bin/osv-scanner && \
    chmod +x /usr/local/bin/osv-scanner

# Final stage - distroless for security
FROM gcr.io/distroless/static:nonroot

# Copy CA certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy scanning tools
COPY --from=tools /usr/local/bin/syft /usr/local/bin/syft
COPY --from=tools /usr/local/bin/osv-scanner /usr/local/bin/osv-scanner

# Copy our application
COPY --from=builder /app/dep-risk /usr/local/bin/dep-risk

# Set user to non-root
USER 65532:65532

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/dep-risk"]
