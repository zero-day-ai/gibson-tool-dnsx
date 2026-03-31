# Multi-stage Dockerfile for dnsx tool
#
# Stage 1: Download dnsx binary from ProjectDiscovery releases
# Stage 2: Build Go wrapper binary
# Stage 3: Runtime alpine image with non-root user
#
# Build: docker build -t dnsx-tool .
# Run: docker run -p 50051:50051 -p 8080:8080 dnsx-tool

# ============================================================================
# Stage 1: Downloader - Download dnsx binary
# ============================================================================
FROM alpine:3.21 AS downloader

# Install download dependencies
RUN apk add --no-cache wget unzip

# Download dnsx binary from ProjectDiscovery releases
# Using v1.2.1 - stable release with JSON output support
ARG DNSX_VERSION=1.2.1
RUN wget -qO /tmp/dnsx.zip \
    "https://github.com/projectdiscovery/dnsx/releases/download/v${DNSX_VERSION}/dnsx_${DNSX_VERSION}_linux_amd64.zip" && \
    unzip /tmp/dnsx.zip -d /tmp && \
    chmod +x /tmp/dnsx && \
    rm -f /tmp/dnsx.zip

# ============================================================================
# Stage 2: Builder - Build Go wrapper binary
# ============================================================================
FROM golang:1.25-alpine AS builder

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -a -installsuffix cgo \
    -ldflags '-extldflags "-static"' \
    -o dnsx-tool ./cmd

# ============================================================================
# Stage 3: Runtime - Alpine with non-root user
# ============================================================================
FROM alpine:3.21

# Install runtime dependencies
# - ca-certificates: TLS certificate verification
# - tzdata: Timezone data for proper timestamp handling
# - wget: Health check endpoint verification
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    wget

# Create non-root user gibson with UID/GID 1000
# This follows Kubernetes security best practices
RUN addgroup -g 1000 gibson && \
    adduser -D -u 1000 -G gibson -h /home/gibson -s /bin/sh gibson

# Copy dnsx binary from downloader stage
COPY --from=downloader /tmp/dnsx /usr/local/bin/dnsx

# Copy the Go wrapper binary from builder stage
COPY --from=builder /build/dnsx-tool /usr/local/bin/dnsx-tool

# Ensure binaries are executable
RUN chmod +x /usr/local/bin/dnsx /usr/local/bin/dnsx-tool

# Create working directory for the tool
WORKDIR /home/gibson

# Change ownership of binaries to gibson user
RUN chown gibson:gibson /usr/local/bin/dnsx-tool

# Expose gRPC port for tool service
EXPOSE 50051

# Expose health port for Kubernetes probes
EXPOSE 8080

# Health check using wget to verify the health endpoint
# Checks every 30s, times out after 10s, retries 3 times before unhealthy
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/healthz || exit 1

# Run as non-root user
USER gibson

# Set entrypoint to the Go wrapper binary
ENTRYPOINT ["/usr/local/bin/dnsx-tool"]
