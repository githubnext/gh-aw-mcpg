# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -o flowguard .

# Runtime stage
FROM alpine:latest

# Install Docker CLI for launching backend MCP servers
RUN apk add --no-cache docker-cli

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/flowguard .

# Expose default HTTP port
EXPOSE 3000

# Default command
ENTRYPOINT ["/app/flowguard"]
CMD ["--config", "/app/config.toml"]
