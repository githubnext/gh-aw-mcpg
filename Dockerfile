# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .
RUN go mod tidy

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -o flowguard-go .

# Runtime stage
FROM alpine:latest

# Install Docker CLI and bash for launching backend MCP servers
RUN apk add --no-cache docker-cli bash

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/flowguard-go .

# Copy run.sh script
COPY run.sh .
RUN chmod +x run.sh

# Expose default HTTP port
EXPOSE 8000

# Use run.sh as entrypoint
ENTRYPOINT ["/app/run.sh"]
