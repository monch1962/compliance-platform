# Multi-stage build for compliance-gate GitHub Action
FROM golang:1.21-alpine AS builder

# Install dependencies
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /app

# Copy go mod and sum files
COPY packages/cicd-gate/go.mod packages/cicd-gate/go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY packages/cicd-gate/ .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o compliance-gate \
    ./main.go

# Copy policies
COPY packages/policies/ /app/policies/

# Final stage: distroless runtime
FROM gcr.io/distroless/static

# Copy the binary
COPY --from=builder /app/compliance-gate /usr/local/bin/compliance-gate

# Copy policies
COPY --from=builder /app/policies/ /etc/compliance-gate/policies/

# Copy CA certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Set user
USER 65534:65534

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/compliance-gate"]

# Labels
LABEL org.opencontainers.image.title="Compliance Gate"
LABEL org.opencontainers.image.description="Check IaC against Australian ISM and Essential Eight compliance policies"
LABEL org.opencontainers.image.source="https://github.com/monch1962/compliance-platform"
LABEL org.opencontainers.image.licenses="Apache-2.0"
