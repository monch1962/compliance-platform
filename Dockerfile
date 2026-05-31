# Multi-stage build for compliance-gate GitHub Action
FROM golang:1.21-alpine AS builder

# Install dependencies
RUN apk add --no-cache git ca-certificates curl

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

# Download conftest (the OPA policy engine that compliance-gate wraps)
RUN curl -sL https://github.com/open-policy-agent/conftest/releases/download/v0.58.0/conftest_0.58.0_Linux_x86_64.tar.gz \
    -o /tmp/conftest.tar.gz && \
    tar xzf /tmp/conftest.tar.gz -C /usr/local/bin/ conftest && \
    chmod +x /usr/local/bin/conftest

# Copy policies
COPY packages/policies/ /app/policies/

# Final stage: distroless runtime
FROM gcr.io/distroless/static

# Copy the binary and conftest
COPY --from=builder /app/compliance-gate /usr/local/bin/compliance-gate
COPY --from=builder /usr/local/bin/conftest /usr/local/bin/conftest

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
