# Build stage
FROM golang:1.24-alpine AS builder

# Accept GitHub token as build argument
ARG GH_TOKEN

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates git

# Configure git to use the GitHub token for private repositories
RUN if [ -n "$GH_TOKEN" ]; then \
      git config --global url."https://${GH_TOKEN}:x-oauth-basic@github.com/".insteadOf "https://github.com/"; \
    fi

WORKDIR /app

# Create kms directory and copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o kms-server cmd/kms-server/main.go

# Final stage
FROM alpine:latest

# Labels to enable Confidential Space features
LABEL tee.launch_policy.allow_cmd_override=true
LABEL tee.launch_policy.log_redirect=always
LABEL "tee.launch_policy.allow_env_override"="PORT,LOG_LEVEL,DEBUG_MODE,ENV_RATE_LIMIT,API_KEY,GOOGLE_CLOUD_PROJECT,ATTESTATION_PROJECT_ID,KMS_LOCATION,KMS_KEY_RING,KMS_HMAC_KEY_NAME,KMS_ENCRYPTION_KEY_NAME,KMS_SIGNING_KEY_NAME,RPC_URL,APP_CONTROLLER_ADDRESS"

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/kms-server .

# Expose port
EXPOSE 8080

# Run the binary
CMD ["./kms-server"]