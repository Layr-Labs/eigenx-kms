# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

EigenX KMS is a Key Management Service designed for Trusted Execution Environments (TEEs), specifically Google Confidential Spaces running on Intel TDX. The KMS serves encrypted secrets and generates persistent private keys for applications while ensuring only authorized, attested code can access them.

**⚠️ Alpha Status**: This project is in alpha, under active development, and has not been audited. It should be used only for testing purposes and not in production.

## Build & Test Commands

```bash
# Build the KMS client for Linux
make build-kms-client

# Generate mocks for testing
make generate-kms-mocks

# Run all tests
make test-kms

# Standard Go commands
go build -o kms-server cmd/kms-server/main.go
go build -o kms-client cmd/kms-client/main.go
go test ./...
go test ./pkg/crypto -v  # Run tests for a specific package
```

## Architecture

### Core Components

**Two binaries:**
1. **kms-server** (`cmd/kms-server/main.go`): HTTP server that runs in a Google Confidential Space, handles attestation verification, decrypts environment variables, and generates mnemonics for applications
2. **kms-client** (`cmd/kms-client/main.go`): Client binary that obtains attestation tokens, sends requests to the KMS server, and retrieves environment variables for applications

**Package structure:**
- `internal/handlers/`: HTTP request handlers for the KMS server endpoints (`/env`, `/env/v2`, `/addresses`, `/addresses/v2`, `/health`)
- `internal/kms/`: GCP KMS client wrapper for encryption/decryption, signing, and HMAC operations
- `internal/utils/`: CLI flag definitions and configuration management for both server and client
- `pkg/attestation/`: JWT verification for Google Confidential Space and Intel Trust Authority attestations
- `pkg/chainclient/`: Ethereum blockchain client for fetching application release data from the AppController contract
- `pkg/crypto/`: Cryptographic operations including RSA key generation, JWE encryption/decryption, key derivation, and address generation
- `pkg/envclient/`: Client library for requesting environment variables from the KMS server with attestation
- `pkg/types/`: Shared type definitions for API requests/responses and interfaces

### Request Flow (V2 Endpoint)

1. **Client generates ephemeral RSA key pair** (4096-bit)
2. **Client calculates SHA-256 hash of RSA public key** with `ENV_REQUEST_RSA_KEY` header
3. **Client requests attested JWT from Intel Trust Authority** with RSA key hash as `eat_nonce`
4. **Client sends plaintext request** to `/env/v2` with JWT + RSA public key
5. **Server verifies JWT signature** against Intel Trust Authority JWKS
6. **Server extracts nonce from JWT** and verifies it matches RSA key hash (prevents key substitution attacks)
7. **Server queries blockchain** for latest release via `AppController` contract
8. **Server verifies image_digest** in JWT matches the on-chain release
9. **Server decrypts privateEnv** using GCP KMS (RSA-OAEP-256 + AES-256-GCM via JWE)
10. **Server generates mnemonic** deterministically via HMAC of appID
11. **Server combines mnemonic + privateEnv + publicEnv** into response
12. **Server encrypts response** with client's attested RSA public key
13. **Server signs encrypted data** with `KMS_SIGNING_PRIVATE_KEY`
14. **Client verifies signature** and decrypts with ephemeral RSA private key

### GCP KMS Keys

The KMS system uses three keys managed by GCP KMS:
1. **KMS_DECRYPTION_KEY**: RSA asymmetric encryption/decryption key (rsa-decrypt-oaep-4096-sha256) for decrypting application secrets
2. **KMS_HMAC_KEY**: HMAC key (hmac-sha256) for deterministic mnemonic generation per app
3. **KMS_SIGNING_PRIVATE_KEY**: Asymmetric signing key (ec-sign-p256-sha256) for signing KMS responses

### Attestation

Two attestation providers are supported:
- **Google Confidential Space** (V1 endpoint): Uses Google's attestation service with JWKS from `https://www.googleapis.com/service_accounts/v1/metadata/jwk/...`
- **Intel Trust Authority** (V2 endpoint): Uses Intel's attestation service with JWKS from `https://portal.trustauthority.intel.com/certs`

V2 is preferred as it cryptographically binds the RSA public key to the attestation via nonce, preventing key substitution attacks. V1 attestations must remain private as they can be replayed with a different RSA key.

### Cryptographic Operations

**Key headers used in signing/verification** (`pkg/crypto/crypto.go`):
- `KMSSignatureHeader`: "COMPUTE_APP_KMS_SIGNATURE_V1"
- `EnvRequestRSAKeyHeader`: "COMPUTE_APP_ENV_REQUEST_RSA_KEY_V1"
- `AppDerivedAddressesHeader`: "COMPUTE_APP_DERIVED_ADDRESSES_V1"
- `JWEAppIDHeader`: "x-eigenx-app-id" (protected header in JWE to prevent cross-app encryption replay)

**Mnemonic generation** is deterministic:
```go
seed = gcpkms.HMAC(sha256([]byte("COMPUTE_APP_KEY_DERIVATION_V1") || 0x00 || appId))
mnemonic = MnemonicFromSeed(seed)
```

### Blockchain Integration

The KMS verifies on-chain releases by:
1. Querying `AppController.GetAppLatestReleaseBlockNumber(appAddress)` to get the latest release block
2. Filtering `AppUpgraded` events at that block number for the app address
3. Extracting the release data which contains `imageDigest`, `encryptedEnv`, and `publicEnv`
4. Verifying the JWT's `image_digest` claim matches the on-chain digest

## Testing

- Tests use `go-mock` for mocking interfaces
- Generate mocks with `make generate-kms-mocks` or `go generate ./...`
- Mock files are located in `*/mocks/` subdirectories
- Key interfaces to mock: `AttestationVerifierInterface`, `ChainClient`, `KMSClient`, `AppController`
- E2E tests exist for the envclient package (`pkg/envclient/envclient_e2e_test.go`)

## Common Development Patterns

**Adding a new endpoint:**
1. Define request/response types in `pkg/types/server.go`
2. Add handler function in `internal/handlers/`
3. Register endpoint in `cmd/kms-server/main.go` with appropriate middleware (rate limiting, auth)
4. Add Swagger documentation comments using `@Summary`, `@Description`, etc.

**Working with GCP KMS:**
- The `kms.KMSClient` interface (`internal/kms/kms.go`) abstracts GCP KMS operations
- For testing, use fakes (`internal/kms/fakes/fake_kms.go`) or mocks (`internal/kms/mocks/mock_kms.go`)
- All KMS operations should use the client interface, never call GCP directly

**Attestation verification:**
- Always specify `AttestationProvider` (GoogleConfidentialSpace or IntelTrustAuthority)
- V1 endpoints must verify `nonce == ""`
- V2 endpoints must verify nonce matches RSA key hash
- All attestations must verify TEE environment (Intel TDX, STABLE OS image, etc.)

## Security Considerations

- V1 attestations without nonces must remain private and never be published
- RSA keys must be 4096-bit (validated by `crypto.ValidateRSAKeySize`)
- The `x-eigenx-app-id` protected header in JWE prevents cross-app encrypted data replay
- Response signing with `KMS_SIGNING_PRIVATE_KEY` prevents tampering during transit
- Debug mode (`--debug` flag) allows appID override via query param - never use in production

## Key Files

- `kms.md`: Detailed design document explaining KMS purpose, flow diagrams, and security model
- `Dockerfile`: Container image definition for running in Google Confidential Space
- `cmd/kms-server/main.go`: Server entry point with endpoint routing (lines 114-135)
- `cmd/kms-client/main.go`: Client entry point for requesting environment variables
- `internal/handlers/env.go`: Core logic for `/env` and `/env/v2` endpoints
- `pkg/attestation/attestation.go`: JWT verification and attestation claim extraction
- `pkg/chainclient/chainclient.go`: On-chain release verification
- `pkg/crypto/crypto.go`: Cryptographic primitives and key operations
