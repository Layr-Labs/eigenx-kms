package envclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/Layr-Labs/eigenx-kms/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms/pkg/types"
	"github.com/cenkalti/backoff/v5"
)

const (
	initialInterval           = 500 * time.Millisecond
	maxInterval               = 5 * time.Second
	multiplier                = 1.5
	maxElapsedTime            = 2 * time.Minute
	attestationSocketPath     = "/run/container_launcher/teeserver.sock"
	attestationTokenURL       = "http://localhost/v1/token"
	confidentialSpaceAudience = "https://sts.googleapis.com"
)

// AttestationTokenProvider interface for generating attestation tokens
type AttestationTokenProvider interface {
	GetToken(ctx context.Context, nonces []string) (string, error)
}

// ConfidentialSpaceTokenProvider implements AttestationTokenProvider using GCP Confidential Space
type ConfidentialSpaceTokenProvider struct {
	logger *slog.Logger
}

func NewConfidentialSpaceTokenProvider(logger *slog.Logger) *ConfidentialSpaceTokenProvider {
	return &ConfidentialSpaceTokenProvider{logger: logger}
}

// attestationTokenRequest represents the request to the attestation service
type attestationTokenRequest struct {
	Audience  string   `json:"audience"`
	TokenType string   `json:"token_type"`
	Nonces    []string `json:"nonces,omitempty"`
}

func (p *ConfidentialSpaceTokenProvider) GetToken(ctx context.Context, nonces []string) (string, error) {
	// Create request with hard-coded audience
	tokenReq := attestationTokenRequest{
		Audience:  confidentialSpaceAudience,
		TokenType: "OIDC",
		Nonces:    nonces,
	}

	reqBody, err := json.Marshal(tokenReq)
	if err != nil {
		return "", fmt.Errorf("failed to marshal token request: %w", err)
	}

	// Create HTTP client that uses Unix socket
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", attestationSocketPath)
			},
		},
	}

	p.logger.Debug("Requesting attestation token", "audience", confidentialSpaceAudience, "nonces", nonces)

	req, err := http.NewRequestWithContext(ctx, "POST", attestationTokenURL, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("failed to create attestation request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to request attestation token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("attestation service returned status %d: %s", resp.StatusCode, string(body))
	}

	tokenBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read attestation token response: %w", err)
	}

	p.logger.Info("Successfully obtained attestation token")

	return string(tokenBytes), nil
}

type EnvClient struct {
	Logger        *slog.Logger
	tokenProvider AttestationTokenProvider
	kmsSigningKey []byte
	serverURL     string
}

func NewEnvClient(logger *slog.Logger, tokenProvider AttestationTokenProvider, kmsSigningKey []byte, serverURL string) *EnvClient {
	return &EnvClient{
		Logger:        logger,
		tokenProvider: tokenProvider,
		kmsSigningKey: kmsSigningKey,
		serverURL:     serverURL,
	}
}

func (e *EnvClient) GetEnv(ctx context.Context) ([]byte, error) {
	// Generate RSA key pair on the fly
	e.Logger.Info("Generating RSA key pair")
	rsaPrivateKeyPEM, rsaPublicKeyPEM, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	e.Logger.Debug("RSA key pair generated", "public_key_length", len(rsaPublicKeyPEM))

	// Calculate RSA key hash for nonce
	rsaKeyHash := crypto.CalculateSignableDigest(crypto.EnvRequestRSAKeyHeader, rsaPublicKeyPEM)
	rsaKeyHashHex := hex.EncodeToString(rsaKeyHash)

	// Request attestation token with RSA key hash as nonce
	e.Logger.Info("Requesting attestation token")
	jwt, err := e.tokenProvider.GetToken(ctx, []string{rsaKeyHashHex})
	if err != nil {
		return nil, fmt.Errorf("failed to get attestation token: %w", err)
	}

	// Send request to server with JWT and RSA public key
	e.Logger.Debug("Sending request to server", "url", e.serverURL)
	response, err := e.sendRequest(ctx, types.EnvRequestV2{
		JWTWithAttestedRSAKey: jwt,
		RSAKeyPEM:             string(rsaPublicKeyPEM),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	e.Logger.Info("Received response from server")

	// Verify signature
	e.Logger.Debug("Verifying response signature")
	isValid, err := crypto.VerifyKMSSignature(*response, e.kmsSigningKey)
	if err != nil {
		return nil, fmt.Errorf("signature verification error: %w", err)
	}
	if !isValid {
		return nil, fmt.Errorf("invalid signature")
	}

	e.Logger.Info("Signature verified successfully")

	e.Logger.Debug("Response", "response", response.Data)

	// Decrypt response
	e.Logger.Debug("Decrypting response")
	rsaPrivateKey, err := crypto.RSAPrivateKeyFromPEM(rsaPrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}
	envJSONBytes, err := crypto.DecryptWithRSAOAEPAndAES256GCM(rsaPrivateKey, []byte(response.Data.EncryptedCombinedEnv))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt response: %w", err)
	}

	e.Logger.Info("Response decrypted successfully")

	return envJSONBytes, nil
}

func (e *EnvClient) sendRequest(ctx context.Context, envRequest types.EnvRequestV2) (*types.SignedResponse[types.EnvResponseV1], error) {
	// Marshal the env request
	requestBody, err := json.Marshal(envRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal env request: %w", err)
	}

	// Create HTTP request
	url := e.serverURL + "/env/v2"
	// Send request
	client := &http.Client{Timeout: 30 * time.Second}

	// start retries
	retries := 0
	operation := func() ([]byte, error) {
		e.Logger.Info("Requesting env from server...", "retries", retries)
		retries++

		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(requestBody))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		responseBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode >= 500 {
			return nil, fmt.Errorf("server error %d: %s", resp.StatusCode, string(responseBody))
		}
		if resp.StatusCode != http.StatusOK {
			// Don't retry client errors (4xx) as they won't resolve with retries
			return nil, backoff.Permanent(fmt.Errorf("client error %d: %s", resp.StatusCode, string(responseBody)))
		}

		return responseBody, nil
	}

	exponentialBackoff := backoff.NewExponentialBackOff()
	exponentialBackoff.InitialInterval = initialInterval
	exponentialBackoff.MaxInterval = maxInterval
	exponentialBackoff.Multiplier = multiplier

	responseBody, err := backoff.Retry(ctx, operation, backoff.WithBackOff(exponentialBackoff), backoff.WithMaxElapsedTime(maxElapsedTime))
	if err != nil {
		return nil, fmt.Errorf("failed to send request after retries: %w", err)
	}
	//end retries

	// Parse response
	var signedResponse types.SignedResponse[types.EnvResponseV1]
	if err := json.Unmarshal(responseBody, &signedResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &signedResponse, nil
}
