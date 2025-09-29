package envclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/Layr-Labs/eigenx-kms/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms/pkg/types"
	"github.com/cenkalti/backoff/v5"
)

const (
	initialInterval = 500 * time.Millisecond
	maxInterval     = 5 * time.Second
	multiplier      = 1.5
	maxElapsedTime  = 2 * time.Minute
)

type EnvClient struct {
	Logger           *slog.Logger
	jwt              []byte
	kmsEncryptionKey []byte
	kmsSigningKey    []byte
	serverURL        string
}

func NewEnvClient(logger *slog.Logger, jwt []byte, kmsEncryptionKey []byte, kmsSigningKey []byte, serverURL string) *EnvClient {
	return &EnvClient{Logger: logger, jwt: jwt, kmsEncryptionKey: kmsEncryptionKey, kmsSigningKey: kmsSigningKey, serverURL: serverURL}
}

func (e *EnvClient) GetEnv(ctx context.Context) ([]byte, error) {
	// Generate RSA key pair on the fly
	e.Logger.Info("Generating RSA key pair")
	rsaPrivateKeyPEM, rsaPublicKeyPEM, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	jwtWithKey := types.JWTWithRSAKey{
		JWT:    string(e.jwt),
		RSAKey: string(rsaPublicKeyPEM),
	}

	jwtWithKeyJSON, err := json.Marshal(jwtWithKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal jwt with key: %w", err)
	}

	// Encrypt jwt+RSA public key with KMS public key using JSON Web Encryption
	e.Logger.Debug("Encrypting jwt with RSA public key with KMS public key")
	encryptedJWTWithRSAKey, err := crypto.EncryptRSAOAEPAndAES256GCMWithPEM(e.kmsEncryptionKey, jwtWithKeyJSON, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt jwt with RSA public key with KMS public key: %w", err)
	}

	e.Logger.Info("Encrypted jwt with RSA public key with KMS public key created")

	// Send request to server
	e.Logger.Debug("Sending request to server", "url", e.serverURL)
	response, err := e.sendRequest(ctx, types.EnvRequest{EncryptedJWTWithRSAKey: string(encryptedJWTWithRSAKey)})
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

func (e *EnvClient) sendRequest(ctx context.Context, envRequest types.EnvRequest) (*types.SignedResponse[types.EnvResponse], error) {
	// Marshal the env request
	requestBody, err := json.Marshal(envRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal env request: %w", err)
	}

	// Create HTTP request
	url := e.serverURL + "/env"
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
	var signedResponse types.SignedResponse[types.EnvResponse]
	if err := json.Unmarshal(responseBody, &signedResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &signedResponse, nil
}
