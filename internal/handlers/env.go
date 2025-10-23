package handlers

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/Layr-Labs/eigenx-kms/internal/kms"
	"github.com/Layr-Labs/eigenx-kms/pkg/attestation"
	"github.com/Layr-Labs/eigenx-kms/pkg/chainclient"
	"github.com/Layr-Labs/eigenx-kms/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms/pkg/types"
	"github.com/lestrrat-go/jwx/v3/jwe"

	"github.com/labstack/echo/v4"
)

// HandleEnv godoc
//
//	@Summary		Get environment variables
//	@Description	Retrieve encrypted environment variables and mnemonic for authenticated app
//	@Tags			environment
//	@Accept			json
//	@Produce		json
//	@Param			data	    body		types.EnvRequest	true	"Encrypted JWT + RSA public key data"
//	@Param			appID		query		string				false	"App ID override (debug mode only)"
//	@Success		200			{object}	types.SignedResponse[types.EnvResponseV1]
//	@Failure		400			{object}	map[string]string
//	@Failure		401			{object}	map[string]string
//	@Failure		500			{object}	map[string]string
//	@Router			/env [post]
func HandleEnv(c echo.Context, logger *slog.Logger, attestationVerifier attestation.AttestationVerifierInterface, chainClient chainclient.ChainClient, kmsClient kms.KMSClient, debugMode bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Parse request body
	var envRequest types.EnvRequestV1
	if err := c.Bind(&envRequest); err != nil {
		return returnError(c, logger, http.StatusBadRequest, fmt.Sprintf("Failed to parse env request: %v", err))
	}

	// Decrypt the encrypted request body to get JWT + RSA key
	jwtWithKeyBytes, err := crypto.DecryptWithRSAOAEPAndAES256GCM(kmsClient, []byte(envRequest.EncryptedJWTWithRSAKey))
	if err != nil {
		return returnError(c, logger, http.StatusBadRequest, fmt.Sprintf("Failed to decrypt encrypted request body: %v", err))
	}

	var jwtWithKey types.JWTWithRSAKey
	err = json.Unmarshal(jwtWithKeyBytes, &jwtWithKey)
	if err != nil {
		return returnError(c, logger, http.StatusBadRequest, fmt.Sprintf("Failed to unmarshal jwt with key: %v", err))
	}

	logger.Debug("Successfully parsed encrypted auth", "jwt_length", len(jwtWithKey.JWT), "rsa_key_length", len(jwtWithKey.RSAKey))

	// Validate RSA key size (must be 4096-bit)
	if err := crypto.ValidateRSAKeySize([]byte(jwtWithKey.RSAKey)); err != nil {
		return returnError(c, logger, http.StatusBadRequest, fmt.Sprintf("encryption key size mismatch: %v", err))
	}

	// Verify attestation and extract claims using the JWT (V1 accepts both Google CS and Intel)
	// Try Google first for backward compatibility, then Intel
	claims, err := attestationVerifier.VerifyAttestation(ctx, jwtWithKey.JWT, attestation.GoogleConfidentialSpace)
	if err != nil {
		logger.Debug("Google CS attestation failed, trying Intel", "error", err)
		claims, err = attestationVerifier.VerifyAttestation(ctx, jwtWithKey.JWT, attestation.IntelTrustAuthority)
		if err != nil {
			return returnError(c, logger, http.StatusUnauthorized, fmt.Sprintf("Attestation verification failed: %v", err))
		}
	}

	logger.Debug("Attestation verified", "app_id", claims.AppID, "image_digest", claims.ImageDigest)

	if claims.Nonce != "" {
		return returnError(c, logger, http.StatusBadRequest, "nonce should be empty for env v1 requests")
	}

	// add the ability to override the appID if in debug mode
	debugAppID := strings.ToLower(c.QueryParam("appID"))
	if debugAppID != "" {
		if debugMode {
			claims.AppID = debugAppID
			logger.Debug("Debug mode override", "app_id", claims.AppID)
		} else {
			return returnError(c, logger, http.StatusBadRequest, "appID query parameter is only allowed in debug mode")
		}
	}

	// Get and decrypt chain environment
	privateEnv, publicEnv, err := getAndDecryptChainEnv(ctx, logger, chainClient, kmsClient, claims)
	if err != nil {
		if httpErr, ok := err.(*httpError); ok {
			return returnError(c, logger, httpErr.statusCode, httpErr.message)
		}
		return returnError(c, logger, http.StatusInternalServerError, err.Error())
	}

	// Get or generate app mnemonic (KMS encrypted)
	mnemonic, err := kmsClient.DeriveMnemonic(ctx, claims.AppID)
	if err != nil {
		return returnError(c, logger, http.StatusInternalServerError, fmt.Sprintf("Failed to get/generate mnemonic: %v", err))
	}

	logger.Debug("Retrieved/generated mnemonic", "app_id", claims.AppID)

	// Combine environments
	env := combineEnvironments(mnemonic, privateEnv, publicEnv)

	// Encrypt and sign response
	return encryptAndSignResponse(c, logger, kmsClient, env, []byte(jwtWithKey.RSAKey))
}

// HandleEnvV2 godoc
//
//	@Summary		Get environment variables (V2)
//	@Description	Retrieve encrypted environment variables and mnemonic for authenticated app using attested RSA key
//	@Tags			environment
//	@Accept			json
//	@Produce		json
//	@Param			data	    body		types.EnvRequestV2	true	"JWT with attested RSA public key"
//	@Param			appID		query		string				false	"App ID override (debug mode only)"
//	@Success		200			{object}	types.SignedResponse[types.EnvResponseV2]
//	@Failure		400			{object}	map[string]string
//	@Failure		401			{object}	map[string]string
//	@Failure		500			{object}	map[string]string
//	@Router			/env/v2 [post]
func HandleEnvV2(c echo.Context, logger *slog.Logger, attestationVerifier attestation.AttestationVerifierInterface, chainClient chainclient.ChainClient, kmsClient kms.KMSClient, debugMode bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Parse request body
	var envRequest types.EnvRequestV2
	if err := c.Bind(&envRequest); err != nil {
		return returnError(c, logger, http.StatusBadRequest, fmt.Sprintf("Failed to parse env request v2: %v", err))
	}

	logger.Debug("Successfully parsed v2 request", "jwt_length", len(envRequest.JWTWithAttestedRSAKey))

	// Validate RSA key size (must be 4096-bit)
	if err := crypto.ValidateRSAKeySize([]byte(envRequest.RSAKeyPEM)); err != nil {
		return returnError(c, logger, http.StatusBadRequest, fmt.Sprintf("encryption key size mismatch: %v", err))
	}

	// Verify attestation and extract claims using the JWT (V2 uses Intel Trust Authority)
	claims, err := attestationVerifier.VerifyAttestation(ctx, envRequest.JWTWithAttestedRSAKey, attestation.IntelTrustAuthority)
	if err != nil {
		return returnError(c, logger, http.StatusUnauthorized, fmt.Sprintf("Attestation verification failed: %v", err))
	}

	logger.Debug("Attestation verified", "app_id", claims.AppID, "image_digest", claims.ImageDigest, "nonce", claims.Nonce)

	// add the ability to override the appID if in debug mode
	debugAppID := strings.ToLower(c.QueryParam("appID"))
	if debugAppID != "" {
		if debugMode {
			claims.AppID = debugAppID
			logger.Debug("Debug mode override", "app_id", claims.AppID)
		} else {
			return returnError(c, logger, http.StatusBadRequest, "appID query parameter is only allowed in debug mode")
		}
	}

	// Verify that the RSA key is attested in the JWT
	if err := checkRSAKeyAttestation(claims, envRequest.RSAKeyPEM); err != nil {
		return returnError(c, logger, http.StatusUnauthorized, fmt.Sprintf("RSA key attestation check failed: %v", err))
	}

	logger.Debug("RSA key attestation verified", "app_id", claims.AppID)

	// Get and decrypt chain environment
	privateEnv, publicEnv, err := getAndDecryptChainEnv(ctx, logger, chainClient, kmsClient, claims)
	if err != nil {
		if httpErr, ok := err.(*httpError); ok {
			return returnError(c, logger, httpErr.statusCode, httpErr.message)
		}
		return returnError(c, logger, http.StatusInternalServerError, err.Error())
	}

	// Get or generate app mnemonic (KMS encrypted)
	mnemonic, err := kmsClient.DeriveMnemonic(ctx, claims.AppID)
	if err != nil {
		return returnError(c, logger, http.StatusInternalServerError, fmt.Sprintf("Failed to get/generate mnemonic: %v", err))
	}

	logger.Debug("Retrieved/generated mnemonic", "app_id", claims.AppID)

	// Combine environments
	env := combineEnvironments(mnemonic, privateEnv, publicEnv)

	// Encrypt and sign response
	return encryptAndSignResponse(c, logger, kmsClient, env, []byte(envRequest.RSAKeyPEM))
}

// verifyRSAKeyAttestation verifies that the RSA public key is attested in the JWT
func checkRSAKeyAttestation(claims *attestation.AttestationClaims, expectedRSAKeyPEM string) error {
	// nonce should be the sha256 of the RSA public key PEM
	if claims.Nonce == "" {
		return fmt.Errorf("no nonce found in attestation claims")
	}

	expectedHashBytes := crypto.CalculateSignableDigest(crypto.EnvRequestRSAKeyHeader, []byte(expectedRSAKeyPEM))
	expectedHash := hex.EncodeToString(expectedHashBytes)

	if claims.Nonce != expectedHash {
		return fmt.Errorf("RSA key attestation mismatch: expected hash %s, got %s", expectedHash, claims.Nonce)
	}

	return nil
}

func checkAuthorization(claims *attestation.AttestationClaims, expectedDigest [32]byte) error {
	actualDigest, err := hex.DecodeString(strings.TrimPrefix(claims.ImageDigest, "sha256:"))
	if err != nil {
		return fmt.Errorf("failed to decode image digest: %v", err)
	}

	if !bytes.Equal(expectedDigest[:], actualDigest) {
		return fmt.Errorf("image digest mismatch: expected %s, got %s", hex.EncodeToString(expectedDigest[:]), hex.EncodeToString(actualDigest))
	}

	return nil
}

// getAndDecryptChainEnv retrieves and decrypts the environment from the chain
// Returns: privateEnv, publicEnv, error
func getAndDecryptChainEnv(ctx context.Context, logger *slog.Logger, chainClient chainclient.ChainClient, kmsClient kms.KMSClient, claims *attestation.AttestationClaims) (types.Env, types.Env, error) {
	// Check smart contract permissions
	digest, publicEnv, encryptedEnvBytes, err := chainClient.GetLatestRelease(ctx, claims.AppID)
	if err != nil {
		return nil, nil, newHTTPError(http.StatusInternalServerError, "GetLatestRelease failed: %v", err)
	}

	// Check authorization
	if err := checkAuthorization(claims, digest); err != nil {
		return nil, nil, newHTTPError(http.StatusUnauthorized, "Authorization failed: %v", err)
	}

	// Parse encrypted env JWE
	msg, err := jwe.Parse(encryptedEnvBytes)
	if err != nil {
		return nil, nil, newHTTPError(http.StatusInternalServerError, "Failed to parse encrypted env: %v", err)
	}

	// Validate app ID in protected headers
	var retrievedAppID string
	err = msg.ProtectedHeaders().Get(crypto.JWEAppIDHeader, &retrievedAppID)
	if err != nil {
		return nil, nil, newHTTPError(http.StatusInternalServerError, "Failed to get app id from encrypted env: %v", err)
	}

	if !strings.EqualFold(retrievedAppID, claims.AppID) {
		return nil, nil, newHTTPError(http.StatusUnauthorized, "Encrypted env app id mismatch: expected %s, got %s", claims.AppID, retrievedAppID)
	}

	// Decrypt secrets
	privateEnvBytes, err := crypto.DecryptWithRSAOAEPAndAES256GCM(kmsClient, encryptedEnvBytes)
	if err != nil {
		return nil, nil, newHTTPError(http.StatusInternalServerError, "Failed to decrypt encrypted env: %v", err)
	}

	privateEnv := types.Env{}
	err = json.Unmarshal(privateEnvBytes, &privateEnv)
	if err != nil {
		return nil, nil, newHTTPError(http.StatusBadRequest, "Failed to unmarshal private env: %v", err)
	}

	logger.Debug("Decrypted private environment", "app_id", claims.AppID)

	return privateEnv, publicEnv, nil
}

// combineEnvironments combines mnemonic, private env, and public env in order of precedence
func combineEnvironments(mnemonic string, privateEnv, publicEnv types.Env) types.Env {
	env := types.Env{}
	env["MNEMONIC"] = mnemonic
	// add the private env (can override mnemonic)
	for k, v := range privateEnv {
		env[k] = v
	}
	// add the public env (can override both)
	for k, v := range publicEnv {
		env[k] = v
	}
	return env
}

// encryptAndSignResponse encrypts the environment with the client's RSA key and signs with KMS
func encryptAndSignResponse(c echo.Context, logger *slog.Logger, kmsClient kms.KMSClient, env types.Env, rsaPublicKeyPEM []byte) error {
	logger.Debug("Encrypting response")

	envJSON, err := json.Marshal(env)
	if err != nil {
		return returnError(c, logger, http.StatusInternalServerError, fmt.Sprintf("Failed to marshal env: %v", err))
	}

	// Use JSON Web Encryption with user's RSA key
	encryptedEnvJSON, err := crypto.EncryptRSAOAEPAndAES256GCMWithPEM(rsaPublicKeyPEM, envJSON, nil)
	if err != nil {
		return returnError(c, logger, http.StatusInternalServerError, fmt.Sprintf("Failed to encrypt response: %v", err))
	}

	envResponse := types.EnvResponseV1{
		EncryptedCombinedEnv: string(encryptedEnvJSON),
	}

	logger.Debug("Returning encrypted response")
	return returnSuccessWithSignature(c, logger, kmsClient, http.StatusOK, envResponse)
}
