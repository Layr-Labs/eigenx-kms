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
//	@Success		200			{object}	types.SignedResponse[types.EnvResponse]
//	@Failure		400			{object}	map[string]string
//	@Failure		401			{object}	map[string]string
//	@Failure		500			{object}	map[string]string
//	@Router			/env [post]
func HandleEnv(c echo.Context, logger *slog.Logger, attestationVerifier attestation.AttestationVerifierInterface, chainClient chainclient.ChainClient, kmsClient kms.KMSClient, debugMode bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Parse request body
	var envRequest types.EnvRequest
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

	// Verify attestation and extract claims using the JWT
	claims, err := attestationVerifier.VerifyAttestation(ctx, jwtWithKey.JWT)
	if err != nil {
		return returnError(c, logger, http.StatusUnauthorized, fmt.Sprintf("Attestation verification failed: %v", err))
	}

	logger.Debug("Attestation verified", "app_id", claims.AppID, "image_digest", claims.ImageDigest)

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

	// Check smart contract permissions
	digest, publicEnv, encryptedEnvBytes, err := chainClient.GetLatestRelease(ctx, claims.AppID)
	if err != nil {
		return returnError(c, logger, http.StatusInternalServerError, fmt.Sprintf("GetLatestRelease failed: %v", err))
	}
	// Check authorization
	if err := checkAuthorization(claims, digest); err != nil {
		return returnError(c, logger, http.StatusUnauthorized, fmt.Sprintf("Authorization failed: %v", err))
	}

	msg, err := jwe.Parse(encryptedEnvBytes)
	if err != nil {
		return returnError(c, logger, http.StatusInternalServerError, fmt.Sprintf("Failed to parse encrypted env: %v", err))
	}

	var retrievedAppID string
	err = msg.ProtectedHeaders().Get(crypto.JWEAppIDHeader, &retrievedAppID)
	if err != nil {
		return returnError(c, logger, http.StatusInternalServerError, fmt.Sprintf("Failed to get app id from encrypted env: %v", err))
	}

	if !strings.EqualFold(retrievedAppID, claims.AppID) {
		return returnError(c, logger, http.StatusUnauthorized, fmt.Sprintf("Encrypted env app id mismatch: expected %s, got %s", claims.AppID, retrievedAppID))
	}

	// Decrypt secrets
	privateEnvBytes, err := crypto.DecryptWithRSAOAEPAndAES256GCM(kmsClient, encryptedEnvBytes)
	if err != nil {
		return returnError(c, logger, http.StatusInternalServerError, fmt.Sprintf("Failed to decrypt encrypted env: %v", err))
	}

	privateEnv := types.Env{}
	err = json.Unmarshal(privateEnvBytes, &privateEnv)
	if err != nil {
		return returnError(c, logger, http.StatusBadRequest, fmt.Sprintf("Failed to unmarshal private env: %v", err))
	}

	logger.Debug("Decrypted private environment", "app_id", claims.AppID)

	// Get or generate app mnemonic (KMS encrypted)
	mnemonic, err := kmsClient.DeriveMnemonic(ctx, claims.AppID)
	if err != nil {
		return returnError(c, logger, http.StatusInternalServerError, fmt.Sprintf("Failed to get/generate mnemonic: %v", err))
	}

	logger.Debug("Retrieved/generated mnemonic", "app_id", claims.AppID)

	// Combine and return all secrets
	env := types.Env{}
	env["MNEMONIC"] = mnemonic
	// add the private env
	for k, v := range privateEnv {
		env[k] = v
	}
	// add the public env
	for k, v := range publicEnv {
		env[k] = v
	}

	logger.Debug("Encrypting response", "app_id", claims.AppID)

	envJSON, err := json.Marshal(env)
	if err != nil {
		return returnError(c, logger, http.StatusInternalServerError, fmt.Sprintf("Failed to marshal env: %v", err))
	}

	// Use existing JSON Web Encryption with user's RSA key
	encryptedEnvJSON, err := crypto.EncryptRSAOAEPAndAES256GCMWithPEM([]byte(jwtWithKey.RSAKey), envJSON, nil)
	if err != nil {
		return returnError(c, logger, http.StatusInternalServerError, fmt.Sprintf("Failed to encrypt response: %v", err))
	}

	envResponse := types.EnvResponse{
		EncryptedCombinedEnv: string(encryptedEnvJSON),
	}

	logger.Debug("Returning encrypted response", "app_id", claims.AppID)
	return returnSuccessWithSignature(c, logger, kmsClient, http.StatusOK, envResponse)
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
