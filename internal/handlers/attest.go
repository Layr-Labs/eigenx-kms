package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/Layr-Labs/eigenx-kms/internal/auth"
	"github.com/Layr-Labs/eigenx-kms/internal/kms"
	"github.com/Layr-Labs/eigenx-kms/pkg/attestation"
	"github.com/Layr-Labs/eigenx-kms/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms/pkg/policy"
	"github.com/Layr-Labs/eigenx-kms/pkg/types"
	"github.com/Layr-Labs/eigenx-kms/pkg/utils"
	"github.com/labstack/echo/v4"
)

// HandleAttest godoc
//
//	@Summary		Attest and receive a signed JWT
//	@Description	Verify attestation and return an encrypted, signed JWT containing the attested appId and imageDigest
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			data	body		types.AttestRequest	true	"Attestation request (V3 only)"
//	@Param			appID	query		string				false	"App ID override (debug mode only)"
//	@Success		200		{object}	types.SignedResponse[types.AttestResponse]
//	@Failure		400		{object}	map[string]string
//	@Failure		401		{object}	map[string]string
//	@Failure		500		{object}	map[string]string
//	@Router			/auth/attest [post]
func HandleAttest(
	c echo.Context,
	logger *slog.Logger,
	jwtSigner *auth.JWTSigner,
	attestationEvidenceVerifier attestation.BoundAttestationEvidenceVerifier,
	policyChecker policy.PolicyCheckerInterface,
	kmsClient kms.KMSClient,
	debugMode bool,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var req types.AttestRequest
	if err := c.Bind(&req); err != nil {
		return returnError(c, logger, http.StatusBadRequest, fmt.Sprintf("Failed to parse attest request: %v", err))
	}

	if req.Version != 3 {
		return returnError(c, logger, http.StatusBadRequest, fmt.Sprintf("Unsupported attestation version: %d, only version 3 is supported", req.Version))
	}

	appID, verified, extraData, err := handleAttestV3(ctx, c, attestationEvidenceVerifier, policyChecker, req, debugMode)
	if err != nil {
		if httpErr, ok := err.(*httpError); ok {
			return returnError(c, logger, httpErr.statusCode, httpErr.message)
		}
		return returnError(c, logger, http.StatusInternalServerError, err.Error())
	}

	// Base64-encode the already-decoded extra_data for the JWT claim
	var extraDataB64 string
	if len(extraData) > 0 {
		extraDataB64 = base64.StdEncoding.EncodeToString(extraData)
	}

	token, err := jwtSigner.SignAttestationJWT(appID, verified, req.Audience, extraDataB64)
	if err != nil {
		return returnError(c, logger, http.StatusInternalServerError, fmt.Sprintf("Failed to sign attestation JWT: %v", err))
	}

	// Encrypt the token with the client's RSA public key (same pattern as /env endpoints)
	tokenBytes, err := json.Marshal(map[string]string{"token": token})
	if err != nil {
		return returnError(c, logger, http.StatusInternalServerError, fmt.Sprintf("Failed to marshal token: %v", err))
	}

	encryptedToken, err := crypto.EncryptRSAOAEPAndAES256GCMWithPEM([]byte(req.RSAKeyPEM), tokenBytes, nil)
	if err != nil {
		return returnError(c, logger, http.StatusInternalServerError, fmt.Sprintf("Failed to encrypt token: %v", err))
	}

	resp := types.AttestResponse{EncryptedToken: string(encryptedToken)}
	return returnSuccessWithSignature(c, logger, kmsClient, http.StatusOK, resp)
}

func handleAttestV3(
	ctx context.Context,
	c echo.Context,
	attestationEvidenceVerifier attestation.BoundAttestationEvidenceVerifier,
	policyChecker policy.PolicyCheckerInterface,
	req types.AttestRequest,
	debugMode bool,
) (string, *attestation.VerifiedAttestation, []byte, error) {
	if err := crypto.ValidateRSAKeySize([]byte(req.RSAKeyPEM)); err != nil {
		return "", nil, nil, newHTTPError(http.StatusBadRequest, "encryption key size mismatch: %v", err)
	}

	attestationBytes, err := base64.StdEncoding.DecodeString(req.Attestation)
	if err != nil {
		return "", nil, nil, newHTTPError(http.StatusBadRequest, "Failed to decode attestation: %v", err)
	}

	// Decode optional extra_data (base64). go-tpm-tools hashes it (SHA-256/SHA-512)
	// before binding into the hardware nonce, so arbitrary data up to 1MB is accepted.
	var extraData []byte
	if req.ExtraData != "" {
		extraData, err = base64.StdEncoding.DecodeString(req.ExtraData)
		if err != nil {
			return "", nil, nil, newHTTPError(http.StatusBadRequest, "Failed to decode extra_data: %v", err)
		}
		if len(extraData) > 1_048_576 {
			return "", nil, nil, newHTTPError(http.StatusBadRequest, "extra_data exceeds 1MB limit (%d bytes)", len(extraData))
		}
	}

	challenge := crypto.CalculateSignableDigest(crypto.JWTRequestRSAKeyHeader, []byte(req.RSAKeyPEM))

	result, err := attestationEvidenceVerifier.Verify(ctx, attestationBytes, challenge, extraData)
	if err != nil {
		return "", nil, nil, newHTTPError(http.StatusUnauthorized, "Attestation verification failed: %v", err)
	}

	if result.TPMClaims.GCE == nil {
		return "", nil, nil, newHTTPError(http.StatusUnauthorized, "GCE instance info not found in attestation")
	}
	if result.Container == nil {
		return "", nil, nil, newHTTPError(http.StatusUnauthorized, "Container info not found in attestation")
	}

	appID, err := utils.ExtractAppIDFromInstanceName(result.TPMClaims.GCE.InstanceName)
	if err != nil {
		return "", nil, nil, newHTTPError(http.StatusUnauthorized, "Failed to extract app ID: %v", err)
	}

	appID = applyDebugOverride(c, appID, debugMode)
	if appID == "" {
		return "", nil, nil, newHTTPError(http.StatusBadRequest, "appID query parameter is only allowed in debug mode")
	}

	if err := policyChecker.CheckTPMPolicies(ctx, result.TPMClaims); err != nil {
		return "", nil, nil, newHTTPError(http.StatusUnauthorized, "TPM policy check failed: %v", err)
	}

	if result.TEEClaims != nil {
		if err := policyChecker.CheckTEEPolicies(ctx, result.TEEClaims); err != nil {
			return "", nil, nil, newHTTPError(http.StatusUnauthorized, "TEE policy check failed: %v", err)
		}
	}

	return appID, result, extraData, nil
}
