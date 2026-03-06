package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

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
//	@Description	Verify attestation and return a signed JWT containing the attested appId and imageDigest
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			data	body		types.AttestRequest	true	"Attestation request with version discriminator"
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
	attestationVerifier attestation.AttestationVerifierInterface,
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

	var appID, imageDigest string
	var err error

	switch req.Version {
	case 1:
		appID, imageDigest, err = handleAttestV1(ctx, c, attestationVerifier, kmsClient, req, debugMode)
	case 2:
		appID, imageDigest, err = handleAttestV2(ctx, c, attestationVerifier, req, debugMode)
	case 3:
		appID, imageDigest, err = handleAttestV3(ctx, c, attestationEvidenceVerifier, policyChecker, req, debugMode)
	default:
		return returnError(c, logger, http.StatusBadRequest, fmt.Sprintf("Unsupported attestation version: %d", req.Version))
	}

	if err != nil {
		if httpErr, ok := err.(*httpError); ok {
			return returnError(c, logger, httpErr.statusCode, httpErr.message)
		}
		return returnError(c, logger, http.StatusInternalServerError, err.Error())
	}

	token, err := jwtSigner.SignAttestationJWT(appID, imageDigest)
	if err != nil {
		return returnError(c, logger, http.StatusInternalServerError, fmt.Sprintf("Failed to sign attestation JWT: %v", err))
	}

	resp := types.AttestResponse{Token: token}
	return returnSuccessWithSignature(c, logger, kmsClient, http.StatusOK, resp)
}

func handleAttestV1(
	ctx context.Context,
	c echo.Context,
	attestationVerifier attestation.AttestationVerifierInterface,
	kmsClient kms.KMSClient,
	req types.AttestRequest,
	debugMode bool,
) (string, string, error) {
	// Decrypt the encrypted request body to get JWT + RSA key
	jwtWithKeyBytes, err := crypto.DecryptWithRSAOAEPAndAES256GCM(kmsClient, []byte(req.EncryptedJWTWithRSAKey))
	if err != nil {
		return "", "", newHTTPError(http.StatusBadRequest, "Failed to decrypt encrypted request body: %v", err)
	}

	var jwtWithKey types.JWTWithRSAKey
	if err := json.Unmarshal(jwtWithKeyBytes, &jwtWithKey); err != nil {
		return "", "", newHTTPError(http.StatusBadRequest, "Failed to unmarshal jwt with key: %v", err)
	}

	claims, err := attestationVerifier.VerifyAttestation(ctx, jwtWithKey.JWT, attestation.GoogleConfidentialSpace)
	if err != nil {
		return "", "", newHTTPError(http.StatusUnauthorized, "Attestation verification failed: %v", err)
	}

	if claims.Nonce != "" {
		return "", "", newHTTPError(http.StatusBadRequest, "nonce should be empty for v1 attestation requests")
	}

	appID := applyDebugOverride(c, claims.AppID, debugMode)
	if appID == "" {
		return "", "", newHTTPError(http.StatusBadRequest, "appID query parameter is only allowed in debug mode")
	}

	return appID, claims.ImageDigest, nil
}

func handleAttestV2(
	ctx context.Context,
	c echo.Context,
	attestationVerifier attestation.AttestationVerifierInterface,
	req types.AttestRequest,
	debugMode bool,
) (string, string, error) {
	if err := crypto.ValidateRSAKeySize([]byte(req.RSAKeyPEM)); err != nil {
		return "", "", newHTTPError(http.StatusBadRequest, "encryption key size mismatch: %v", err)
	}

	claims, err := attestationVerifier.VerifyAttestation(ctx, req.JWTWithAttestedRSAKey, attestation.IntelTrustAuthority)
	if err != nil {
		return "", "", newHTTPError(http.StatusUnauthorized, "Attestation verification failed: %v", err)
	}

	if err := checkRSAKeyAttestation(claims, req.RSAKeyPEM); err != nil {
		return "", "", newHTTPError(http.StatusUnauthorized, "RSA key attestation check failed: %v", err)
	}

	appID := applyDebugOverride(c, claims.AppID, debugMode)
	if appID == "" {
		return "", "", newHTTPError(http.StatusBadRequest, "appID query parameter is only allowed in debug mode")
	}

	return appID, claims.ImageDigest, nil
}

func handleAttestV3(
	ctx context.Context,
	c echo.Context,
	attestationEvidenceVerifier attestation.BoundAttestationEvidenceVerifier,
	policyChecker policy.PolicyCheckerInterface,
	req types.AttestRequest,
	debugMode bool,
) (string, string, error) {
	if err := crypto.ValidateRSAKeySize([]byte(req.RSAKeyPEM)); err != nil {
		return "", "", newHTTPError(http.StatusBadRequest, "encryption key size mismatch: %v", err)
	}

	attestationBytes, err := base64.StdEncoding.DecodeString(req.Attestation)
	if err != nil {
		return "", "", newHTTPError(http.StatusBadRequest, "Failed to decode attestation: %v", err)
	}

	challenge := crypto.CalculateSignableDigest(crypto.EnvRequestRSAKeyHeader, []byte(req.RSAKeyPEM))

	result, err := attestationEvidenceVerifier.Verify(ctx, attestationBytes, challenge)
	if err != nil {
		return "", "", newHTTPError(http.StatusUnauthorized, "Attestation verification failed: %v", err)
	}

	if result.TPMClaims.GCE == nil {
		return "", "", newHTTPError(http.StatusUnauthorized, "GCE instance info not found in attestation")
	}
	if result.Container == nil {
		return "", "", newHTTPError(http.StatusUnauthorized, "Container info not found in attestation")
	}

	appID, err := utils.ExtractAppIDFromInstanceName(result.TPMClaims.GCE.InstanceName)
	if err != nil {
		return "", "", newHTTPError(http.StatusUnauthorized, "Failed to extract app ID: %v", err)
	}

	appID = applyDebugOverride(c, appID, debugMode)
	if appID == "" {
		return "", "", newHTTPError(http.StatusBadRequest, "appID query parameter is only allowed in debug mode")
	}

	if err := policyChecker.CheckTPMPolicies(ctx, result.TPMClaims); err != nil {
		return "", "", newHTTPError(http.StatusUnauthorized, "TPM policy check failed: %v", err)
	}

	if result.TEEClaims != nil {
		if err := policyChecker.CheckTEEPolicies(ctx, result.TEEClaims); err != nil {
			return "", "", newHTTPError(http.StatusUnauthorized, "TEE policy check failed: %v", err)
		}
	}

	return appID, result.Container.ImageDigest, nil
}

// applyDebugOverride checks for the debug appID query parameter and applies it if in debug mode.
// Returns the final appID, or empty string if a debug override was requested but debug mode is off.
func applyDebugOverride(c echo.Context, appID string, debugMode bool) string {
	debugAppID := strings.ToLower(c.QueryParam("appID"))
	if debugAppID != "" {
		if debugMode {
			return debugAppID
		}
		return ""
	}
	return appID
}
