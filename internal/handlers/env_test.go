package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Layr-Labs/eigenx-kms/internal/kms/fakes"
	"github.com/Layr-Labs/eigenx-kms/internal/kms/mocks"
	"github.com/Layr-Labs/eigenx-kms/pkg/attestation"
	attestationMocks "github.com/Layr-Labs/eigenx-kms/pkg/attestation/mocks"
	chainClientMocks "github.com/Layr-Labs/eigenx-kms/pkg/chainclient/mocks"
	"github.com/Layr-Labs/eigenx-kms/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms/pkg/types"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

const (
	testEnvAppID    = "0x1111111111111111111111111111111111111111"
	testEnvMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	testValidDigest = "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
)

func setupEnvLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func setupEchoContextWithBody(method, path string, body []byte) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec), rec
}

func createFakeKMS(t *testing.T) (*fakes.FakeKMS, error) {
	fakeKMS, err := fakes.NewFakeKMS()
	if err != nil {
		t.Fatalf("failed to create fake KMS: %v", err)
	}
	return fakeKMS, nil
}

func setupEchoContextWithBodyAndQuery(method, path string, body []byte, queryParams map[string]string) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	// Add query parameters
	q := req.URL.Query()
	for key, value := range queryParams {
		q.Add(key, value)
	}
	req.URL.RawQuery = q.Encode()

	rec := httptest.NewRecorder()
	return e.NewContext(req, rec), rec
}

// testSetup encapsulates common test setup for HandleEnv tests
type testSetup struct {
	FakeKMS             *fakes.FakeKMS
	MockAttestation     *attestationMocks.MockAttestationVerifierInterface
	MockChainClient     *chainClientMocks.MockChainClient
	EnvRequest          types.EnvRequest
	ClientRSAPrivatePEM []byte
}

// setupHandleEnvTest creates a common test setup with mocks and fake KMS
func setupHandleEnvTest(t *testing.T) *testSetup {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	fakeKMS, err := createFakeKMS(t)
	require.NoError(t, err)

	mockAttestation := attestationMocks.NewMockAttestationVerifierInterface(ctrl)
	mockChainClient := chainClientMocks.NewMockChainClient(ctrl)

	// Create valid encrypted request with fake JWT
	mockJWT := `{"sub":"test-app","iat":1234567890}`
	envRequest, clientRSAPrivatePEM, err := fakeKMS.CreateValidEncryptedRequest(mockJWT)
	require.NoError(t, err)

	return &testSetup{
		FakeKMS:             fakeKMS,
		MockAttestation:     mockAttestation,
		MockChainClient:     mockChainClient,
		EnvRequest:          envRequest,
		ClientRSAPrivatePEM: clientRSAPrivatePEM,
	}
}

// setupSuccessfulChainClient configures the chain client mock for successful responses
func (ts *testSetup) setupSuccessfulChainClient(t *testing.T, appID string, privateEnvData types.Env) {
	hexDigest, err := hex.DecodeString(strings.TrimPrefix(testValidDigest, "sha256:"))
	require.NoError(t, err)
	var expectedDigest [32]byte
	copy(expectedDigest[:], hexDigest)

	// Create encrypted env data with proper app ID header
	privateEnvJSON, _ := json.Marshal(privateEnvData)
	kmsPublicKeyPEM, _ := ts.FakeKMS.GetEncryptionPublicKeyPEM()
	appHeaders := crypto.GetAppProtectedHeaders(appID)
	encryptedPrivateEnv, err := crypto.EncryptRSAOAEPAndAES256GCMWithPEM(kmsPublicKeyPEM, privateEnvJSON, appHeaders)
	require.NoError(t, err)

	publicEnv := types.Env{"PUBLIC_VAR": "public_value", "NODE_ENV": "production"}

	ts.MockChainClient.EXPECT().
		GetLatestRelease(gomock.Any(), appID).
		Return(expectedDigest, publicEnv, []byte(encryptedPrivateEnv), nil)
}

// verifyEnvironmentResponse decrypts and verifies the environment variables in the response
func (ts *testSetup) verifyEnvironmentResponse(t *testing.T, rec *httptest.ResponseRecorder, expectedPrivateEnv types.Env) {
	var signedResponse types.SignedResponse[types.EnvResponse]
	err := json.Unmarshal(rec.Body.Bytes(), &signedResponse)
	require.NoError(t, err)

	// Decrypt the response using the client's private key
	clientRSAPrivateKey, err := crypto.RSAPrivateKeyFromPEM(ts.ClientRSAPrivatePEM)
	require.NoError(t, err)

	decryptedEnvJSON, err := crypto.DecryptWithRSAOAEPAndAES256GCM(clientRSAPrivateKey, []byte(signedResponse.Data.EncryptedCombinedEnv))
	require.NoError(t, err)

	var returnedEnv types.Env
	err = json.Unmarshal(decryptedEnvJSON, &returnedEnv)
	require.NoError(t, err)
	// Verify expected private environment variables
	for key, expectedValue := range expectedPrivateEnv {
		require.Equal(t, expectedValue, returnedEnv[key], "Private env variable %s mismatch", key)
	}

	// Verify standard variables are present
	require.Equal(t, "public_value", returnedEnv["PUBLIC_VAR"])
	require.Equal(t, "production", returnedEnv["NODE_ENV"])
	require.Equal(t, testEnvMnemonic, returnedEnv["MNEMONIC"])
}

func TestHandleEnv_InputValidation(t *testing.T) {
	logger := setupEnvLogger()

	t.Run("invalid JSON in request body", func(t *testing.T) {
		c, rec := setupEchoContextWithBody(http.MethodPost, "/env", []byte("{invalid json}"))

		err := HandleEnv(c, logger, nil, nil, nil, false)

		require.Error(t, err)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Contains(t, err.Error(), "Failed to parse env request")

		var response map[string]string
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		require.Contains(t, response["error"], "Failed to parse env request")
	})

	t.Run("empty encryptedJwtWithRsaKey field", func(t *testing.T) {
		envRequest := types.EnvRequest{EncryptedJWTWithRSAKey: ""}
		requestBody, _ := json.Marshal(envRequest)
		c, rec := setupEchoContextWithBody(http.MethodPost, "/env", requestBody)

		err := HandleEnv(c, logger, nil, nil, nil, false)

		require.Error(t, err)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Contains(t, err.Error(), "Failed to decrypt encrypted request body")

		var response map[string]string
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		require.Contains(t, response["error"], "Failed to decrypt encrypted request body")
	})

	t.Run("invalid encrypted data format", func(t *testing.T) {
		envRequest := types.EnvRequest{EncryptedJWTWithRSAKey: "invalid-jwe-format"}
		requestBody, _ := json.Marshal(envRequest)
		c, rec := setupEchoContextWithBody(http.MethodPost, "/env", requestBody)

		err := HandleEnv(c, logger, nil, nil, nil, false)

		require.Error(t, err)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Contains(t, err.Error(), "Failed to decrypt encrypted request body")

		var response map[string]string
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		require.Contains(t, response["error"], "Failed to decrypt encrypted request body")
	})
}

func TestCheckAuthorization(t *testing.T) {
	t.Run("valid digest matching", func(t *testing.T) {
		digestHex := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
		claims := &attestation.AttestationClaims{
			ImageDigest: "sha256:" + digestHex,
			AppID:       testEnvAppID,
		}

		var expectedDigest [32]byte
		decodedBytes, err := hex.DecodeString(digestHex)
		require.NoError(t, err)
		copy(expectedDigest[:], decodedBytes)

		err = checkAuthorization(claims, expectedDigest)
		require.NoError(t, err)
	})

	t.Run("digest mismatch", func(t *testing.T) {
		claims := &attestation.AttestationClaims{
			ImageDigest: "sha256:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
		}

		var expectedDigest [32]byte
		digestHex := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
		decodedBytes, err := hex.DecodeString(digestHex)
		require.NoError(t, err)
		copy(expectedDigest[:], decodedBytes)

		err = checkAuthorization(claims, expectedDigest)
		require.Error(t, err)
		require.Contains(t, err.Error(), "image digest mismatch")
	})

	t.Run("digest without sha256 prefix", func(t *testing.T) {
		digestHex := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
		claims := &attestation.AttestationClaims{
			ImageDigest: digestHex,
		}

		var expectedDigest [32]byte
		decodedBytes, err := hex.DecodeString(digestHex)
		require.NoError(t, err)
		copy(expectedDigest[:], decodedBytes)

		err = checkAuthorization(claims, expectedDigest)
		require.NoError(t, err)
	})
}

func TestHandleEnv_KMSErrorScenarios(t *testing.T) {
	logger := setupEnvLogger()

	t.Run("JWT decryption failure", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockKMS := mocks.NewMockKMSClient(ctrl)
		mockAttestation := attestationMocks.NewMockAttestationVerifierInterface(ctrl)
		mockChainClient := chainClientMocks.NewMockChainClient(ctrl)

		// Mock KMS to return decryption error
		mockKMS.EXPECT().
			DecryptKey(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, errors.New("KMS decryption failed"))

		envRequest := types.EnvRequest{
			EncryptedJWTWithRSAKey: "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.dGVzdA.dGVzdA.dGVzdA.dGVzdA",
		}
		requestBody, _ := json.Marshal(envRequest)
		c, rec := setupEchoContextWithBody(http.MethodPost, "/env", requestBody)

		err := HandleEnv(c, logger, mockAttestation, mockChainClient, mockKMS, false)

		require.Error(t, err)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Contains(t, err.Error(), "Failed to decrypt encrypted request body")
	})

}

func TestHandleEnv_ValidRequestsWithFakeKMS(t *testing.T) {
	logger := setupEnvLogger()

	t.Run("Valid request with attestation failure", func(t *testing.T) {
		setup := setupHandleEnvTest(t)

		// Mock attestation to fail
		setup.MockAttestation.EXPECT().
			VerifyAttestation(gomock.Any(), gomock.Any()).
			Return(nil, errors.New("attestation verification failed"))

		requestBody, _ := json.Marshal(setup.EnvRequest)
		c, rec := setupEchoContextWithBody(http.MethodPost, "/env", requestBody)

		err := HandleEnv(c, logger, setup.MockAttestation, setup.MockChainClient, setup.FakeKMS, false)

		require.Error(t, err)
		require.Equal(t, http.StatusUnauthorized, rec.Code)
		require.Contains(t, err.Error(), "Attestation verification failed")
	})

	t.Run("Valid request with attestation success but authorization failure", func(t *testing.T) {
		setup := setupHandleEnvTest(t)

		// Mock attestation to succeed with wrong digest
		setup.MockAttestation.EXPECT().
			VerifyAttestation(gomock.Any(), gomock.Any()).
			Return(&attestation.AttestationClaims{
				ImageDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				AppID:       testEnvAppID,
			}, nil)

		// Mock ChainClient to return different digest (causing authorization failure)
		hexDigest, err := hex.DecodeString(strings.TrimPrefix(testValidDigest, "sha256:"))
		require.NoError(t, err)
		var expectedDigest [32]byte
		copy(expectedDigest[:], hexDigest)
		setup.MockChainClient.EXPECT().
			GetLatestRelease(gomock.Any(), gomock.Any()).
			Return(expectedDigest, types.Env{}, []byte(""), nil)

		requestBody, _ := json.Marshal(setup.EnvRequest)
		c, rec := setupEchoContextWithBody(http.MethodPost, "/env", requestBody)

		err = HandleEnv(c, logger, setup.MockAttestation, setup.MockChainClient, setup.FakeKMS, false)

		require.Error(t, err)
		require.Equal(t, http.StatusUnauthorized, rec.Code)
		require.Contains(t, err.Error(), "Authorization failed")
	})

	t.Run("Invalid RSA key size should fail", func(t *testing.T) {
		fakeKMS, err := createFakeKMS(t)
		require.NoError(t, err)

		// Create encrypted request with smaller RSA key (2048-bit instead of 4096-bit)
		mockJWT := `{"sub":"test-app","iat":1234567890}`
		envRequest, err := fakeKMS.CreateInvalidKeyEncryptedRequest(mockJWT, 2048)
		require.NoError(t, err)

		requestBody, _ := json.Marshal(envRequest)
		c, rec := setupEchoContextWithBody(http.MethodPost, "/env", requestBody)

		// No mocks needed since validation happens before attestation/chainclient calls
		err = HandleEnv(c, logger, nil, nil, fakeKMS, false)

		require.Error(t, err)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Contains(t, err.Error(), "encryption key size mismatch")
		require.Contains(t, err.Error(), "RSA key must be 4096 bits, got 2048 bits")
	})

	t.Run("Valid request with full success path", func(t *testing.T) {
		setup := setupHandleEnvTest(t)

		// Mock attestation to succeed with correct digest
		setup.MockAttestation.EXPECT().
			VerifyAttestation(gomock.Any(), gomock.Any()).
			Return(&attestation.AttestationClaims{
				ImageDigest: testValidDigest,
				AppID:       testEnvAppID,
			}, nil)

		// Setup successful chain client response
		privateEnv := types.Env{"SECRET_KEY": "secret_value", "DATABASE_URL": "postgres://test:test@localhost/db"}
		setup.setupSuccessfulChainClient(t, testEnvAppID, privateEnv)

		requestBody, _ := json.Marshal(setup.EnvRequest)
		c, rec := setupEchoContextWithBody(http.MethodPost, "/env", requestBody)

		err := HandleEnv(c, logger, setup.MockAttestation, setup.MockChainClient, setup.FakeKMS, false)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, rec.Code)

		// Verify the response content
		setup.verifyEnvironmentResponse(t, rec, privateEnv)
	})

}

func TestHandleEnv_AppIDMismatchCheck(t *testing.T) {
	logger := setupEnvLogger()

	t.Run("App ID mismatch between attestation claims and encrypted env", func(t *testing.T) {
		setup := setupHandleEnvTest(t)

		attestationAppID := "0x1111111111111111111111111111111111111111"
		encryptedEnvAppID := "0x2222222222222222222222222222222222222222"

		// Mock attestation to succeed with one app ID
		setup.MockAttestation.EXPECT().
			VerifyAttestation(gomock.Any(), gomock.Any()).
			Return(&attestation.AttestationClaims{
				ImageDigest: testValidDigest,
				AppID:       attestationAppID,
			}, nil)

		// Create encrypted env data with different app ID in headers
		privateEnv := types.Env{"SECRET_KEY": "secret_value"}
		privateEnvJSON, _ := json.Marshal(privateEnv)
		kmsPublicKeyPEM, _ := setup.FakeKMS.GetEncryptionPublicKeyPEM()

		// Use crypto.GetAppProtectedHeaders to add the wrong app ID
		wrongHeaders := crypto.GetAppProtectedHeaders(encryptedEnvAppID)
		encryptedPrivateEnv, err := crypto.EncryptRSAOAEPAndAES256GCMWithPEM(kmsPublicKeyPEM, privateEnvJSON, wrongHeaders)
		require.NoError(t, err)

		// Mock chain client to return the encrypted env with wrong app ID
		hexDigest, err := hex.DecodeString(strings.TrimPrefix(testValidDigest, "sha256:"))
		require.NoError(t, err)
		var expectedDigest [32]byte
		copy(expectedDigest[:], hexDigest)

		publicEnv := types.Env{"PUBLIC_VAR": "public_value"}
		setup.MockChainClient.EXPECT().
			GetLatestRelease(gomock.Any(), attestationAppID).
			Return(expectedDigest, publicEnv, []byte(encryptedPrivateEnv), nil)

		requestBody, _ := json.Marshal(setup.EnvRequest)
		c, rec := setupEchoContextWithBody(http.MethodPost, "/env", requestBody)

		err = HandleEnv(c, logger, setup.MockAttestation, setup.MockChainClient, setup.FakeKMS, false)

		require.Error(t, err)
		require.Equal(t, http.StatusUnauthorized, rec.Code)
		require.Contains(t, err.Error(), "Encrypted env app id mismatch")
		require.Contains(t, err.Error(), fmt.Sprintf("expected %s, got %s", attestationAppID, encryptedEnvAppID))
	})

	t.Run("Missing app ID header in encrypted env", func(t *testing.T) {
		setup := setupHandleEnvTest(t)

		appID := "0x1111111111111111111111111111111111111111"

		// Mock attestation to succeed
		setup.MockAttestation.EXPECT().
			VerifyAttestation(gomock.Any(), gomock.Any()).
			Return(&attestation.AttestationClaims{
				ImageDigest: testValidDigest,
				AppID:       appID,
			}, nil)

		// Create encrypted env data WITHOUT app ID headers
		privateEnv := types.Env{"SECRET_KEY": "secret_value"}
		privateEnvJSON, _ := json.Marshal(privateEnv)
		kmsPublicKeyPEM, _ := setup.FakeKMS.GetEncryptionPublicKeyPEM()

		// Don't use GetAppProtectedHeaders - encrypt without the app ID header
		encryptedPrivateEnv, err := crypto.EncryptRSAOAEPAndAES256GCMWithPEM(kmsPublicKeyPEM, privateEnvJSON, nil)
		require.NoError(t, err)

		// Mock chain client to return the encrypted env without app ID header
		hexDigest, err := hex.DecodeString(strings.TrimPrefix(testValidDigest, "sha256:"))
		require.NoError(t, err)
		var expectedDigest [32]byte
		copy(expectedDigest[:], hexDigest)

		publicEnv := types.Env{"PUBLIC_VAR": "public_value"}
		setup.MockChainClient.EXPECT().
			GetLatestRelease(gomock.Any(), appID).
			Return(expectedDigest, publicEnv, []byte(encryptedPrivateEnv), nil)

		requestBody, _ := json.Marshal(setup.EnvRequest)
		c, rec := setupEchoContextWithBody(http.MethodPost, "/env", requestBody)

		err = HandleEnv(c, logger, setup.MockAttestation, setup.MockChainClient, setup.FakeKMS, false)

		require.Error(t, err)
		require.Equal(t, http.StatusInternalServerError, rec.Code)
		require.Contains(t, err.Error(), "Failed to get app id from encrypted env")
	})

	t.Run("Tampered JWE protected header fails authentication", func(t *testing.T) {
		setup := setupHandleEnvTest(t)

		// Victim's app ID (whose secrets we're trying to steal)
		victimAppID := "0x1111111111111111111111111111111111111111"
		// Attacker's app ID (who we are)
		attackerAppID := "0x2222222222222222222222222222222222222222"

		// Mock attestation to succeed with attacker's ID
		setup.MockAttestation.EXPECT().
			VerifyAttestation(gomock.Any(), gomock.Any()).
			Return(&attestation.AttestationClaims{
				ImageDigest: testValidDigest,
				AppID:       attackerAppID,
			}, nil)

		// Create victim's encrypted env data with victim's app ID in header
		victimSecrets := types.Env{"VICTIM_SECRET_KEY": "victim_secret_value"}
		victimSecretsJSON, _ := json.Marshal(victimSecrets)
		kmsPublicKeyPEM, _ := setup.FakeKMS.GetEncryptionPublicKeyPEM()

		// Encrypt with victim's app ID
		victimHeaders := crypto.GetAppProtectedHeaders(victimAppID)
		victimEncryptedEnv, err := crypto.EncryptRSAOAEPAndAES256GCMWithPEM(kmsPublicKeyPEM, victimSecretsJSON, victimHeaders)
		require.NoError(t, err)

		// Attacker attempts to tamper: replace victim's AppID with attacker's AppID in protected header
		// to try to steal victim's secrets
		jweString := string(victimEncryptedEnv)
		parts := strings.Split(jweString, ".")
		require.Equal(t, 5, len(parts), "JWE should have 5 parts in compact format")

		// Decode the protected header
		protectedHeaderBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
		require.NoError(t, err)

		var protectedHeader map[string]interface{}
		err = json.Unmarshal(protectedHeaderBytes, &protectedHeader)
		require.NoError(t, err)

		// Attacker changes the app ID to their own
		protectedHeader[crypto.JWEAppIDHeader] = attackerAppID

		// Re-encode the modified header
		modifiedHeaderBytes, _ := json.Marshal(protectedHeader)
		modifiedHeaderBase64 := base64.RawURLEncoding.EncodeToString(modifiedHeaderBytes)

		// Reconstruct JWE with attacker's app ID in header
		parts[0] = modifiedHeaderBase64
		tamperedEnv := []byte(strings.Join(parts, "."))

		// Mock chain client - attacker deployed victim's (tampered) secrets as their own
		hexDigest, err := hex.DecodeString(strings.TrimPrefix(testValidDigest, "sha256:"))
		require.NoError(t, err)
		var expectedDigest [32]byte
		copy(expectedDigest[:], hexDigest)

		publicEnv := types.Env{"PUBLIC_VAR": "public_value"}
		setup.MockChainClient.EXPECT().
			GetLatestRelease(gomock.Any(), attackerAppID).
			Return(expectedDigest, publicEnv, tamperedEnv, nil)

		requestBody, _ := json.Marshal(setup.EnvRequest)
		c, rec := setupEchoContextWithBody(http.MethodPost, "/env", requestBody)

		err = HandleEnv(c, logger, setup.MockAttestation, setup.MockChainClient, setup.FakeKMS, false)

		require.Error(t, err)
		require.Equal(t, http.StatusInternalServerError, rec.Code)

		// The tampered JWE should fail decryption due to AEAD authentication tag verification
		// The protected header is part of the Additional Authenticated Data (AAD)
		require.Contains(t, err.Error(), "Failed to decrypt encrypted env",
			"Expected decryption failure due to tampered protected header")
	})

	t.Run("Case insensitive AppID comparison", func(t *testing.T) {
		setup := setupHandleEnvTest(t)

		// Use different case app IDs that should match when compared case-insensitively
		lowerCaseAppID := "0xabcd1234567890abcd1234567890abcd12345678"
		mixedCaseAppID := "0xABCD1234567890ABCD1234567890ABCD12345678"

		// Mock attestation with mixed case
		setup.MockAttestation.EXPECT().
			VerifyAttestation(gomock.Any(), gomock.Any()).
			Return(&attestation.AttestationClaims{
				ImageDigest: testValidDigest,
				AppID:       mixedCaseAppID,
			}, nil)

		// Create encrypted env with lowercase
		privateEnv := types.Env{"SECRET_KEY": "secret_value"}
		privateEnvJSON, _ := json.Marshal(privateEnv)
		kmsPublicKeyPEM, _ := setup.FakeKMS.GetEncryptionPublicKeyPEM()

		appHeaders := crypto.GetAppProtectedHeaders(lowerCaseAppID)
		encryptedPrivateEnv, err := crypto.EncryptRSAOAEPAndAES256GCMWithPEM(kmsPublicKeyPEM, privateEnvJSON, appHeaders)
		require.NoError(t, err)

		// Mock chain client
		hexDigest, err := hex.DecodeString(strings.TrimPrefix(testValidDigest, "sha256:"))
		require.NoError(t, err)
		var expectedDigest [32]byte
		copy(expectedDigest[:], hexDigest)

		publicEnv := types.Env{"PUBLIC_VAR": "public_value"}
		setup.MockChainClient.EXPECT().
			GetLatestRelease(gomock.Any(), mixedCaseAppID).
			Return(expectedDigest, publicEnv, encryptedPrivateEnv, nil)

		requestBody, _ := json.Marshal(setup.EnvRequest)
		c, rec := setupEchoContextWithBody(http.MethodPost, "/env", requestBody)

		err = HandleEnv(c, logger, setup.MockAttestation, setup.MockChainClient, setup.FakeKMS, false)

		// Should succeed despite case mismatch
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestHandleEnv_DebugModeAppIDOverride(t *testing.T) {
	logger := setupEnvLogger()

	t.Run("AppID override in debug mode", func(t *testing.T) {
		setup := setupHandleEnvTest(t)

		originalAppID := "0x2222222222222222222222222222222222222222"
		overrideAppID := "0x9999999999999999999999999999999999999999"

		// Mock attestation to succeed with original AppID
		setup.MockAttestation.EXPECT().
			VerifyAttestation(gomock.Any(), gomock.Any()).
			Return(&attestation.AttestationClaims{
				ImageDigest: testValidDigest,
				AppID:       originalAppID,
			}, nil)

		// Setup chain client to expect call with OVERRIDE AppID
		privateEnv := types.Env{"SECRET_KEY": "debug_secret"}
		setup.setupSuccessfulChainClient(t, overrideAppID, privateEnv)

		requestBody, _ := json.Marshal(setup.EnvRequest)
		c, rec := setupEchoContextWithBodyAndQuery(http.MethodPost, "/env", requestBody, map[string]string{"appID": overrideAppID})

		// Enable debug mode
		err := HandleEnv(c, logger, setup.MockAttestation, setup.MockChainClient, setup.FakeKMS, true)

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("No AppID override in non-debug mode", func(t *testing.T) {
		setup := setupHandleEnvTest(t)

		originalAppID := "0x2222222222222222222222222222222222222222"
		overrideAppID := "0x9999999999999999999999999999999999999999"

		// Mock attestation to succeed with original AppID
		setup.MockAttestation.EXPECT().
			VerifyAttestation(gomock.Any(), gomock.Any()).
			Return(&attestation.AttestationClaims{
				ImageDigest: testValidDigest,
				AppID:       originalAppID,
			}, nil)

		requestBody, _ := json.Marshal(setup.EnvRequest)
		c, rec := setupEchoContextWithBodyAndQuery(http.MethodPost, "/env", requestBody, map[string]string{"appID": overrideAppID})

		// Disable debug mode
		err := HandleEnv(c, logger, setup.MockAttestation, setup.MockChainClient, setup.FakeKMS, false)

		require.Error(t, err)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Contains(t, err.Error(), "appID query parameter is only allowed in debug mode")
	})

}
