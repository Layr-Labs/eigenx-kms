package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Layr-Labs/eigenx-kms/internal/auth"
	"github.com/Layr-Labs/eigenx-kms/internal/kms/fakes"
	"github.com/Layr-Labs/eigenx-kms/pkg/attestation"
	attestationMocks "github.com/Layr-Labs/eigenx-kms/pkg/attestation/mocks"
	"github.com/Layr-Labs/eigenx-kms/pkg/crypto"
	policyMocks "github.com/Layr-Labs/eigenx-kms/pkg/policy/mocks"
	"github.com/Layr-Labs/eigenx-kms/pkg/types"
	"github.com/Layr-Labs/go-tpm-tools/sdk/attest"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func createTestJWTSigner(t *testing.T) *auth.JWTSigner {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	signer, err := auth.NewJWTSigner(string(pemBytes), time.Hour)
	require.NoError(t, err)
	return signer
}

func TestHandleAttest_InvalidJSON(t *testing.T) {
	logger := setupEnvLogger()
	signer := createTestJWTSigner(t)

	c, rec := setupEchoContextWithBody(http.MethodPost, "/auth/attest", []byte("{invalid"))

	err := HandleAttest(c, logger, signer, nil, nil, nil, nil, false)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	requireErrorResponse(t, rec, "Failed to parse attest request")
}

func TestHandleAttest_InvalidVersion(t *testing.T) {
	logger := setupEnvLogger()
	signer := createTestJWTSigner(t)

	body, _ := json.Marshal(types.AttestRequest{Version: 99})
	c, rec := setupEchoContextWithBody(http.MethodPost, "/auth/attest", body)

	err := HandleAttest(c, logger, signer, nil, nil, nil, nil, false)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	requireErrorResponse(t, rec, "Unsupported attestation version: 99")
}

// --- V1 tests ---

func TestHandleAttest_V1_AttestationFailure(t *testing.T) {
	logger := setupEnvLogger()
	signer := createTestJWTSigner(t)

	fakeKMS, err := fakes.NewFakeKMS()
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAttestation := attestationMocks.NewMockAttestationVerifierInterface(ctrl)

	mockJWT := `{"sub":"test-app","iat":1234567890}`
	envReq, _, err := fakeKMS.CreateValidEncryptedRequestV1(mockJWT)
	require.NoError(t, err)

	attestReq := types.AttestRequest{
		Version:                1,
		EncryptedJWTWithRSAKey: envReq.EncryptedJWTWithRSAKey,
	}
	body, _ := json.Marshal(attestReq)
	c, rec := setupEchoContextWithBody(http.MethodPost, "/auth/attest", body)

	mockAttestation.EXPECT().
		VerifyAttestation(gomock.Any(), gomock.Any(), attestation.GoogleConfidentialSpace).
		Return(nil, errors.New("attestation failed"))

	err = HandleAttest(c, logger, signer, mockAttestation, nil, nil, fakeKMS, false)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	requireErrorResponse(t, rec, "Attestation verification failed")
}

func TestHandleAttest_V1_Success(t *testing.T) {
	logger := setupEnvLogger()
	signer := createTestJWTSigner(t)

	fakeKMS, err := fakes.NewFakeKMS()
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAttestation := attestationMocks.NewMockAttestationVerifierInterface(ctrl)

	mockJWT := `{"sub":"test-app","iat":1234567890}`
	envReq, _, err := fakeKMS.CreateValidEncryptedRequestV1(mockJWT)
	require.NoError(t, err)

	attestReq := types.AttestRequest{
		Version:                1,
		EncryptedJWTWithRSAKey: envReq.EncryptedJWTWithRSAKey,
	}
	body, _ := json.Marshal(attestReq)
	c, rec := setupEchoContextWithBody(http.MethodPost, "/auth/attest", body)

	claims := &attestation.AttestationClaims{
		AppID:       testEnvAppID,
		ImageDigest: testValidDigest,
		Nonce:       "",
	}
	mockAttestation.EXPECT().
		VerifyAttestation(gomock.Any(), gomock.Any(), attestation.GoogleConfidentialSpace).
		Return(claims, nil)

	err = HandleAttest(c, logger, signer, mockAttestation, nil, nil, fakeKMS, false)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rec.Code)

	// Verify JWT claims
	var signedResponse types.SignedResponse[types.AttestResponse]
	err = json.Unmarshal(rec.Body.Bytes(), &signedResponse)
	require.NoError(t, err)
	require.NotEmpty(t, signedResponse.Data.Token)

	parsed, err := jwt.Parse([]byte(signedResponse.Data.Token), jwt.WithKey(jwa.RS256(), signer.PublicKey()))
	require.NoError(t, err)

	sub, ok := parsed.Subject()
	require.True(t, ok)
	require.Equal(t, testEnvAppID, sub)

	var gotAppID string
	require.NoError(t, parsed.Get("appId", &gotAppID))
	require.Equal(t, testEnvAppID, gotAppID)

	var gotDigest string
	require.NoError(t, parsed.Get("imageDigest", &gotDigest))
	require.Equal(t, testValidDigest, gotDigest)
}

func TestHandleAttest_V1_NonceRejected(t *testing.T) {
	logger := setupEnvLogger()
	signer := createTestJWTSigner(t)

	fakeKMS, err := fakes.NewFakeKMS()
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAttestation := attestationMocks.NewMockAttestationVerifierInterface(ctrl)

	mockJWT := `{"sub":"test-app","iat":1234567890}`
	envReq, _, err := fakeKMS.CreateValidEncryptedRequestV1(mockJWT)
	require.NoError(t, err)

	attestReq := types.AttestRequest{
		Version:                1,
		EncryptedJWTWithRSAKey: envReq.EncryptedJWTWithRSAKey,
	}
	body, _ := json.Marshal(attestReq)
	c, rec := setupEchoContextWithBody(http.MethodPost, "/auth/attest", body)

	claims := &attestation.AttestationClaims{
		AppID:       testEnvAppID,
		ImageDigest: testValidDigest,
		Nonce:       "some-nonce",
	}
	mockAttestation.EXPECT().
		VerifyAttestation(gomock.Any(), gomock.Any(), attestation.GoogleConfidentialSpace).
		Return(claims, nil)

	err = HandleAttest(c, logger, signer, mockAttestation, nil, nil, fakeKMS, false)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	requireErrorResponse(t, rec, "nonce should be empty for v1 attestation requests")
}

// --- V2 tests ---

func TestHandleAttest_V2_AttestationFailure(t *testing.T) {
	logger := setupEnvLogger()
	signer := createTestJWTSigner(t)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAttestation := attestationMocks.NewMockAttestationVerifierInterface(ctrl)

	_, clientRSAPublicPEM, err := crypto.GenerateRSAKeyPair()
	require.NoError(t, err)

	attestReq := types.AttestRequest{
		Version:               2,
		JWTWithAttestedRSAKey: "mock-jwt",
		RSAKeyPEM:             string(clientRSAPublicPEM),
	}
	body, _ := json.Marshal(attestReq)
	c, rec := setupEchoContextWithBody(http.MethodPost, "/auth/attest", body)

	mockAttestation.EXPECT().
		VerifyAttestation(gomock.Any(), gomock.Any(), attestation.IntelTrustAuthority).
		Return(nil, errors.New("attestation failed"))

	err = HandleAttest(c, logger, signer, mockAttestation, nil, nil, nil, false)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	requireErrorResponse(t, rec, "Attestation verification failed")
}

func TestHandleAttest_V2_InvalidRSAKeySize(t *testing.T) {
	logger := setupEnvLogger()
	signer := createTestJWTSigner(t)

	smallKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	smallPubBytes, err := x509.MarshalPKIXPublicKey(&smallKey.PublicKey)
	require.NoError(t, err)
	smallPubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: smallPubBytes})

	attestReq := types.AttestRequest{
		Version:               2,
		JWTWithAttestedRSAKey: "mock-jwt",
		RSAKeyPEM:             string(smallPubPEM),
	}
	body, _ := json.Marshal(attestReq)
	c, rec := setupEchoContextWithBody(http.MethodPost, "/auth/attest", body)

	err = HandleAttest(c, logger, signer, nil, nil, nil, nil, false)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	requireErrorResponse(t, rec, "encryption key size mismatch")
}

func TestHandleAttest_V2_RSAKeyAttestationMismatch(t *testing.T) {
	logger := setupEnvLogger()
	signer := createTestJWTSigner(t)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAttestation := attestationMocks.NewMockAttestationVerifierInterface(ctrl)

	_, clientRSAPublicPEM, err := crypto.GenerateRSAKeyPair()
	require.NoError(t, err)

	attestReq := types.AttestRequest{
		Version:               2,
		JWTWithAttestedRSAKey: "mock-jwt",
		RSAKeyPEM:             string(clientRSAPublicPEM),
	}
	body, _ := json.Marshal(attestReq)
	c, rec := setupEchoContextWithBody(http.MethodPost, "/auth/attest", body)

	claims := &attestation.AttestationClaims{
		AppID:       testEnvAppID,
		ImageDigest: testValidDigest,
		Nonce:       "wrong-nonce",
	}
	mockAttestation.EXPECT().
		VerifyAttestation(gomock.Any(), gomock.Any(), attestation.IntelTrustAuthority).
		Return(claims, nil)

	err = HandleAttest(c, logger, signer, mockAttestation, nil, nil, nil, false)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	requireErrorResponse(t, rec, "RSA key attestation check failed")
}

func TestHandleAttest_V2_Success(t *testing.T) {
	logger := setupEnvLogger()
	signer := createTestJWTSigner(t)

	fakeKMS, err := fakes.NewFakeKMS()
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAttestation := attestationMocks.NewMockAttestationVerifierInterface(ctrl)

	_, clientRSAPublicPEM, err := crypto.GenerateRSAKeyPair()
	require.NoError(t, err)

	// Calculate expected nonce
	hashBytes := crypto.CalculateSignableDigest(crypto.EnvRequestRSAKeyHeader, clientRSAPublicPEM)
	expectedNonce := encodeHex(hashBytes)

	attestReq := types.AttestRequest{
		Version:               2,
		JWTWithAttestedRSAKey: "mock-jwt",
		RSAKeyPEM:             string(clientRSAPublicPEM),
	}
	body, _ := json.Marshal(attestReq)
	c, rec := setupEchoContextWithBody(http.MethodPost, "/auth/attest", body)

	claims := &attestation.AttestationClaims{
		AppID:       testEnvAppID,
		ImageDigest: testValidDigest,
		Nonce:       expectedNonce,
	}
	mockAttestation.EXPECT().
		VerifyAttestation(gomock.Any(), gomock.Any(), attestation.IntelTrustAuthority).
		Return(claims, nil)

	err = HandleAttest(c, logger, signer, mockAttestation, nil, nil, fakeKMS, false)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rec.Code)

	// Verify JWT claims
	var signedResponse types.SignedResponse[types.AttestResponse]
	err = json.Unmarshal(rec.Body.Bytes(), &signedResponse)
	require.NoError(t, err)

	parsed, err := jwt.Parse([]byte(signedResponse.Data.Token), jwt.WithKey(jwa.RS256(), signer.PublicKey()))
	require.NoError(t, err)

	sub, ok := parsed.Subject()
	require.True(t, ok)
	require.Equal(t, testEnvAppID, sub)
}

// --- V3 tests ---

func TestHandleAttest_V3_AttestationFailure(t *testing.T) {
	logger := setupEnvLogger()
	signer := createTestJWTSigner(t)

	fakeKMS, err := fakes.NewFakeKMS()
	require.NoError(t, err)

	_, clientRSAPublicPEM, err := crypto.GenerateRSAKeyPair()
	require.NoError(t, err)

	verifier := &stubBoundAttestationEvidenceVerifier{
		err: errors.New("bad quote"),
	}

	attestReq := types.AttestRequest{
		Version:     3,
		Attestation: base64.StdEncoding.EncodeToString([]byte("dummy")),
		RSAKeyPEM:   string(clientRSAPublicPEM),
	}
	body, _ := json.Marshal(attestReq)
	c, rec := setupEchoContextWithBody(http.MethodPost, "/auth/attest", body)

	err = HandleAttest(c, logger, signer, nil, verifier, nil, fakeKMS, false)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	requireErrorResponse(t, rec, "Attestation verification failed")
}

func TestHandleAttest_V3_PolicyFailure(t *testing.T) {
	logger := setupEnvLogger()
	signer := createTestJWTSigner(t)

	fakeKMS, err := fakes.NewFakeKMS()
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockPolicy := policyMocks.NewMockPolicyCheckerInterface(ctrl)

	_, clientRSAPublicPEM, err := crypto.GenerateRSAKeyPair()
	require.NoError(t, err)

	verifier := &stubBoundAttestationEvidenceVerifier{
		result: gcpTPMClaims(testEnvAppID, testValidDigest),
	}

	mockPolicy.EXPECT().
		CheckTPMPolicies(gomock.Any(), gomock.Any()).
		Return(errors.New("not hardened"))

	attestReq := types.AttestRequest{
		Version:     3,
		Attestation: base64.StdEncoding.EncodeToString([]byte("dummy")),
		RSAKeyPEM:   string(clientRSAPublicPEM),
	}
	body, _ := json.Marshal(attestReq)
	c, rec := setupEchoContextWithBody(http.MethodPost, "/auth/attest", body)

	err = HandleAttest(c, logger, signer, nil, verifier, mockPolicy, fakeKMS, false)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	requireErrorResponse(t, rec, "TPM policy check failed")
}

func TestHandleAttest_V3_MissingGCEInfo(t *testing.T) {
	logger := setupEnvLogger()
	signer := createTestJWTSigner(t)

	fakeKMS, err := fakes.NewFakeKMS()
	require.NoError(t, err)

	_, clientRSAPublicPEM, err := crypto.GenerateRSAKeyPair()
	require.NoError(t, err)

	verifier := &stubBoundAttestationEvidenceVerifier{
		result: &attestation.VerifiedAttestation{
			TPMClaims: &attest.TPMClaims{GCE: nil},
			Container: &attest.ContainerInfo{ImageDigest: testValidDigest},
		},
	}

	attestReq := types.AttestRequest{
		Version:     3,
		Attestation: base64.StdEncoding.EncodeToString([]byte("dummy")),
		RSAKeyPEM:   string(clientRSAPublicPEM),
	}
	body, _ := json.Marshal(attestReq)
	c, rec := setupEchoContextWithBody(http.MethodPost, "/auth/attest", body)

	err = HandleAttest(c, logger, signer, nil, verifier, nil, fakeKMS, false)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	requireErrorResponse(t, rec, "GCE instance info not found in attestation")
}

func TestHandleAttest_V3_MissingContainerInfo(t *testing.T) {
	logger := setupEnvLogger()
	signer := createTestJWTSigner(t)

	fakeKMS, err := fakes.NewFakeKMS()
	require.NoError(t, err)

	_, clientRSAPublicPEM, err := crypto.GenerateRSAKeyPair()
	require.NoError(t, err)

	verifier := &stubBoundAttestationEvidenceVerifier{
		result: &attestation.VerifiedAttestation{
			TPMClaims: &attest.TPMClaims{
				GCE: &attest.GCEInfo{InstanceName: "app-" + testEnvAppID, ProjectID: "test-project"},
			},
			Container: nil,
		},
	}

	attestReq := types.AttestRequest{
		Version:     3,
		Attestation: base64.StdEncoding.EncodeToString([]byte("dummy")),
		RSAKeyPEM:   string(clientRSAPublicPEM),
	}
	body, _ := json.Marshal(attestReq)
	c, rec := setupEchoContextWithBody(http.MethodPost, "/auth/attest", body)

	err = HandleAttest(c, logger, signer, nil, verifier, nil, fakeKMS, false)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	requireErrorResponse(t, rec, "Container info not found in attestation")
}

func TestHandleAttest_V3_Success(t *testing.T) {
	logger := setupEnvLogger()
	signer := createTestJWTSigner(t)

	fakeKMS, err := fakes.NewFakeKMS()
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockPolicy := policyMocks.NewMockPolicyCheckerInterface(ctrl)

	_, clientRSAPublicPEM, err := crypto.GenerateRSAKeyPair()
	require.NoError(t, err)

	verifier := &stubBoundAttestationEvidenceVerifier{
		result: gcpTPMClaims(testEnvAppID, testValidDigest),
	}

	mockPolicy.EXPECT().
		CheckTPMPolicies(gomock.Any(), gomock.Any()).
		Return(nil)

	attestReq := types.AttestRequest{
		Version:     3,
		Attestation: base64.StdEncoding.EncodeToString([]byte("dummy")),
		RSAKeyPEM:   string(clientRSAPublicPEM),
	}
	body, _ := json.Marshal(attestReq)
	c, rec := setupEchoContextWithBody(http.MethodPost, "/auth/attest", body)

	err = HandleAttest(c, logger, signer, nil, verifier, mockPolicy, fakeKMS, false)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rec.Code)

	// Verify JWT claims
	var signedResponse types.SignedResponse[types.AttestResponse]
	err = json.Unmarshal(rec.Body.Bytes(), &signedResponse)
	require.NoError(t, err)

	parsed, err := jwt.Parse([]byte(signedResponse.Data.Token), jwt.WithKey(jwa.RS256(), signer.PublicKey()))
	require.NoError(t, err)

	sub, ok := parsed.Subject()
	require.True(t, ok)
	require.Equal(t, testEnvAppID, sub)

	var gotDigest string
	require.NoError(t, parsed.Get("imageDigest", &gotDigest))
	require.Equal(t, testValidDigest, gotDigest)
}

func TestHandleAttest_V3_TEEPolicyFailure(t *testing.T) {
	logger := setupEnvLogger()
	signer := createTestJWTSigner(t)

	fakeKMS, err := fakes.NewFakeKMS()
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockPolicy := policyMocks.NewMockPolicyCheckerInterface(ctrl)

	_, clientRSAPublicPEM, err := crypto.GenerateRSAKeyPair()
	require.NoError(t, err)

	verifier := &stubBoundAttestationEvidenceVerifier{
		result: &attestation.VerifiedAttestation{
			TPMClaims: &attest.TPMClaims{
				GCE: &attest.GCEInfo{InstanceName: "app-" + testEnvAppID, ProjectID: "test-project"},
			},
			Container: &attest.ContainerInfo{ImageDigest: testValidDigest},
			TEEClaims: &attest.TEEClaims{},
		},
	}

	mockPolicy.EXPECT().
		CheckTPMPolicies(gomock.Any(), gomock.Any()).
		Return(nil)
	mockPolicy.EXPECT().
		CheckTEEPolicies(gomock.Any(), gomock.Any()).
		Return(errors.New("tcb out of date"))

	attestReq := types.AttestRequest{
		Version:     3,
		Attestation: base64.StdEncoding.EncodeToString([]byte("dummy")),
		RSAKeyPEM:   string(clientRSAPublicPEM),
	}
	body, _ := json.Marshal(attestReq)
	c, rec := setupEchoContextWithBody(http.MethodPost, "/auth/attest", body)

	err = HandleAttest(c, logger, signer, nil, verifier, mockPolicy, fakeKMS, false)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	requireErrorResponse(t, rec, "TEE policy check failed")
}

// --- Debug mode tests ---

func TestHandleAttest_V2_DebugOverride(t *testing.T) {
	logger := setupEnvLogger()
	signer := createTestJWTSigner(t)

	fakeKMS, err := fakes.NewFakeKMS()
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAttestation := attestationMocks.NewMockAttestationVerifierInterface(ctrl)

	_, clientRSAPublicPEM, err := crypto.GenerateRSAKeyPair()
	require.NoError(t, err)

	hashBytes := crypto.CalculateSignableDigest(crypto.EnvRequestRSAKeyHeader, clientRSAPublicPEM)
	expectedNonce := encodeHex(hashBytes)

	claims := &attestation.AttestationClaims{
		AppID:       "0x2222222222222222222222222222222222222222",
		ImageDigest: testValidDigest,
		Nonce:       expectedNonce,
	}
	mockAttestation.EXPECT().
		VerifyAttestation(gomock.Any(), gomock.Any(), attestation.IntelTrustAuthority).
		Return(claims, nil)

	overrideAppID := "0x9999999999999999999999999999999999999999"
	attestReq := types.AttestRequest{
		Version:               2,
		JWTWithAttestedRSAKey: "mock-jwt",
		RSAKeyPEM:             string(clientRSAPublicPEM),
	}
	body, _ := json.Marshal(attestReq)
	c, rec := setupEchoContextWithBodyAndQuery(http.MethodPost, "/auth/attest", body, map[string]string{"appID": overrideAppID})

	err = HandleAttest(c, logger, signer, mockAttestation, nil, nil, fakeKMS, true)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rec.Code)

	var signedResponse types.SignedResponse[types.AttestResponse]
	err = json.Unmarshal(rec.Body.Bytes(), &signedResponse)
	require.NoError(t, err)

	parsed, err := jwt.Parse([]byte(signedResponse.Data.Token), jwt.WithKey(jwa.RS256(), signer.PublicKey()))
	require.NoError(t, err)

	var gotAppID string
	require.NoError(t, parsed.Get("appId", &gotAppID))
	require.Equal(t, overrideAppID, gotAppID)
}

func TestHandleAttest_V2_DebugOverrideRejectedInNonDebugMode(t *testing.T) {
	logger := setupEnvLogger()
	signer := createTestJWTSigner(t)

	fakeKMS, err := fakes.NewFakeKMS()
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAttestation := attestationMocks.NewMockAttestationVerifierInterface(ctrl)
	_, clientRSAPublicPEM, err := crypto.GenerateRSAKeyPair()
	require.NoError(t, err)

	hashBytes := crypto.CalculateSignableDigest(crypto.EnvRequestRSAKeyHeader, clientRSAPublicPEM)
	expectedNonce := encodeHex(hashBytes)

	claims := &attestation.AttestationClaims{
		AppID:       testEnvAppID,
		ImageDigest: testValidDigest,
		Nonce:       expectedNonce,
	}
	mockAttestation.EXPECT().
		VerifyAttestation(gomock.Any(), gomock.Any(), attestation.IntelTrustAuthority).
		Return(claims, nil)

	attestReq := types.AttestRequest{
		Version:               2,
		JWTWithAttestedRSAKey: "mock-jwt",
		RSAKeyPEM:             string(clientRSAPublicPEM),
	}
	body, _ := json.Marshal(attestReq)
	c, rec := setupEchoContextWithBodyAndQuery(http.MethodPost, "/auth/attest", body, map[string]string{"appID": "0x999"})

	err = HandleAttest(c, logger, signer, mockAttestation, nil, nil, fakeKMS, false)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	requireErrorResponse(t, rec, "appID query parameter is only allowed in debug mode")
}

func encodeHex(b []byte) string {
	return hex.EncodeToString(b)
}
