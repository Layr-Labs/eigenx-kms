package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Layr-Labs/eigenx-kms/internal/auth"
	"github.com/Layr-Labs/eigenx-kms/internal/kms/fakes"
	"github.com/Layr-Labs/eigenx-kms/pkg/attestation"
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

	err := HandleAttest(c, logger, signer, nil, nil, nil, false)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	requireErrorResponse(t, rec, "Failed to parse attest request")
}

func TestHandleAttest_UnsupportedVersion(t *testing.T) {
	logger := setupEnvLogger()
	signer := createTestJWTSigner(t)

	for _, version := range []int{0, 1, 2, 99} {
		body, _ := json.Marshal(types.AttestRequest{Version: version})
		c, rec := setupEchoContextWithBody(http.MethodPost, "/auth/attest", body)

		err := HandleAttest(c, logger, signer, nil, nil, nil, false)
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		requireErrorResponse(t, rec, "Unsupported attestation version")
	}
}

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

	err = HandleAttest(c, logger, signer, verifier, nil, fakeKMS, false)
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

	err = HandleAttest(c, logger, signer, verifier, mockPolicy, fakeKMS, false)
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

	err = HandleAttest(c, logger, signer, verifier, nil, fakeKMS, false)
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

	err = HandleAttest(c, logger, signer, verifier, nil, fakeKMS, false)
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

	clientRSAPrivatePEM, clientRSAPublicPEM, err := crypto.GenerateRSAKeyPair()
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

	err = HandleAttest(c, logger, signer, verifier, mockPolicy, fakeKMS, false)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rec.Code)

	// Parse signed response
	var signedResponse types.SignedResponse[types.AttestResponse]
	err = json.Unmarshal(rec.Body.Bytes(), &signedResponse)
	require.NoError(t, err)
	require.NotEmpty(t, signedResponse.Data.EncryptedToken)

	// Decrypt the token
	rsaPrivateKey, err := crypto.RSAPrivateKeyFromPEM(clientRSAPrivatePEM)
	require.NoError(t, err)
	decryptedBytes, err := crypto.DecryptWithRSAOAEPAndAES256GCM(rsaPrivateKey, []byte(signedResponse.Data.EncryptedToken))
	require.NoError(t, err)

	var tokenPayload map[string]string
	err = json.Unmarshal(decryptedBytes, &tokenPayload)
	require.NoError(t, err)

	tokenStr := tokenPayload["token"]
	require.NotEmpty(t, tokenStr)

	// Verify JWT claims
	parsed, err := jwt.Parse([]byte(tokenStr), jwt.WithKey(jwa.RS256(), signer.PublicKey()))
	require.NoError(t, err)

	sub, ok := parsed.Subject()
	require.True(t, ok)
	require.Equal(t, testEnvAppID, sub)

	// Verify rich claims
	var gotSubmods map[string]interface{}
	require.NoError(t, parsed.Get("submods", &gotSubmods))
	container := gotSubmods["container"].(map[string]interface{})
	require.Equal(t, testValidDigest, container["image_digest"])
}

func TestHandleAttest_V3_WithAudience(t *testing.T) {
	logger := setupEnvLogger()
	signer := createTestJWTSigner(t)

	fakeKMS, err := fakes.NewFakeKMS()
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockPolicy := policyMocks.NewMockPolicyCheckerInterface(ctrl)

	clientRSAPrivatePEM, clientRSAPublicPEM, err := crypto.GenerateRSAKeyPair()
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
		Audience:    "test-audience",
	}
	body, _ := json.Marshal(attestReq)
	c, rec := setupEchoContextWithBody(http.MethodPost, "/auth/attest", body)

	err = HandleAttest(c, logger, signer, verifier, mockPolicy, fakeKMS, false)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rec.Code)

	// Decrypt and verify audience claim
	var signedResponse types.SignedResponse[types.AttestResponse]
	err = json.Unmarshal(rec.Body.Bytes(), &signedResponse)
	require.NoError(t, err)

	rsaPrivateKey, err := crypto.RSAPrivateKeyFromPEM(clientRSAPrivatePEM)
	require.NoError(t, err)
	decryptedBytes, err := crypto.DecryptWithRSAOAEPAndAES256GCM(rsaPrivateKey, []byte(signedResponse.Data.EncryptedToken))
	require.NoError(t, err)

	var tokenPayload map[string]string
	err = json.Unmarshal(decryptedBytes, &tokenPayload)
	require.NoError(t, err)

	parsed, err := jwt.Parse([]byte(tokenPayload["token"]), jwt.WithKey(jwa.RS256(), signer.PublicKey()))
	require.NoError(t, err)

	aud, ok := parsed.Audience()
	require.True(t, ok)
	require.Contains(t, aud, "test-audience")
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

	err = HandleAttest(c, logger, signer, verifier, mockPolicy, fakeKMS, false)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	requireErrorResponse(t, rec, "TEE policy check failed")
}

func TestHandleAttest_V3_DebugOverride(t *testing.T) {
	logger := setupEnvLogger()
	signer := createTestJWTSigner(t)

	fakeKMS, err := fakes.NewFakeKMS()
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockPolicy := policyMocks.NewMockPolicyCheckerInterface(ctrl)

	clientRSAPrivatePEM, clientRSAPublicPEM, err := crypto.GenerateRSAKeyPair()
	require.NoError(t, err)

	verifier := &stubBoundAttestationEvidenceVerifier{
		result: gcpTPMClaims(testEnvAppID, testValidDigest),
	}

	mockPolicy.EXPECT().
		CheckTPMPolicies(gomock.Any(), gomock.Any()).
		Return(nil)

	overrideAppID := "0x9999999999999999999999999999999999999999"
	attestReq := types.AttestRequest{
		Version:     3,
		Attestation: base64.StdEncoding.EncodeToString([]byte("dummy")),
		RSAKeyPEM:   string(clientRSAPublicPEM),
	}
	body, _ := json.Marshal(attestReq)
	c, rec := setupEchoContextWithBodyAndQuery(http.MethodPost, "/auth/attest", body, map[string]string{"appID": overrideAppID})

	err = HandleAttest(c, logger, signer, verifier, mockPolicy, fakeKMS, true)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rec.Code)

	var signedResponse types.SignedResponse[types.AttestResponse]
	err = json.Unmarshal(rec.Body.Bytes(), &signedResponse)
	require.NoError(t, err)

	rsaPrivateKey, err := crypto.RSAPrivateKeyFromPEM(clientRSAPrivatePEM)
	require.NoError(t, err)
	decryptedBytes, err := crypto.DecryptWithRSAOAEPAndAES256GCM(rsaPrivateKey, []byte(signedResponse.Data.EncryptedToken))
	require.NoError(t, err)

	var tokenPayload map[string]string
	err = json.Unmarshal(decryptedBytes, &tokenPayload)
	require.NoError(t, err)

	parsed, err := jwt.Parse([]byte(tokenPayload["token"]), jwt.WithKey(jwa.RS256(), signer.PublicKey()))
	require.NoError(t, err)

	var gotAppID string
	require.NoError(t, parsed.Get("appId", &gotAppID))
	require.Equal(t, overrideAppID, gotAppID)
}

func TestHandleAttest_V3_DebugOverrideRejectedInNonDebugMode(t *testing.T) {
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

	attestReq := types.AttestRequest{
		Version:     3,
		Attestation: base64.StdEncoding.EncodeToString([]byte("dummy")),
		RSAKeyPEM:   string(clientRSAPublicPEM),
	}
	body, _ := json.Marshal(attestReq)
	c, rec := setupEchoContextWithBodyAndQuery(http.MethodPost, "/auth/attest", body, map[string]string{"appID": "0x999"})

	err = HandleAttest(c, logger, signer, verifier, mockPolicy, fakeKMS, false)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	requireErrorResponse(t, rec, "appID query parameter is only allowed in debug mode")
}
