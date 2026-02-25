package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Layr-Labs/eigenx-kms/internal/kms/fakes"
	"github.com/Layr-Labs/eigenx-kms/pkg/attestation"
	chainClientMocks "github.com/Layr-Labs/eigenx-kms/pkg/chainclient/mocks"
	"github.com/Layr-Labs/eigenx-kms/pkg/crypto"
	policyMocks "github.com/Layr-Labs/eigenx-kms/pkg/policy/mocks"
	"github.com/Layr-Labs/eigenx-kms/pkg/types"
	"github.com/Layr-Labs/go-tpm-tools/teeverify"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// stubBoundAttestationEvidenceVerifier is a lightweight test double for
// attestation.BoundAttestationEvidenceVerifier that returns preset values without gomock setup.
type stubBoundAttestationEvidenceVerifier struct {
	result *attestation.VerifiedAttestation
	err    error
}

func (s *stubBoundAttestationEvidenceVerifier) Verify(_ context.Context, _, _ []byte) (*attestation.VerifiedAttestation, error) {
	return s.result, s.err
}

// TestHandleEnvV3_InputValidation tests input validation before attestation verification.
func TestHandleEnvV3_InputValidation(t *testing.T) {
	logger := setupEnvLogger()

	t.Run("invalid JSON in request body", func(t *testing.T) {
		c, rec := setupEchoContextWithBody(http.MethodPost, "/env/v3", []byte("{invalid json}"))

		err := HandleEnvV3(c, logger, nil, nil, nil, nil, false)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		requireErrorResponse(t, rec, "Failed to parse env request v3")
	})

	t.Run("invalid RSA key PEM", func(t *testing.T) {
		envRequest := types.EnvRequestV3{
			Attestation: base64.StdEncoding.EncodeToString([]byte("attestation")),
			RSAKeyPEM:   "not-a-valid-pem",
		}
		requestBody, _ := json.Marshal(envRequest)
		c, rec := setupEchoContextWithBody(http.MethodPost, "/env/v3", requestBody)

		err := HandleEnvV3(c, logger, nil, nil, nil, nil, false)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		requireErrorResponse(t, rec, "encryption key size mismatch")
	})

	t.Run("RSA key size mismatch - 2048 bit instead of 4096", func(t *testing.T) {
		smallPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		smallPublicKeyBytes, err := x509.MarshalPKIXPublicKey(&smallPrivateKey.PublicKey)
		require.NoError(t, err)

		smallPublicKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: smallPublicKeyBytes,
		})

		envRequest := types.EnvRequestV3{
			Attestation: base64.StdEncoding.EncodeToString([]byte("attestation")),
			RSAKeyPEM:   string(smallPublicKeyPEM),
		}

		requestBody, _ := json.Marshal(envRequest)
		c, rec := setupEchoContextWithBody(http.MethodPost, "/env/v3", requestBody)

		err = HandleEnvV3(c, logger, nil, nil, nil, nil, false)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		requireErrorResponse(t, rec, "encryption key size mismatch")
	})

	t.Run("invalid base64 attestation", func(t *testing.T) {
		_, clientRSAPublicPEM, err := crypto.GenerateRSAKeyPair()
		require.NoError(t, err)

		envRequest := types.EnvRequestV3{
			Attestation: "not-valid-base64!!!",
			RSAKeyPEM:   string(clientRSAPublicPEM),
		}
		requestBody, _ := json.Marshal(envRequest)
		c, rec := setupEchoContextWithBody(http.MethodPost, "/env/v3", requestBody)

		err = HandleEnvV3(c, logger, nil, nil, nil, nil, false)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		requireErrorResponse(t, rec, "Failed to decode attestation")
	})
}

// envTestSetupV3 encapsulates common test setup for HandleEnvV3 tests.
type envTestSetupV3 struct {
	FakeKMS         *fakes.FakeKMS
	Verifier        *stubBoundAttestationEvidenceVerifier
	MockPolicy      *policyMocks.MockPolicyCheckerInterface
	MockChainClient *chainClientMocks.MockChainClient
	ClientPrivKey   *rsa.PrivateKey
	EnvRequestV3    types.EnvRequestV3
}

func setupEnvTestV3(t *testing.T) *envTestSetupV3 {
	t.Helper()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	fakeKMS, err := fakes.NewFakeKMS()
	require.NoError(t, err)

	clientPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)
	pubDER, err := x509.MarshalPKIXPublicKey(&clientPrivKey.PublicKey)
	require.NoError(t, err)
	clientPubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	return &envTestSetupV3{
		FakeKMS:         fakeKMS,
		Verifier:        &stubBoundAttestationEvidenceVerifier{},
		MockPolicy:      policyMocks.NewMockPolicyCheckerInterface(ctrl),
		MockChainClient: chainClientMocks.NewMockChainClient(ctrl),
		ClientPrivKey:   clientPrivKey,
		EnvRequestV3: types.EnvRequestV3{
			Attestation: base64.StdEncoding.EncodeToString([]byte("dummy")),
			RSAKeyPEM:   string(clientPubKeyPEM),
		},
	}
}

// gcpTPMClaims returns a VerifiedAttestation for a GCP Shielded VM (no TEE claims).
func gcpTPMClaims(appID, imageDigest string) *attestation.VerifiedAttestation {
	return &attestation.VerifiedAttestation{
		TPMClaims: &teeverify.TPMClaims{
			GCE: &teeverify.GCEInfo{
				InstanceName: "app-" + appID,
				ProjectID:    "test-project",
			},
			Container: &teeverify.ContainerInfo{ImageDigest: imageDigest},
		},
		TEEClaims: nil, // GCP Shielded VM — no TEE binding
	}
}

// setupSuccessfulChainClient configures the chain client mock for successful V3 responses.
func (ts *envTestSetupV3) setupSuccessfulChainClient(t *testing.T, appID string, privateEnvData types.Env) {
	t.Helper()
	hexDigest, err := hex.DecodeString(strings.TrimPrefix(testValidDigest, "sha256:"))
	require.NoError(t, err)
	var expectedDigest [32]byte
	copy(expectedDigest[:], hexDigest)

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

// verifyEnvironmentResponse decrypts and verifies the environment variables in the V3 response.
func (ts *envTestSetupV3) verifyEnvironmentResponse(t *testing.T, rec *httptest.ResponseRecorder, expectedPrivateEnv types.Env) {
	t.Helper()
	var signedResponse types.SignedResponse[types.EnvResponseV1]
	err := json.Unmarshal(rec.Body.Bytes(), &signedResponse)
	require.NoError(t, err)

	decryptedEnvJSON, err := crypto.DecryptWithRSAOAEPAndAES256GCM(ts.ClientPrivKey, []byte(signedResponse.Data.EncryptedCombinedEnv))
	require.NoError(t, err)

	var returnedEnv types.Env
	err = json.Unmarshal(decryptedEnvJSON, &returnedEnv)
	require.NoError(t, err)

	for key, expectedValue := range expectedPrivateEnv {
		require.Equal(t, expectedValue, returnedEnv[key], "Env variable %s mismatch", key)
	}
	require.Equal(t, "public_value", returnedEnv["PUBLIC_VAR"])
	require.Equal(t, "production", returnedEnv["NODE_ENV"])
	require.Equal(t, testEnvMnemonic, returnedEnv["MNEMONIC"])
}

func TestHandleEnvV3_AttestationFailure(t *testing.T) {
	logger := setupEnvLogger()
	ts := setupEnvTestV3(t)

	ts.Verifier.err = errors.New("bad quote")

	requestBody, _ := json.Marshal(ts.EnvRequestV3)
	c, rec := setupEchoContextWithBody(http.MethodPost, "/env/v3", requestBody)

	err := HandleEnvV3(c, logger, ts.Verifier, ts.MockPolicy, ts.MockChainClient, ts.FakeKMS, false)

	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	requireErrorResponse(t, rec, "Attestation verification failed")
}

func TestHandleEnvV3_PolicyFailure(t *testing.T) {
	logger := setupEnvLogger()
	ts := setupEnvTestV3(t)

	ts.Verifier.result = gcpTPMClaims(testEnvAppID, testValidDigest)

	ts.MockPolicy.EXPECT().
		CheckTPMPolicies(gomock.Any(), gomock.Any()).
		Return(errors.New("not hardened"))

	requestBody, _ := json.Marshal(ts.EnvRequestV3)
	c, rec := setupEchoContextWithBody(http.MethodPost, "/env/v3", requestBody)

	err := HandleEnvV3(c, logger, ts.Verifier, ts.MockPolicy, ts.MockChainClient, ts.FakeKMS, false)

	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	requireErrorResponse(t, rec, "TPM policy check failed")
}

func TestHandleEnvV3_AuthorizationFailure(t *testing.T) {
	logger := setupEnvLogger()
	ts := setupEnvTestV3(t)

	// Verifier returns a different image digest than what the chain returns
	wrongDigest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	ts.Verifier.result = gcpTPMClaims(testEnvAppID, wrongDigest)

	ts.MockPolicy.EXPECT().
		CheckTPMPolicies(gomock.Any(), gomock.Any()).
		Return(nil)

	// Chain returns the correct (different) digest
	hexDigest, err := hex.DecodeString(strings.TrimPrefix(testValidDigest, "sha256:"))
	require.NoError(t, err)
	var expectedDigest [32]byte
	copy(expectedDigest[:], hexDigest)
	ts.MockChainClient.EXPECT().
		GetLatestRelease(gomock.Any(), testEnvAppID).
		Return(expectedDigest, types.Env{}, []byte(""), nil)

	requestBody, _ := json.Marshal(ts.EnvRequestV3)
	c, rec := setupEchoContextWithBody(http.MethodPost, "/env/v3", requestBody)

	err = HandleEnvV3(c, logger, ts.Verifier, ts.MockPolicy, ts.MockChainClient, ts.FakeKMS, false)

	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	requireErrorResponse(t, rec, "Authorization failed")
}

func TestHandleEnvV3_Success(t *testing.T) {
	logger := setupEnvLogger()
	ts := setupEnvTestV3(t)

	ts.Verifier.result = gcpTPMClaims(testEnvAppID, testValidDigest)

	ts.MockPolicy.EXPECT().
		CheckTPMPolicies(gomock.Any(), gomock.Any()).
		Return(nil)
	// CheckTEEPolicies is NOT expected — TEEClaims is nil for GCP Shielded VM

	privateEnv := types.Env{"SECRET_KEY": "secret_value", "DATABASE_URL": "postgres://test/db"}
	ts.setupSuccessfulChainClient(t, testEnvAppID, privateEnv)

	requestBody, _ := json.Marshal(ts.EnvRequestV3)
	c, rec := setupEchoContextWithBody(http.MethodPost, "/env/v3", requestBody)

	err := HandleEnvV3(c, logger, ts.Verifier, ts.MockPolicy, ts.MockChainClient, ts.FakeKMS, false)

	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rec.Code)
	ts.verifyEnvironmentResponse(t, rec, privateEnv)
}

func TestHandleEnvV3_MissingGCEInfo(t *testing.T) {
	logger := setupEnvLogger()
	ts := setupEnvTestV3(t)

	ts.Verifier.result = &attestation.VerifiedAttestation{
		TPMClaims: &teeverify.TPMClaims{
			GCE:       nil,
			Container: &teeverify.ContainerInfo{ImageDigest: testValidDigest},
		},
	}

	requestBody, _ := json.Marshal(ts.EnvRequestV3)
	c, rec := setupEchoContextWithBody(http.MethodPost, "/env/v3", requestBody)

	err := HandleEnvV3(c, logger, ts.Verifier, ts.MockPolicy, ts.MockChainClient, ts.FakeKMS, false)

	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	requireErrorResponse(t, rec, "GCE instance info not found in attestation")
}

func TestHandleEnvV3_MissingContainerInfo(t *testing.T) {
	logger := setupEnvLogger()
	ts := setupEnvTestV3(t)

	ts.Verifier.result = &attestation.VerifiedAttestation{
		TPMClaims: &teeverify.TPMClaims{
			GCE:       &teeverify.GCEInfo{InstanceName: "app-" + testEnvAppID, ProjectID: "test-project"},
			Container: nil,
		},
	}

	requestBody, _ := json.Marshal(ts.EnvRequestV3)
	c, rec := setupEchoContextWithBody(http.MethodPost, "/env/v3", requestBody)

	err := HandleEnvV3(c, logger, ts.Verifier, ts.MockPolicy, ts.MockChainClient, ts.FakeKMS, false)

	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	requireErrorResponse(t, rec, "Container info not found in attestation")
}

func TestHandleEnvV3_InvalidInstanceName(t *testing.T) {
	logger := setupEnvLogger()
	ts := setupEnvTestV3(t)

	ts.Verifier.result = &attestation.VerifiedAttestation{
		TPMClaims: &teeverify.TPMClaims{
			GCE:       &teeverify.GCEInfo{InstanceName: "nohyphen", ProjectID: "test-project"},
			Container: &teeverify.ContainerInfo{ImageDigest: testValidDigest},
		},
	}

	requestBody, _ := json.Marshal(ts.EnvRequestV3)
	c, rec := setupEchoContextWithBody(http.MethodPost, "/env/v3", requestBody)

	err := HandleEnvV3(c, logger, ts.Verifier, ts.MockPolicy, ts.MockChainClient, ts.FakeKMS, false)

	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	requireErrorResponse(t, rec, "Failed to extract app ID")
}

func TestHandleEnvV3_TEEPolicyFailure(t *testing.T) {
	logger := setupEnvLogger()
	ts := setupEnvTestV3(t)

	ts.Verifier.result = &attestation.VerifiedAttestation{
		TPMClaims: &teeverify.TPMClaims{
			GCE:       &teeverify.GCEInfo{InstanceName: "app-" + testEnvAppID, ProjectID: "test-project"},
			Container: &teeverify.ContainerInfo{ImageDigest: testValidDigest},
		},
		TEEClaims: &teeverify.TEEClaims{},
	}

	ts.MockPolicy.EXPECT().
		CheckTPMPolicies(gomock.Any(), gomock.Any()).
		Return(nil)
	ts.MockPolicy.EXPECT().
		CheckTEEPolicies(gomock.Any(), gomock.Any()).
		Return(errors.New("tcb out of date"))

	requestBody, _ := json.Marshal(ts.EnvRequestV3)
	c, rec := setupEchoContextWithBody(http.MethodPost, "/env/v3", requestBody)

	err := HandleEnvV3(c, logger, ts.Verifier, ts.MockPolicy, ts.MockChainClient, ts.FakeKMS, false)

	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	requireErrorResponse(t, rec, "TEE policy check failed")
}

func TestHandleEnvV3_CVMSuccess(t *testing.T) {
	logger := setupEnvLogger()
	ts := setupEnvTestV3(t)

	ts.Verifier.result = &attestation.VerifiedAttestation{
		TPMClaims: &teeverify.TPMClaims{
			GCE:       &teeverify.GCEInfo{InstanceName: "app-" + testEnvAppID, ProjectID: "test-project"},
			Container: &teeverify.ContainerInfo{ImageDigest: testValidDigest},
		},
		TEEClaims: &teeverify.TEEClaims{},
	}

	ts.MockPolicy.EXPECT().
		CheckTPMPolicies(gomock.Any(), gomock.Any()).
		Return(nil)
	ts.MockPolicy.EXPECT().
		CheckTEEPolicies(gomock.Any(), gomock.Any()).
		Return(nil)

	privateEnv := types.Env{"SECRET_KEY": "secret_value"}
	ts.setupSuccessfulChainClient(t, testEnvAppID, privateEnv)

	requestBody, _ := json.Marshal(ts.EnvRequestV3)
	c, rec := setupEchoContextWithBody(http.MethodPost, "/env/v3", requestBody)

	err := HandleEnvV3(c, logger, ts.Verifier, ts.MockPolicy, ts.MockChainClient, ts.FakeKMS, false)

	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rec.Code)
	ts.verifyEnvironmentResponse(t, rec, privateEnv)
}
