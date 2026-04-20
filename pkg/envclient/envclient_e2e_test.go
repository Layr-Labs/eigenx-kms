package envclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Layr-Labs/eigenx-kms/internal/auth"
	"github.com/Layr-Labs/eigenx-kms/internal/handlers"
	"github.com/Layr-Labs/eigenx-kms/internal/kms/fakes"
	"github.com/Layr-Labs/eigenx-kms/pkg/attestation"
	attestationMocks "github.com/Layr-Labs/eigenx-kms/pkg/attestation/mocks"
	chainClientMocks "github.com/Layr-Labs/eigenx-kms/pkg/chainclient/mocks"
	"github.com/Layr-Labs/eigenx-kms/pkg/crypto"
	policyMocks "github.com/Layr-Labs/eigenx-kms/pkg/policy/mocks"
	"github.com/Layr-Labs/eigenx-kms/pkg/types"
	"github.com/Layr-Labs/go-tpm-tools/sdk/attest"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

const (
	testAppID       = "0x1111111111111111111111111111111111111111"
	testMnemonic    = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	testValidDigest = "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
)

// mockAttestationProvider is a mock implementation of AttestationProvider for testing
type mockAttestationProvider struct {
	attestation []byte
	err         error
}

func (m *mockAttestationProvider) GetAttestation(ctx context.Context, challenge []byte, extraData ...[]byte) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.attestation, nil
}

// TestKMSServer represents a test KMS server setup
type TestKMSServer struct {
	Server                  *httptest.Server
	UserAPIServer           *httptest.Server
	FakeKMS                 *fakes.FakeKMS
	MockChainClient         *chainClientMocks.MockChainClient
	MockAttestationVerifier *attestationMocks.MockBoundAttestationEvidenceVerifier
	MockPolicyChecker       *policyMocks.MockPolicyCheckerInterface
	JWTSigner               *auth.JWTSigner
	Logger                  *slog.Logger
	Ctrl                    *gomock.Controller
}

// NewTestKMSServer creates a new test KMS server with all mocked dependencies
func NewTestKMSServer(t *testing.T) *TestKMSServer {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	fakeKMS, err := fakes.NewFakeKMS()
	require.NoError(t, err)

	// Create a JWT signer for /auth/attest
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})
	jwtSigner, err := auth.NewJWTSigner(string(rsaKeyPEM), time.Hour)
	require.NoError(t, err)

	mockChainClient := chainClientMocks.NewMockChainClient(ctrl)
	mockAttestationVerifier := attestationMocks.NewMockBoundAttestationEvidenceVerifier(ctrl)
	mockPolicyChecker := policyMocks.NewMockPolicyCheckerInterface(ctrl)

	e := echo.New()
	e.POST("/env/v3", func(c echo.Context) error {
		return handlers.HandleEnvV3(c, logger, mockAttestationVerifier, mockPolicyChecker, mockChainClient, fakeKMS, false)
	})
	e.POST("/auth/attest", func(c echo.Context) error {
		return handlers.HandleAttest(c, logger, jwtSigner, mockAttestationVerifier, mockPolicyChecker, fakeKMS, false)
	})
	e.GET("/health", func(c echo.Context) error {
		return c.JSON(200, map[string]string{"status": "ok"})
	})

	server := httptest.NewServer(e)
	t.Cleanup(server.Close)

	// Create mock user API server
	userAPIEcho := echo.New()
	userAPIEcho.GET("/", func(c echo.Context) error {
		return c.JSON(200, map[string]string{"status": "ok"})
	})

	userAPIServer := httptest.NewServer(userAPIEcho)
	t.Cleanup(userAPIServer.Close)

	return &TestKMSServer{
		Server:                  server,
		UserAPIServer:           userAPIServer,
		FakeKMS:                 fakeKMS,
		MockChainClient:         mockChainClient,
		MockAttestationVerifier: mockAttestationVerifier,
		MockPolicyChecker:       mockPolicyChecker,
		JWTSigner:               jwtSigner,
		Logger:                  logger,
		Ctrl:                    ctrl,
	}
}

// GetKMSKeys returns the KMS public keys for client configuration
func (ts *TestKMSServer) GetKMSKeys() (encryptionKey []byte, signingKey []byte, err error) {
	encryptionKeyPEM, err := ts.FakeKMS.GetEncryptionPublicKeyPEM()
	if err != nil {
		return nil, nil, err
	}

	signingKeyPEM, err := ts.FakeKMS.GetSigningPublicKeyPEM()
	if err != nil {
		return nil, nil, err
	}

	return encryptionKeyPEM, signingKeyPEM, nil
}

// SetupSuccessfulMocks configures the test server for successful responses
func (ts *TestKMSServer) SetupSuccessfulMocks(t *testing.T, appID string, privateEnv types.Env) {
	// Setup chain client mock
	hexDigest, err := hex.DecodeString(strings.TrimPrefix(testValidDigest, "sha256:"))
	require.NoError(t, err)
	var expectedDigest [32]byte
	copy(expectedDigest[:], hexDigest)

	// Create encrypted private env data
	privateEnvJSON, err := json.Marshal(privateEnv)
	require.NoError(t, err)
	encryptionKeyPEM, err := ts.FakeKMS.GetEncryptionPublicKeyPEM()
	require.NoError(t, err)
	encryptedPrivateEnv, err := crypto.EncryptRSAOAEPAndAES256GCMWithPEM(encryptionKeyPEM, privateEnvJSON, crypto.GetAppProtectedHeaders(appID))
	require.NoError(t, err)

	publicEnv := types.Env{"PUBLIC_VAR": "public_value", "NODE_ENV": "production"}

	ts.MockChainClient.EXPECT().
		GetLatestRelease(gomock.Any(), appID).
		Return(expectedDigest, publicEnv, []byte(encryptedPrivateEnv), nil)

	// Mock verifier returns GCP Shielded VM claims for this appID
	ts.MockAttestationVerifier.EXPECT().
		Verify(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&attestation.VerifiedAttestation{
			TPMClaims: &attest.TPMClaims{
				GCE: &attest.GCEInfo{InstanceName: "app-" + appID, ProjectID: "test"},
			},
			Container: &attest.ContainerInfo{ImageDigest: testValidDigest},
		}, nil)

	ts.MockPolicyChecker.EXPECT().
		CheckTPMPolicies(gomock.Any(), gomock.Any()).
		Return(nil)
}

func TestEnvClient_E2E_Success(t *testing.T) {
	testServer := NewTestKMSServer(t)

	// Setup successful mocks
	privateEnv := types.Env{
		types.MnemonicEnvVarName: testMnemonic,
		"DATABASE_URL":           "postgres://test:test@localhost/testdb",
		"API_TOKEN":              "token_abc123",
	}
	testServer.SetupSuccessfulMocks(t, testAppID, privateEnv)

	// Get KMS signing key
	_, signingKey, err := testServer.GetKMSKeys()
	require.NoError(t, err)

	// Create mock attestation provider returning dummy bytes
	mockProvider := &mockAttestationProvider{attestation: []byte("dummy-attestation-bytes")}

	// Create EnvClient
	client := NewEnvClient(testServer.Logger, mockProvider, signingKey, testServer.Server.URL, testServer.UserAPIServer.URL)

	// Test the GetEnv method
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	envBytes, err := client.GetEnv(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, envBytes)

	// Parse the returned environment
	var returnedEnv types.Env
	err = json.Unmarshal(envBytes, &returnedEnv)
	require.NoError(t, err)

	// Verify all expected environment variables are present
	require.Equal(t, testMnemonic, returnedEnv[types.MnemonicEnvVarName])
	require.Equal(t, "postgres://test:test@localhost/testdb", returnedEnv["DATABASE_URL"])
	require.Equal(t, "token_abc123", returnedEnv["API_TOKEN"])
	require.Equal(t, "public_value", returnedEnv["PUBLIC_VAR"])
	require.Equal(t, "production", returnedEnv["NODE_ENV"])
	require.Equal(t, testMnemonic, returnedEnv["MNEMONIC"])
}

func TestEnvClient_E2E_InvalidSignature(t *testing.T) {
	testServer := NewTestKMSServer(t)

	// Generate a wrong signing key
	wrongSigningECDSAKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&wrongSigningECDSAKey.PublicKey)
	require.NoError(t, err)
	wrongSigningKey := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	// Setup successful mocks so we get to signature verification
	privateEnv := types.Env{"SECRET_KEY": "test_secret"}
	testServer.SetupSuccessfulMocks(t, testAppID, privateEnv)

	mockProvider := &mockAttestationProvider{attestation: []byte("dummy-attestation-bytes")}
	client := NewEnvClient(testServer.Logger, mockProvider, wrongSigningKey, testServer.Server.URL, testServer.UserAPIServer.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = client.GetEnv(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid signature")
}

func TestEnvClient_E2E_ServerDown(t *testing.T) {
	// Don't create a server - test connection failure
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Use fake signing key for this test
	_, signingKey, err := crypto.GenerateRSAKeyPair()
	require.NoError(t, err)

	mockProvider := &mockAttestationProvider{attestation: []byte("dummy-attestation-bytes")}
	client := NewEnvClient(logger, mockProvider, []byte(signingKey), "http://localhost:99999", "http://localhost:99998") // non-existent servers

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = client.GetEnv(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to send request after retries")
}

func TestEnvClient_E2E_Attest(t *testing.T) {
	tests := []struct {
		name      string
		extraData []byte
	}{
		{
			name:      "with extra_data",
			extraData: []byte("action-hash-32-bytes-of-data-here"),
		},
		{
			name:      "without extra_data",
			extraData: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testServer := NewTestKMSServer(t)

			var expectedExtraData gomock.Matcher
			if tc.extraData != nil {
				expectedExtraData = gomock.Eq(tc.extraData)
			} else {
				expectedExtraData = gomock.Nil()
			}

			testServer.MockAttestationVerifier.EXPECT().
				Verify(gomock.Any(), gomock.Any(), gomock.Any(), expectedExtraData).
				Return(&attestation.VerifiedAttestation{
					TPMClaims: &attest.TPMClaims{
						GCE: &attest.GCEInfo{InstanceName: "app-" + testAppID, ProjectID: "test"},
					},
					Container: &attest.ContainerInfo{ImageDigest: testValidDigest},
				}, nil)
			testServer.MockPolicyChecker.EXPECT().
				CheckTPMPolicies(gomock.Any(), gomock.Any()).
				Return(nil)

			_, signingKey, err := testServer.GetKMSKeys()
			require.NoError(t, err)

			mockProvider := &mockAttestationProvider{attestation: []byte("dummy-attestation-bytes")}
			client := NewEnvClient(testServer.Logger, mockProvider, signingKey, testServer.Server.URL, testServer.UserAPIServer.URL)

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			var tokenStr string
			var attestErr error
			if tc.extraData != nil {
				tokenStr, attestErr = client.Attest(ctx, "test-audience", tc.extraData)
			} else {
				tokenStr, attestErr = client.Attest(ctx, "test-audience")
			}
			require.NoError(t, attestErr)
			require.NotEmpty(t, tokenStr)

			parts := strings.Split(tokenStr, ".")
			require.Len(t, parts, 3)
			payload, err := base64DecodeRaw(parts[1])
			require.NoError(t, err)

			var claims map[string]any
			require.NoError(t, json.Unmarshal(payload, &claims))

			if tc.extraData != nil {
				require.Equal(t, base64.StdEncoding.EncodeToString(tc.extraData), claims["extra_data"])
			} else {
				_, hasExtraData := claims["extra_data"]
				require.False(t, hasExtraData, "extra_data claim should be absent when not provided")
			}
		})
	}
}

// base64DecodeRaw decodes a base64url-encoded JWT segment.
func base64DecodeRaw(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func TestEnvClient_E2E_UserAPIDown(t *testing.T) {
	testServer := NewTestKMSServer(t)

	// Setup successful mocks for KMS server
	privateEnv := types.Env{
		types.MnemonicEnvVarName: testMnemonic,
		"DATABASE_URL":           "postgres://test:test@localhost/testdb",
		"API_TOKEN":              "token_abc123",
	}
	testServer.SetupSuccessfulMocks(t, testAppID, privateEnv)

	// Get KMS signing key
	_, signingKey, err := testServer.GetKMSKeys()
	require.NoError(t, err)

	// Create mock attestation provider
	mockProvider := &mockAttestationProvider{attestation: []byte("dummy-attestation-bytes")}

	// Create EnvClient with non-existent user API URL
	// v3 doesn't upload to user API, so this should succeed regardless
	client := NewEnvClient(testServer.Logger, mockProvider, signingKey, testServer.Server.URL, "http://localhost:99998")

	// Test the GetEnv method - should succeed (v3 skips user API upload)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	envBytes, err := client.GetEnv(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, envBytes)

	// Parse the returned environment to verify we got valid data
	var returnedEnv types.Env
	err = json.Unmarshal(envBytes, &returnedEnv)
	require.NoError(t, err)

	// Verify all expected environment variables are present
	require.Equal(t, testMnemonic, returnedEnv[types.MnemonicEnvVarName])
	require.Equal(t, "postgres://test:test@localhost/testdb", returnedEnv["DATABASE_URL"])
	require.Equal(t, "token_abc123", returnedEnv["API_TOKEN"])
}
