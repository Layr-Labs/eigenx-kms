package envclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Layr-Labs/eigenx-kms/internal/kms/fakes"
	chainClientMocks "github.com/Layr-Labs/eigenx-kms/pkg/chainclient/mocks"
	"github.com/Layr-Labs/eigenx-kms/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms/pkg/types"
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

func (m *mockAttestationProvider) GetAttestation(ctx context.Context, nonce []byte) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.attestation, nil
}

// TestKMSServer represents a test KMS server setup
type TestKMSServer struct {
	Server          *httptest.Server
	UserAPIServer   *httptest.Server
	FakeKMS         *fakes.FakeKMS
	MockChainClient *chainClientMocks.MockChainClient
	Logger          *slog.Logger
	Ctrl            *gomock.Controller
}

// NewTestKMSServer creates a new test KMS server with all mocked dependencies
func NewTestKMSServer(t *testing.T) *TestKMSServer {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	fakeKMS, err := fakes.NewFakeKMS()
	require.NoError(t, err)

	mockChainClient := chainClientMocks.NewMockChainClient(ctrl)

	e := echo.New()
	// v3 endpoint: inline handler that validates request and produces encrypted+signed response
	e.POST("/env/v3", func(c echo.Context) error {
		var envRequest types.EnvRequestV3
		if err := c.Bind(&envRequest); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Failed to parse request: %v", err)})
		}

		// Validate RSA key size (must be 4096-bit)
		if err := crypto.ValidateRSAKeySize([]byte(envRequest.RSAKeyPEM)); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("encryption key size mismatch: %v", err)})
		}

		// Validate attestation is valid base64
		if _, err := base64.StdEncoding.DecodeString(envRequest.Attestation); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid attestation base64: %v", err)})
		}

		// Use mock chain client to get env data (using hardcoded test app ID)
		_, publicEnv, encryptedEnvBytes, err := mockChainClient.GetLatestRelease(c.Request().Context(), testAppID)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("GetLatestRelease failed: %v", err)})
		}

		// Decrypt private env using fakeKMS
		privateEnvBytes, err := crypto.DecryptWithRSAOAEPAndAES256GCM(fakeKMS, encryptedEnvBytes)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("decrypt failed: %v", err)})
		}

		var privateEnv types.Env
		if err := json.Unmarshal(privateEnvBytes, &privateEnv); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("unmarshal failed: %v", err)})
		}

		// Get mnemonic
		mnemonic, err := fakeKMS.DeriveMnemonic(c.Request().Context(), testAppID)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("mnemonic failed: %v", err)})
		}

		// Combine environments
		env := types.Env{}
		env[types.MnemonicEnvVarName] = mnemonic
		for k, v := range privateEnv {
			env[k] = v
		}
		for k, v := range publicEnv {
			env[k] = v
		}

		// Encrypt with client's RSA key
		envJSON, err := json.Marshal(env)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("marshal env failed: %v", err)})
		}

		encryptedEnvJSON, err := crypto.EncryptRSAOAEPAndAES256GCMWithPEM([]byte(envRequest.RSAKeyPEM), envJSON, nil)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("encrypt response failed: %v", err)})
		}

		envResponse := types.EnvResponseV3{
			EncryptedCombinedEnv: string(encryptedEnvJSON),
		}

		// Sign the response
		responseJSON, err := json.Marshal(envResponse)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("marshal response failed: %v", err)})
		}

		signature, err := fakeKMS.SignMessage(c.Request().Context(), string(responseJSON))
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("sign failed: %v", err)})
		}

		return c.JSON(http.StatusOK, types.SignedResponse[types.EnvResponseV3]{
			Data:      envResponse,
			Signature: signature,
		})
	})
	e.GET("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
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
		Server:          server,
		UserAPIServer:   userAPIServer,
		FakeKMS:         fakeKMS,
		MockChainClient: mockChainClient,
		Logger:          logger,
		Ctrl:            ctrl,
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
