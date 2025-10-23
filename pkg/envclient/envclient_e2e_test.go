package envclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Layr-Labs/eigenx-kms/internal/handlers"
	"github.com/Layr-Labs/eigenx-kms/internal/kms/fakes"
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
	testAppID       = "0x1111111111111111111111111111111111111111"
	testMnemonic    = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	testValidDigest = "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
)

// mockAttestationTokenProvider is a mock implementation of AttestationTokenProvider for testing
type mockAttestationTokenProvider struct {
	baseToken string // Token template without nonce
	err       error
}

func (m *mockAttestationTokenProvider) GetToken(ctx context.Context, nonce string) (string, error) {
	if m.err != nil {
		return "", m.err
	}

	// Parse the base token to add nonce
	var claims map[string]interface{}
	if err := json.Unmarshal([]byte(m.baseToken), &claims); err != nil {
		return "", fmt.Errorf("failed to parse base token: %w", err)
	}

	// Add nonce to the claims
	claims["eat_nonce"] = nonce

	// Marshal back to JSON
	tokenWithNonce, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal token with nonce: %w", err)
	}

	return string(tokenWithNonce), nil
}

// TestKMSServer represents a test KMS server setup
type TestKMSServer struct {
	Server          *httptest.Server
	FakeKMS         *fakes.FakeKMS
	MockAttestation *attestationMocks.MockAttestationVerifierInterface
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

	mockAttestation := attestationMocks.NewMockAttestationVerifierInterface(ctrl)
	mockChainClient := chainClientMocks.NewMockChainClient(ctrl)

	e := echo.New()
	e.POST("/env", func(c echo.Context) error {
		return handlers.HandleEnv(c, logger, mockAttestation, mockChainClient, fakeKMS, true) // debug mode enabled
	})
	e.POST("/env/v2", func(c echo.Context) error {
		return handlers.HandleEnvV2(c, logger, mockAttestation, mockChainClient, fakeKMS, true) // debug mode enabled
	})
	e.GET("/health", func(c echo.Context) error {
		return handlers.HandleHealth(c)
	})

	server := httptest.NewServer(e)
	t.Cleanup(server.Close)

	return &TestKMSServer{
		Server:          server,
		FakeKMS:         fakeKMS,
		MockAttestation: mockAttestation,
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
	// Setup attestation mock to extract nonce from JWT
	ts.MockAttestation.EXPECT().
		VerifyAttestation(gomock.Any(), gomock.Any(), attestation.IntelTrustAuthority).
		DoAndReturn(func(ctx context.Context, jwtString string, provider attestation.AttestationProvider) (*attestation.AttestationClaims, error) {
			// Parse the JWT to extract nonce
			var claims map[string]interface{}
			if err := json.Unmarshal([]byte(jwtString), &claims); err != nil {
				return nil, fmt.Errorf("failed to parse JWT: %w", err)
			}

			// Extract nonce if present
			var nonce string
			if nonceRaw, ok := claims["eat_nonce"]; ok {
				if nonceStr, ok := nonceRaw.(string); ok {
					nonce = nonceStr
				}
			}

			return &attestation.AttestationClaims{
				ImageDigest: testValidDigest,
				AppID:       appID,
				Nonce:       nonce,
			}, nil
		})

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
		"SECRET_KEY":   "secret_value_123",
		"DATABASE_URL": "postgres://test:test@localhost/testdb",
		"API_TOKEN":    "token_abc123",
	}
	testServer.SetupSuccessfulMocks(t, testAppID, privateEnv)

	// Get KMS signing key
	_, signingKey, err := testServer.GetKMSKeys()
	require.NoError(t, err)

	// Create a mock JWT
	mockJWT := `{"sub":"test-app","iat":1234567890,"app_id":"` + testAppID + `"}`

	// Create mock token provider
	mockTokenProvider := &mockAttestationTokenProvider{baseToken: mockJWT}

	// Create EnvClient
	client := NewEnvClient(testServer.Logger, mockTokenProvider, signingKey, testServer.Server.URL)

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
	require.Equal(t, "secret_value_123", returnedEnv["SECRET_KEY"])
	require.Equal(t, "postgres://test:test@localhost/testdb", returnedEnv["DATABASE_URL"])
	require.Equal(t, "token_abc123", returnedEnv["API_TOKEN"])
	require.Equal(t, "public_value", returnedEnv["PUBLIC_VAR"])
	require.Equal(t, "production", returnedEnv["NODE_ENV"])
	require.Equal(t, testMnemonic, returnedEnv["MNEMONIC"])
}

func TestEnvClient_E2E_InvalidSignature(t *testing.T) {
	testServer := NewTestKMSServer(t)

	// Generate a wrong signing key
	// Generate ECDSA key for signing (P-256 curve)
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

	mockJWT := `{"sub":"test-app","iat":1234567890,"app_id":"` + testAppID + `"}`
	mockTokenProvider := &mockAttestationTokenProvider{baseToken: mockJWT}
	client := NewEnvClient(testServer.Logger, mockTokenProvider, wrongSigningKey, testServer.Server.URL)

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

	mockJWT := `{"sub":"test-app","iat":1234567890,"app_id":"` + testAppID + `"}`
	mockTokenProvider := &mockAttestationTokenProvider{baseToken: mockJWT}
	client := NewEnvClient(logger, mockTokenProvider, []byte(signingKey), "http://localhost:99999") // non-existent server

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = client.GetEnv(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to send request after retries")
}
