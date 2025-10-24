package attestation

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"
)

func createProductionCsToken(provider AttestationProvider) ConfidentialSpaceToken {
	// Real production token JSON structure
	issuer := "https://confidentialcomputing.googleapis.com"
	hwmodel := "GCP_INTEL_TDX"
	attesterTcb := `"attester_tcb": ["INTEL"],`
	supportAttr := "STABLE"

	if provider == IntelTrustAuthority {
		issuer = "https://portal.trustauthority.intel.com"
		hwmodel = "INTEL_TDX"
		attesterTcb = "" // Intel tokens don't have attester_tcb field
		supportAttr = "EXPERIMENTAL"
	}

	realTokenJSON := `{
		"aud": "https://sts.googleapis.com",
		"exp": 1757100915,
		"iat": 1757097315,
		"iss": "` + issuer + `",
		"nbf": 1757097315,
		"sub": "https://www.googleapis.com/compute/v1/projects/tee-compute-sepolia-prod/zones/us-central1-c/instances/tee-0xb69a8c848a4b79f4c1810c31156d80e7eaff874a",
		"eat_profile": "https://cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims",
		"secboot": true,
		"oemid": 11129,
		"hwmodel": "` + hwmodel + `",
		"swname": "CONFIDENTIAL_SPACE",
		"swversion": ["250800"],
		` + attesterTcb + `
		"dbgstat": "disabled-since-boot",
		"submods": {
			"confidential_space": {
				"monitoring_enabled": {
					"memory": false
				},
				"support_attributes": ["` + supportAttr + `"]
			},
			"container": {
				"image_reference": "index.docker.io/saucelord/account-printer@sha256:1580f84f1585dbecd84479ae867b6d586de31a19bbc9e551f2fbc20f9df59ec9",
				"image_digest": "sha256:1580f84f1585dbecd84479ae867b6d586de31a19bbc9e551f2fbc20f9df59ec9",
				"restart_policy": "Never",
				"image_id": "sha256:338bff3f9f38e9f0d2eb4772f07dcc77baac9b353b521c40344c04a62c003332",
				"env": {
					"HOSTNAME": "tee-0xb69a8c848a4b79f4c1810c31156d80e7eaff874a",
					"NODE_VERSION": "18.20.8",
					"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
					"YARN_VERSION": "1.22.22"
				},
				"args": ["/usr/local/bin/compute-source-env.sh", "npm", "start"]
			},
			"gce": {
				"zone": "us-central1-c",
				"project_id": "tee-compute-sepolia-prod",
				"project_number": "889537417991",
				"instance_name": "tee-0xb69a8c848a4b79f4c1810c31156d80e7eaff874a",
				"instance_id": "8114146583384593350"
			},
			"tdx": {
				"gcp_attester_tcb_status": "UpToDate",
				"gcp_attester_tcb_date": "2024-03-13T00:00:00Z"
			},
			"google_service_accounts": ["889537417991-compute@developer.gserviceaccount.com"]
		}
	}`

	var token ConfidentialSpaceToken
	if err := json.Unmarshal([]byte(realTokenJSON), &token); err != nil {
		panic("Failed to unmarshal real token JSON: " + err.Error())
	}
	token.Exp = time.Now().Add(1 * time.Hour).Unix()
	token.Nbf = time.Now().Unix()
	return token
}

func createDebugCsToken() ConfidentialSpaceToken {
	debugTokenJSON := `{
  "aud": "https://sts.googleapis.com",
  "exp": 1757100915,
  "iat": 1757097315,
  "iss": "https://confidentialcomputing.googleapis.com",
  "nbf": 1757097315,
  "sub": "https://www.googleapis.com/compute/v1/projects/tee-compute-sepolia-prod/zones/us-central1-c/instances/tee-0xb69a8c848a4b79f4c1810c31156d80e7eaff874a",
  "eat_profile": "https://cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims",
  "secboot": true,
  "oemid": 11129,
  "hwmodel": "GCP_INTEL_TDX",
  "swname": "CONFIDENTIAL_SPACE",
  "swversion": [
    "250800"
  ],
  "attester_tcb": [
    "INTEL"
  ],
  "dbgstat": "enabled",
  "submods": {
    "confidential_space": {
      "monitoring_enabled": {
        "memory": false
      }
    },
    "container": {
      "image_reference": "index.docker.io/saucelord/account-printer@sha256:1580f84f1585dbecd84479ae867b6d586de31a19bbc9e551f2fbc20f9df59ec9",
      "image_digest": "sha256:1580f84f1585dbecd84479ae867b6d586de31a19bbc9e551f2fbc20f9df59ec9",
      "restart_policy": "Never",
      "image_id": "sha256:338bff3f9f38e9f0d2eb4772f07dcc77baac9b353b521c40344c04a62c003332",
      "env": {
        "HOSTNAME": "tee-0xb69a8c848a4b79f4c1810c31156d80e7eaff874a",
        "NODE_VERSION": "18.20.8",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "YARN_VERSION": "1.22.22"
      },
      "args": [
        "/usr/local/bin/compute-source-env.sh",
        "npm",
        "start"
      ]
    },
    "gce": {
      "zone": "us-central1-c",
      "project_id": "tee-compute-sepolia-prod",
      "project_number": "889537417991",
      "instance_name": "tee-0xb69a8c848a4b79f4c1810c31156d80e7eaff874a",
      "instance_id": "8114146583384593350"
    }
  },
  "tdx": {
    "gcp_attester_tcb_status": "UpToDate",
    "gcp_attester_tcb_date": "2024-03-13T00:00:00Z"
  },
  "google_service_accounts": [
    "889537417991-compute@developer.gserviceaccount.com"
  ]
}`

	var token ConfidentialSpaceToken
	if err := json.Unmarshal([]byte(debugTokenJSON), &token); err != nil {
		panic("Failed to unmarshal debug token JSON: " + err.Error())
	}
	token.Exp = time.Now().Add(1 * time.Hour).Unix()
	token.Nbf = time.Now().Unix()
	return token
}

func setupLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func createTestJWKS(t *testing.T) (jwk.Set, *rsa.PrivateKey, string) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create JWK from the public key
	publicKey, err := jwk.Import(&privateKey.PublicKey)
	require.NoError(t, err)

	keyID := "test-key-id"
	err = publicKey.Set(jwk.KeyIDKey, keyID)
	require.NoError(t, err)

	// Set algorithm to match what we use for signing
	err = publicKey.Set(jwk.AlgorithmKey, jwa.RS256())
	require.NoError(t, err)

	// Set usage for verification
	err = publicKey.Set(jwk.KeyUsageKey, "sig")
	require.NoError(t, err)

	publicSet := jwk.NewSet()
	publicSet.AddKey(publicKey)

	return publicSet, privateKey, keyID
}

func createdSignedJWT(t *testing.T, privateKey *rsa.PrivateKey, keyID string, csToken ConfidentialSpaceToken) string {
	// Convert validCsToken struct to JSON and then to map for JWT claims
	jsonBytes, err := json.Marshal(csToken)
	require.NoError(t, err)

	var claims map[string]any
	err = json.Unmarshal(jsonBytes, &claims)
	require.NoError(t, err)

	token := jwt.New()
	for key, value := range claims {
		require.NoError(t, token.Set(key, value))
	}

	// Create a private key JWK with the specified key ID for signing
	jwkKey, err := jwk.Import(privateKey)
	require.NoError(t, err)
	require.NoError(t, jwkKey.Set(jwk.KeyIDKey, keyID))
	require.NoError(t, jwkKey.Set(jwk.AlgorithmKey, jwa.RS256()))

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), jwkKey))
	require.NoError(t, err)

	return string(signed)
}

func testValidation(t *testing.T, verifier *AttestationVerifier, csToken ConfidentialSpaceToken, provider AttestationProvider, expectError bool, errorSubstring string) {
	var err error
	if provider == GoogleConfidentialSpace {
		err = verifier.validateConfidentialSpaceToken(&csToken)
	} else {
		err = verifier.validateIntelTrustAuthorityToken(&csToken)
	}

	if expectError {
		require.Error(t, err)
		if errorSubstring != "" {
			require.Contains(t, err.Error(), errorSubstring)
		}
	} else {
		require.NoError(t, err)
	}
}

func TestNewAttestationVerifier(t *testing.T) {
	ctx := context.Background()
	logger := setupLogger()

	t.Run("successful creation with debug mode false", func(t *testing.T) {
		// The real JWKS URL is actually accessible, so this should succeed
		verifier, err := NewAttestationVerifier(ctx, logger, "test-project", time.Minute, false)
		require.NoError(t, err)
		require.NotNil(t, verifier)
		require.Equal(t, "test-project", verifier.projectID)
		require.False(t, verifier.debugMode)
	})

	t.Run("successful creation with debug mode true", func(t *testing.T) {
		// The real JWKS URL is actually accessible, so this should succeed
		verifier, err := NewAttestationVerifier(ctx, logger, "test-project", time.Minute, true)
		require.NoError(t, err)
		require.NotNil(t, verifier)
		require.Equal(t, "test-project", verifier.projectID)
		require.True(t, verifier.debugMode)
	})
}

func TestVerifyAttestation(t *testing.T) {
	ctx := context.Background()
	logger := setupLogger()
	projectID := "tee-compute-sepolia-prod" // Use the project ID from real token

	jwkSet, privateKey, keyID := createTestJWKS(t)

	// Create verifier with mock JWK set and debug mode enabled
	verifier := &AttestationVerifier{
		logger:          logger,
		projectID:       projectID,
		googleJwksCache: jwkSet,
		intelJwksCache:  jwkSet, // Use same mock JWKS for both providers in tests
		debugMode:       true,   // Enable debug mode to allow dbgstat="enabled"
	}

	// Test both Google and Intel providers
	providers := []AttestationProvider{GoogleConfidentialSpace, IntelTrustAuthority}

	for _, provider := range providers {
		t.Run("valid attestation with jwt verification", func(t *testing.T) {
			token := createdSignedJWT(t, privateKey, keyID, createProductionCsToken(provider))

			claims, err := verifier.VerifyAttestation(ctx, token, provider)
			require.NoError(t, err)
			require.NotNil(t, claims)
			require.Equal(t, "0xb69a8c848a4b79f4c1810c31156d80e7eaff874a", claims.AppID)
			require.Equal(t, "sha256:1580f84f1585dbecd84479ae867b6d586de31a19bbc9e551f2fbc20f9df59ec9", claims.ImageDigest)
		})

		t.Run("invalid issuer", func(t *testing.T) {
			csToken := createProductionCsToken(provider)
			csToken.Issuer = "https://malicious.com"
			token := createdSignedJWT(t, privateKey, keyID, csToken)

			_, err := verifier.VerifyAttestation(ctx, token, provider)
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid issuer")
		})

		t.Run("valid Google STS audience", func(t *testing.T) {
			csToken := createProductionCsToken(provider)
			csToken.Audience = "https://sts.googleapis.com"
			token := createdSignedJWT(t, privateKey, keyID, csToken)

			claims, err := verifier.VerifyAttestation(ctx, token, provider)
			require.NoError(t, err)
			require.NotNil(t, claims)
			require.Equal(t, "0xb69a8c848a4b79f4c1810c31156d80e7eaff874a", claims.AppID)
		})

		t.Run("valid EigenX KMS audience", func(t *testing.T) {
			csToken := createProductionCsToken(provider)
			csToken.Audience = "EigenX KMS"
			token := createdSignedJWT(t, privateKey, keyID, csToken)

			claims, err := verifier.VerifyAttestation(ctx, token, provider)
			require.NoError(t, err)
			require.NotNil(t, claims)
			require.Equal(t, "0xb69a8c848a4b79f4c1810c31156d80e7eaff874a", claims.AppID)
		})

		t.Run("invalid audience", func(t *testing.T) {
			csToken := createProductionCsToken(provider)
			csToken.Audience = "https://malicious.com"
			token := createdSignedJWT(t, privateKey, keyID, csToken)

			_, err := verifier.VerifyAttestation(ctx, token, provider)
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid audience")
		})

		t.Run("invalid exp", func(t *testing.T) {
			csToken := createProductionCsToken(provider)
			csToken.Exp = time.Now().Add(-1 * time.Hour).Unix()
			token := createdSignedJWT(t, privateKey, keyID, csToken)

			_, err := verifier.VerifyAttestation(ctx, token, provider)
			require.Error(t, err)
			require.Contains(t, err.Error(), "token is expired")
		})

		t.Run("invalid nbf", func(t *testing.T) {
			csToken := createProductionCsToken(provider)
			csToken.Nbf = time.Now().Add(1 * time.Hour).Unix()
			token := createdSignedJWT(t, privateKey, keyID, csToken)

			_, err := verifier.VerifyAttestation(ctx, token, provider)
			require.Error(t, err)
			require.Contains(t, err.Error(), "token is not yet valid")
		})
	}
}

// TestValidationLogic tests the business logic validation using the extracted function
func TestValidationLogic(t *testing.T) {
	logger := setupLogger()
	projectID := "tee-compute-sepolia-prod" // Use the project ID from real token

	// Create a mock verifier for testing validation logic
	verifier := &AttestationVerifier{
		logger:          logger,
		projectID:       projectID,
		googleJwksCache: nil,   // We'll bypass JWT verification
		intelJwksCache:  nil,   // We'll bypass JWT verification
		debugMode:       false, // Disable debug mode for these tests
	}

	// Test both Google and Intel providers
	providers := []AttestationProvider{GoogleConfidentialSpace, IntelTrustAuthority}

	for _, provider := range providers {
		t.Run("valid claims pass validation", func(t *testing.T) {
			testValidation(t, verifier, createProductionCsToken(provider), provider, false, "")
		})

		t.Run("invalid software name", func(t *testing.T) {
			claims := createProductionCsToken(provider)
			claims.SwName = "INVALID_SOFTWARE"
			testValidation(t, verifier, claims, provider, true, "invalid software name")
		})

		t.Run("invalid hardware model", func(t *testing.T) {
			csToken := createProductionCsToken(provider)
			csToken.HwModel = "GCP_AMD_SEV"
			testValidation(t, verifier, csToken, provider, true, "invalid hwmodel")
		})

		t.Run("invalid debug status - enabled", func(t *testing.T) {
			csToken := createProductionCsToken(provider)
			csToken.DbgStat = "enabled"
			testValidation(t, verifier, csToken, provider, true, "invalid dbgstat")
		})

		t.Run("invalid debug status - partially disabled", func(t *testing.T) {
			csToken := createProductionCsToken(provider)
			csToken.DbgStat = "disabled"
			testValidation(t, verifier, csToken, provider, true, "invalid dbgstat")
		})

		t.Run("valid debug status - disabled-since-boot", func(t *testing.T) {
			csToken := createProductionCsToken(provider)
			csToken.DbgStat = "disabled-since-boot"
			testValidation(t, verifier, csToken, provider, false, "")
		})

		t.Run("invalid software version - too low", func(t *testing.T) {
			csToken := createProductionCsToken(provider)
			csToken.SwVersion = []string{"250299"}
			testValidation(t, verifier, csToken, provider, true, "invalid swversion")
		})

		t.Run("valid software version - at boundary", func(t *testing.T) {
			csToken := createProductionCsToken(provider)
			csToken.SwVersion = []string{"250300"}
			testValidation(t, verifier, csToken, provider, false, "")
		})

		t.Run("valid software version - above boundary", func(t *testing.T) {
			csToken := createProductionCsToken(provider)
			csToken.SwVersion = []string{"300000"}
			testValidation(t, verifier, csToken, provider, false, "")
		})

		t.Run("invalid project ID", func(t *testing.T) {
			csToken := createProductionCsToken(provider)
			csToken.SubMods.GCE.ProjectID = "wrong-project"
			testValidation(t, verifier, csToken, provider, true, "invalid project_id")
		})
	}

	// Google Confidential Space specific tests
	t.Run("Google CS: invalid attester TCB - empty", func(t *testing.T) {
		csToken := createProductionCsToken(GoogleConfidentialSpace)
		csToken.AttesterTCB = []string{}
		testValidation(t, verifier, csToken, GoogleConfidentialSpace, true, "invalid attester_tcb")
	})

	t.Run("Google CS: invalid attester TCB - wrong value", func(t *testing.T) {
		csToken := createProductionCsToken(GoogleConfidentialSpace)
		csToken.AttesterTCB = []string{"AMD"}
		testValidation(t, verifier, csToken, GoogleConfidentialSpace, true, "invalid attester_tcb")
	})

	t.Run("Google CS: invalid support attributes", func(t *testing.T) {
		csToken := createProductionCsToken(GoogleConfidentialSpace)
		csToken.SubMods.ConfidentialSpace.SupportAttributes = []string{"USABLE"}
		testValidation(t, verifier, csToken, GoogleConfidentialSpace, true, "invalid confidential_space.support_attributes")
	})

	// Intel Trust Authority specific tests
	t.Run("Intel: invalid TDX TCB status", func(t *testing.T) {
		csToken := createProductionCsToken(IntelTrustAuthority)
		csToken.SubMods.TDX.GcpAttesterTcbStatus = "OutOfDate"
		testValidation(t, verifier, csToken, IntelTrustAuthority, true, "invalid tdx.gcp_attester_tcb_status")
	})

	t.Run("Intel: missing TDX submods", func(t *testing.T) {
		csToken := createProductionCsToken(IntelTrustAuthority)
		csToken.SubMods.TDX = nil
		testValidation(t, verifier, csToken, IntelTrustAuthority, true, "tdx submods not found")
	})

	t.Run("Intel: requires EXPERIMENTAL support attributes", func(t *testing.T) {
		csToken := createProductionCsToken(IntelTrustAuthority)
		csToken.SubMods.ConfidentialSpace.SupportAttributes = []string{"EXPERIMENTAL"}
		testValidation(t, verifier, csToken, IntelTrustAuthority, false, "")
	})

	t.Run("Intel: rejects STABLE support attributes", func(t *testing.T) {
		csToken := createProductionCsToken(IntelTrustAuthority)
		csToken.SubMods.ConfidentialSpace.SupportAttributes = []string{"STABLE"}
		testValidation(t, verifier, csToken, IntelTrustAuthority, true, "Expected to contain EXPERIMENTAL")
	})

	t.Run("Intel: rejects missing EXPERIMENTAL", func(t *testing.T) {
		csToken := createProductionCsToken(IntelTrustAuthority)
		csToken.SubMods.ConfidentialSpace.SupportAttributes = []string{"USABLE"}
		testValidation(t, verifier, csToken, IntelTrustAuthority, true, "Expected to contain EXPERIMENTAL")
	})

	t.Run("debug token fails validation", func(t *testing.T) {
		csToken := createDebugCsToken()
		testValidation(t, verifier, csToken, GoogleConfidentialSpace, true, "") // any error is acceptable
	})
}

// Test that debug mode skips debug status validation
func TestDebugModeSkipsValidation(t *testing.T) {
	logger := setupLogger()
	projectID := "tee-compute-sepolia-prod"

	// Create a verifier with debug mode enabled
	verifier := &AttestationVerifier{
		logger:          logger,
		projectID:       projectID,
		googleJwksCache: nil,
		intelJwksCache:  nil,
		debugMode:       true,
	}

	t.Run("debug mode enabled - allows enabled debug status", func(t *testing.T) {
		csToken := createDebugCsToken()
		csToken.DbgStat = "enabled"
		// Should NOT fail because debug mode is enabled
		testValidation(t, verifier, csToken, GoogleConfidentialSpace, false, "")
	})

	t.Run("debug mode enabled - allows any debug status", func(t *testing.T) {
		csToken := createDebugCsToken()
		csToken.DbgStat = "some-random-status"
		// Should NOT fail because debug mode is enabled
		testValidation(t, verifier, csToken, GoogleConfidentialSpace, false, "")
	})
}

// Test instance name parsing logic separately
func TestInstanceNameParsing(t *testing.T) {
	testCases := []struct {
		name         string
		instanceName string
		expectedApp  string
		expectError  bool
	}{
		{
			name:         "simple instance name",
			instanceName: "test-instance-app1",
			expectedApp:  "app1",
			expectError:  false,
		},
		{
			name:         "complex instance name",
			instanceName: "my-complex-instance-name-with-dashes-finalapp",
			expectedApp:  "finalapp",
			expectError:  false,
		},
		{
			name:         "minimum valid parts",
			instanceName: "prefix-app",
			expectedApp:  "app",
			expectError:  false,
		},
		{
			name:         "invalid single part",
			instanceName: "invalid",
			expectError:  true,
		},
		{
			name:         "empty string",
			instanceName: "",
			expectError:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			appID, err := extractAppIDFromInstanceName(tc.instanceName)
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expectedApp, appID)
			}
		})
	}
}

func TestNonceDecoding(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	// Setup JWKS once for all test cases
	keySet, privateKey, keyID := createTestJWKS(t)

	// Test both Google and Intel providers
	providers := []AttestationProvider{GoogleConfidentialSpace, IntelTrustAuthority}

	testCases := []struct {
		name          string
		nonce         string
		expectedNonce string
	}{
		{
			name:          "with nonce",
			nonce:         "abc123",
			expectedNonce: "abc123",
		},
		{
			name:          "empty nonce",
			nonce:         "",
			expectedNonce: "",
		},
	}

	for _, provider := range providers {
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Create token with nonce
				csToken := createProductionCsToken(provider)
				csToken.EatNonce = tc.nonce

				// Create and sign JWT token using helper
				signedToken := createdSignedJWT(t, privateKey, keyID, csToken)

				// Create verifier with mock key set
				verifier := &AttestationVerifier{
					logger:          logger,
					projectID:       "tee-compute-sepolia-prod",
					googleJwksCache: keySet,
					intelJwksCache:  keySet, // Use same mock JWKS for both providers in tests
					debugMode:       true,   // Use debug mode to skip strict validation
				}

				// Verify and extract nonce
				claims, err := verifier.VerifyAttestation(ctx, signedToken, provider)
				require.NoError(t, err)
				require.NotNil(t, claims)
				require.Equal(t, tc.expectedNonce, claims.Nonce)
			})
		}
	}
}
