package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"testing"

	"github.com/Layr-Labs/eigenx-kms/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms/pkg/types"
	"github.com/stretchr/testify/require"
)

// TestHandleEnvV3_InputValidation tests input validation before attestation verification.
// Since we call teeverify.VerifyAttestation directly (not mocked), we can only test
// scenarios that fail before reaching attestation verification.
// The attestation verification itself is tested in the go-tpm-tools repo.
func TestHandleEnvV3_InputValidation(t *testing.T) {
	logger := setupEnvLogger()

	t.Run("invalid JSON in request body", func(t *testing.T) {
		c, rec := setupEchoContextWithBody(http.MethodPost, "/env/v3", []byte("{invalid json}"))

		err := HandleEnvV3(c, logger, nil, nil, nil, false)

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

		err := HandleEnvV3(c, logger, nil, nil, nil, false)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		requireErrorResponse(t, rec, "encryption key size mismatch")
	})

	t.Run("RSA key size mismatch - 2048 bit instead of 4096", func(t *testing.T) {
		// Generate a 2048-bit RSA key (invalid, should be 4096)
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

		err = HandleEnvV3(c, logger, nil, nil, nil, false)

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

		err = HandleEnvV3(c, logger, nil, nil, nil, false)

		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		requireErrorResponse(t, rec, "Failed to decode attestation")
	})
}
