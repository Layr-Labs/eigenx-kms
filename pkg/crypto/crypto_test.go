package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecryptSecretsWithProtectedHeaders(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := GenerateRSAKeyPair()
	require.NoError(t, err)

	appID := "test-app-id"
	protectedHeaders := GetAppProtectedHeaders(appID)

	testSecrets := map[string]string{
		"api_key":     "secret-api-key",
		"db_password": "secret-password",
		"jwt_secret":  "super-secret-jwt-key",
	}

	// Convert to JSON
	secretsJSON, err := json.Marshal(testSecrets)
	require.NoError(t, err)

	// Encrypt
	encryptedData, err := EncryptRSAOAEPAndAES256GCMWithPEM(publicKeyPEM, secretsJSON, protectedHeaders)
	require.NoError(t, err)
	require.NotEmpty(t, encryptedData)

	msg, err := jwe.Parse(encryptedData)
	require.NoError(t, err)
	var retrievedAppID string
	err = msg.ProtectedHeaders().Get(JWEAppIDHeader, &retrievedAppID)
	require.NoError(t, err)
	require.Equal(t, appID, retrievedAppID)

	// Decrypt
	privateKey, err := RSAPrivateKeyFromPEM(privateKeyPEM)
	require.NoError(t, err)

	decryptedJSON, err := DecryptWithRSAOAEPAndAES256GCM(privateKey, encryptedData)
	require.NoError(t, err)

	// Verify
	var decryptedSecrets map[string]string
	err = json.Unmarshal(decryptedJSON, &decryptedSecrets)
	require.NoError(t, err)
	require.Equal(t, testSecrets, decryptedSecrets)
}

func TestEncryptDecryptSecretsWithoutProtectedHeaders(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := GenerateRSAKeyPair()
	require.NoError(t, err)

	testSecrets := map[string]string{
		"api_key":     "secret-api-key",
		"db_password": "secret-password",
		"jwt_secret":  "super-secret-jwt-key",
	}

	// Convert to JSON
	secretsJSON, err := json.Marshal(testSecrets)
	require.NoError(t, err)

	// Encrypt
	encryptedData, err := EncryptRSAOAEPAndAES256GCMWithPEM(publicKeyPEM, secretsJSON, nil)
	require.NoError(t, err)
	require.NotEmpty(t, encryptedData)

	// Decrypt
	privateKey, err := RSAPrivateKeyFromPEM(privateKeyPEM)
	require.NoError(t, err)

	decryptedJSON, err := DecryptWithRSAOAEPAndAES256GCM(privateKey, encryptedData)
	require.NoError(t, err)

	// Verify
	var decryptedSecrets map[string]string
	err = json.Unmarshal(decryptedJSON, &decryptedSecrets)
	require.NoError(t, err)
	require.Equal(t, testSecrets, decryptedSecrets)
}

func TestEncryptDecryptLargeData(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := GenerateRSAKeyPair()
	require.NoError(t, err)

	// Test with larger data (10KB)
	largeData := make([]byte, 10000)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	encryptedData, err := EncryptRSAOAEPAndAES256GCMWithPEM(publicKeyPEM, largeData, nil)
	require.NoError(t, err)

	privateKey, err := RSAPrivateKeyFromPEM(privateKeyPEM)
	require.NoError(t, err)

	decryptedData, err := DecryptWithRSAOAEPAndAES256GCM(privateKey, encryptedData)
	require.NoError(t, err)
	require.Equal(t, largeData, decryptedData)
}

func TestRSAPrivateKeyFromPEM(t *testing.T) {
	privateKeyPEM, _, err := GenerateRSAKeyPair()
	require.NoError(t, err)

	// Test valid PEM
	privateKey, err := RSAPrivateKeyFromPEM(privateKeyPEM)
	require.NoError(t, err)
	require.NotNil(t, privateKey)
}

func TestInvalidInputs(t *testing.T) {
	t.Run("invalid public key PEM", func(t *testing.T) {
		_, err := EncryptRSAOAEPAndAES256GCMWithPEM([]byte("invalid-pem"), []byte("test"), nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decode PEM block")
	})

	t.Run("invalid private key PEM", func(t *testing.T) {
		_, err := RSAPrivateKeyFromPEM([]byte("invalid-pem"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decode PEM block")
	})

	t.Run("invalid encrypted data", func(t *testing.T) {
		privateKeyPEM, _, err := GenerateRSAKeyPair()
		require.NoError(t, err)

		privateKey, err := RSAPrivateKeyFromPEM(privateKeyPEM)
		require.NoError(t, err)

		_, err = DecryptWithRSAOAEPAndAES256GCM(privateKey, []byte("invalid-jwe"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decrypt data")
	})

	t.Run("mismatched keys", func(t *testing.T) {
		_, publicKeyPEM1, err := GenerateRSAKeyPair()
		require.NoError(t, err)
		privateKeyPEM2, _, err := GenerateRSAKeyPair()
		require.NoError(t, err)

		encryptedData, err := EncryptRSAOAEPAndAES256GCMWithPEM(publicKeyPEM1, []byte("test"), nil)
		require.NoError(t, err)

		privateKey2, err := RSAPrivateKeyFromPEM(privateKeyPEM2)
		require.NoError(t, err)

		_, err = DecryptWithRSAOAEPAndAES256GCM(privateKey2, encryptedData)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decrypt data")
	})
}

func TestMinimalData(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := GenerateRSAKeyPair()
	require.NoError(t, err)

	// Test with minimal data (single byte)
	minimalData := []byte("x")
	encryptedData, err := EncryptRSAOAEPAndAES256GCMWithPEM(publicKeyPEM, minimalData, nil)
	require.NoError(t, err)

	privateKey, err := RSAPrivateKeyFromPEM(privateKeyPEM)
	require.NoError(t, err)

	decryptedData, err := DecryptWithRSAOAEPAndAES256GCM(privateKey, encryptedData)
	require.NoError(t, err)
	require.Equal(t, minimalData, decryptedData)
}

// Mock opaque key decrypter for testing KMS scenario
type mockOpaqueDecrypter struct {
	decryptedKey []byte
	shouldFail   bool
}

func (m *mockOpaqueDecrypter) DecryptKey(alg jwa.KeyEncryptionAlgorithm, encryptedKey []byte, _ jwe.Recipient, _ *jwe.Message) ([]byte, error) {
	if m.shouldFail {
		return nil, fmt.Errorf("mock decryption failure")
	}
	return m.decryptedKey, nil
}

func TestDecryptWithOpaqueKeyWithProtectedHeaders(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := GenerateRSAKeyPair()
	require.NoError(t, err)

	appID := "test-app-id"
	protectedHeaders := GetAppProtectedHeaders(appID)
	testData := []byte("test data for opaque key")

	// Encrypt with RSA public key
	encryptedData, err := EncryptRSAOAEPAndAES256GCMWithPEM(publicKeyPEM, testData, protectedHeaders)
	require.NoError(t, err)

	msg, err := jwe.Parse(encryptedData)
	require.NoError(t, err)
	var retrievedAppID string
	err = msg.ProtectedHeaders().Get(JWEAppIDHeader, &retrievedAppID)
	require.NoError(t, err)
	require.Equal(t, appID, retrievedAppID)

	// Get the actual data by decrypting with the real private key first
	privateKey, err := RSAPrivateKeyFromPEM(privateKeyPEM)
	require.NoError(t, err)
	actualData, err := DecryptWithRSAOAEPAndAES256GCM(privateKey, encryptedData)
	require.NoError(t, err)
	require.Equal(t, testData, actualData)

	// Test mock opaque decrypter failure case
	mockDecrypter := &mockOpaqueDecrypter{shouldFail: true}
	_, err = DecryptWithRSAOAEPAndAES256GCM(mockDecrypter, encryptedData)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to decrypt data")
}

func TestDecryptWithOpaqueKeyWithoutProtectedHeaders(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := GenerateRSAKeyPair()
	require.NoError(t, err)

	testData := []byte("test data for opaque key")

	// Encrypt with RSA public key
	encryptedData, err := EncryptRSAOAEPAndAES256GCMWithPEM(publicKeyPEM, testData, nil)
	require.NoError(t, err)

	privateKey, err := RSAPrivateKeyFromPEM(privateKeyPEM)
	require.NoError(t, err)

	decryptedData, err := DecryptWithRSAOAEPAndAES256GCM(privateKey, encryptedData)
	require.NoError(t, err)
	require.Equal(t, testData, decryptedData)

	// Test mock opaque decrypter failure case
	mockDecrypter := &mockOpaqueDecrypter{shouldFail: true}
	_, err = DecryptWithRSAOAEPAndAES256GCM(mockDecrypter, encryptedData)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to decrypt data")
}

func TestValidateRSAKeySize(t *testing.T) {
	t.Run("valid 4096-bit key", func(t *testing.T) {
		_, publicKeyPEM, err := GenerateRSAKeyPair()
		require.NoError(t, err)

		err = ValidateRSAKeySize(publicKeyPEM)
		require.NoError(t, err)
	})

	t.Run("invalid 2048-bit key", func(t *testing.T) {
		// Generate 2048-bit key for testing
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		require.NoError(t, err)

		publicKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		})

		err = ValidateRSAKeySize(publicKeyPEM)
		require.Error(t, err)
		require.Contains(t, err.Error(), "RSA key must be 4096 bits, got 2048 bits")
	})

	t.Run("invalid PEM", func(t *testing.T) {
		err := ValidateRSAKeySize([]byte("invalid-pem"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decode PEM block")
	})

	t.Run("PKCS#1 format support", func(t *testing.T) {
		// Generate 4096-bit key
		privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
		require.NoError(t, err)

		// Marshal as PKCS#1 (RSA PUBLIC KEY)
		publicKeyBytes := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
		publicKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKeyBytes,
		})

		err = ValidateRSAKeySize(publicKeyPEM)
		require.NoError(t, err)
	})
}
