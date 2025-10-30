package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/Layr-Labs/eigenx-kms/pkg/types"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
)

var (
	KMSSignatureHeader     = []byte("COMPUTE_APP_KMS_SIGNATURE_V1")
	EnvRequestRSAKeyHeader = []byte("COMPUTE_APP_ENV_REQUEST_RSA_KEY_V1")
	JWEAppIDHeader         = "x-eigenx-app-id"
)

// GenerateRSAKeyPair generates a 4096-bit RSA private key and public key
func GenerateRSAKeyPair() ([]byte, []byte, error) {
	// Generate 4096-bit RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Encode private key as PEM
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Encode public key as PEM
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return privateKeyPEM, publicKeyPEM, nil
}

func RSAPrivateKeyFromPEM(privateKeyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return privKey, nil
}

func GetAppProtectedHeaders(appID string) *jwe.Headers {
	headers := jwe.NewHeaders()
	headers.Set(JWEAppIDHeader, appID)
	return &headers
}

// EncryptRSAOAEPAndAES256GCMWithPEM encrypts data with RSA-OAEP and AES-256-GCM given a public key PEM and protected headers
func EncryptRSAOAEPAndAES256GCMWithPEM(publicKeyPEM []byte, data []byte, protectedHeaders *jwe.Headers) ([]byte, error) {
	rsaPubKey, err := parseRSAKey(publicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
	}
	options := []jwe.EncryptOption{
		jwe.WithKey(jwa.RSA_OAEP_256(), rsaPubKey),
		jwe.WithContentEncryption(jwa.A256GCM()),
	}
	if protectedHeaders != nil {
		options = append(options, jwe.WithProtectedHeaders(*protectedHeaders))
	}

	encryptedData, err := jwe.Encrypt(data, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	return encryptedData, nil
}

// DecryptWithRSAOAEPAndAES256GCM decrypts data with RSA-OAEP and AES-256-GCM given a decryption key and protected headers
func DecryptWithRSAOAEPAndAES256GCM(keyDecrypter interface{}, encryptedData []byte) ([]byte, error) {
	if jweDecrypter, ok := keyDecrypter.(jwe.KeyDecrypter); ok {
		decryptedData, err := jwe.Decrypt(encryptedData, jwe.WithKey(jwa.RSA_OAEP_256(), jweDecrypter))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt data: %w", err)
		}
		return decryptedData, nil
	} else if rsaKey, ok := keyDecrypter.(*rsa.PrivateKey); ok {
		decryptedData, err := jwe.Decrypt(encryptedData, jwe.WithKey(jwa.RSA_OAEP_256(), rsaKey))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt data: %w", err)
		}
		return decryptedData, nil
	} else {
		return nil, fmt.Errorf("key decrypter is not a JWE key decrypter or RSA private key")
	}
}

// ValidateRSAKeySize validates that the RSA public key is 4096-bit with standard public exponent
func ValidateRSAKeySize(publicKeyPEM []byte) error {
	rsaPubKey, err := parseRSAKey(publicKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse RSA public key: %w", err)
	}

	// Check if the key size is 4096 bits
	keySize := rsaPubKey.N.BitLen()
	if keySize != 4096 {
		return fmt.Errorf("RSA key must be 4096 bits, got %d bits", keySize)
	}

	// Validate standard public exponent for security
	if rsaPubKey.E != 65537 {
		return fmt.Errorf("RSA public exponent must be 65537 (standard), got %d", rsaPubKey.E)
	}

	return nil
}

func parseRSAKey(publicKeyPEM []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	var rsaPubKey *rsa.PublicKey
	// Try PKIX format first (most common)
	if pubKey, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		var ok bool
		rsaPubKey, ok = pubKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key is not RSA")
		}
	} else {
		// Fallback to PKCS#1 format
		var err2 error
		rsaPubKey, err2 = x509.ParsePKCS1PublicKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("failed to parse RSA public key (tried both PKIX and PKCS#1): %w", err2)
		}
	}

	return rsaPubKey, nil
}

func CalculateSignableDigest(header, data []byte) []byte {
	digest := sha256.New()
	digest.Write(header)
	digest.Write([]byte{0x00}) // separator
	digest.Write(data)

	return digest.Sum(nil)
}

// VerifyKMSSignature verifies a signature using ECDSA with SHA-256
func VerifyKMSSignature[T any](signedResponse types.SignedResponse[T], publicKeyPEM []byte) (bool, error) {
	// Parse the PEM encoded public key
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return false, fmt.Errorf("failed to decode PEM block")
	}

	// Parse the public key
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse public key: %w", err)
	}

	ecKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("public key is not elliptic curve")
	}

	// Parse the ASN.1 DER encoded signature
	var parsedSig struct{ R, S *big.Int }
	if _, err = asn1.Unmarshal(signedResponse.Signature, &parsedSig); err != nil {
		return false, fmt.Errorf("asn1.Unmarshal: %w", err)
	}

	envJSON, err := json.Marshal(signedResponse.Data)
	if err != nil {
		return false, fmt.Errorf("failed to marshal env: %w", err)
	}
	digest := CalculateSignableDigest(KMSSignatureHeader, envJSON)
	if !ecdsa.Verify(ecKey, digest[:], parsedSig.R, parsedSig.S) {
		return false, nil // Invalid signature, but no error
	}

	return true, nil
}
