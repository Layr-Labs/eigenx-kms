package fakes

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/Layr-Labs/eigenx-kms/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms/pkg/types"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
)

// FakeKMS provides a simple in-memory KMS implementation with real RSA encryption
// and ECDSA signing for testing purposes. It generates both RSA and ECDSA key pairs.
type FakeKMS struct {
	rsaPrivateKey   *rsa.PrivateKey
	rsaPublicKey    *rsa.PublicKey
	ecdsaPrivateKey *ecdsa.PrivateKey
	ecdsaPublicKey  *ecdsa.PublicKey
}

// NewFakeKMS creates a new fake KMS instance with generated RSA and ECDSA key pairs
func NewFakeKMS() (*FakeKMS, error) {
	// Generate 4096-bit RSA key for encryption
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Generate ECDSA key for signing (P-256 curve)
	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	return &FakeKMS{
		rsaPrivateKey:   rsaPrivateKey,
		rsaPublicKey:    &rsaPrivateKey.PublicKey,
		ecdsaPrivateKey: ecdsaPrivateKey,
		ecdsaPublicKey:  &ecdsaPrivateKey.PublicKey,
	}, nil
}

// GetPublicKeyPEM returns the RSA public key in PEM format (for encryption)
func (f *FakeKMS) GetEncryptionPublicKeyPEM() ([]byte, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(f.rsaPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal RSA public key: %w", err)
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return pubKeyPEM, nil
}

// GetSigningPublicKeyPEM returns the ECDSA public key in PEM format (for signature verification)
func (f *FakeKMS) GetSigningPublicKeyPEM() ([]byte, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(f.ecdsaPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ECDSA public key: %w", err)
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return pubKeyPEM, nil
}

// GetPrivateKeyPEM returns the RSA private key in PEM format
func (f *FakeKMS) GetEncryptionPrivateKeyPEM() ([]byte, error) {
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(f.rsaPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal RSA private key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return privateKeyPEM, nil
}

// Implement KMSClient interface

// DeriveMnemonic returns a fake mnemonic for testing
func (f *FakeKMS) DeriveMnemonic(ctx context.Context, appID string) (string, error) {
	return "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", nil
}

// SignMessage returns a real ECDSA signature for testing
func (f *FakeKMS) SignMessage(ctx context.Context, message string) ([]byte, error) {
	// Calculate the digest of the message using the same method as the real KMS
	digest := crypto.CalculateSignableDigest(crypto.KMSSignatureHeader, []byte(message))

	// Sign the digest using ECDSA
	r, s, err := ecdsa.Sign(rand.Reader, f.ecdsaPrivateKey, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	// Encode the signature in ASN.1 DER format (same as real KMS)
	type ecdsaSignature struct {
		R, S *big.Int
	}

	signature := ecdsaSignature{R: r, S: s}
	signatureBytes, err := asn1.Marshal(signature)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signature: %w", err)
	}

	return signatureBytes, nil
}

// DecryptBytes decrypts data using RSA-OAEP with SHA256
func (f *FakeKMS) DecryptBytes(ctx context.Context, encryptedData []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, f.rsaPrivateKey, encryptedData, nil)
}

// DecryptKey implements key decryption for JWE operations
func (f *FakeKMS) DecryptKey(alg jwa.KeyEncryptionAlgorithm, encryptedKey []byte, _ jwe.Recipient, _ *jwe.Message) ([]byte, error) {
	if alg != jwa.RSA_OAEP_256() {
		return nil, fmt.Errorf("unsupported algorithm: %s", alg)
	}
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, f.rsaPrivateKey, encryptedKey, nil)
}

// Close does nothing for fake implementation
func (f *FakeKMS) Close() error {
	return nil
}

// CreateValidEncryptedRequestV1 creates a valid encrypted request using the fake KMS
// that can be used in tests to simulate real client requests
func (f *FakeKMS) CreateValidEncryptedRequestV1(jwt string) (types.EnvRequestV1, []byte, error) {
	// Get our public key PEM for the request
	kmsPublicKeyPEM, err := f.GetEncryptionPublicKeyPEM()
	if err != nil {
		return types.EnvRequestV1{}, nil, fmt.Errorf("failed to get KMS public key: %w", err)
	}

	// Generate client RSA key pair
	clientRSAPrivatePEM, clientRSAPublicPEM, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		return types.EnvRequestV1{}, nil, fmt.Errorf("failed to generate client RSA key pair: %w", err)
	}

	// Create JWTWithRSAKey structure
	jwtWithKey := types.JWTWithRSAKey{
		JWT:    jwt,
		RSAKey: string(clientRSAPublicPEM),
	}

	jwtWithKeyJSON, err := json.Marshal(jwtWithKey)
	if err != nil {
		return types.EnvRequestV1{}, nil, fmt.Errorf("failed to marshal JWT with key: %w", err)
	}

	// Encrypt using the crypto library like the client does
	encryptedJWTWithRSAKey, err := crypto.EncryptRSAOAEPAndAES256GCMWithPEM(kmsPublicKeyPEM, jwtWithKeyJSON, nil)
	if err != nil {
		return types.EnvRequestV1{}, nil, fmt.Errorf("failed to encrypt JWT with RSA key: %w", err)
	}

	return types.EnvRequestV1{
		EncryptedJWTWithRSAKey: string(encryptedJWTWithRSAKey),
	}, clientRSAPrivatePEM, nil
}

// CreateInvalidKeyEncryptedRequestV1 creates an encrypted request with a non-4096-bit RSA key
func (f *FakeKMS) CreateInvalidKeyEncryptedRequestV1(jwt string, keySize int) (types.EnvRequestV1, error) {
	// Get our public key PEM for the request
	kmsPublicKeyPEM, err := f.GetEncryptionPublicKeyPEM()
	if err != nil {
		return types.EnvRequestV1{}, fmt.Errorf("failed to get KMS public key: %w", err)
	}

	// Generate client RSA key pair with specified size (not 4096)
	clientPrivateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return types.EnvRequestV1{}, fmt.Errorf("failed to generate client RSA key: %w", err)
	}

	// Convert to PEM format
	clientPublicKeyBytes, err := x509.MarshalPKIXPublicKey(&clientPrivateKey.PublicKey)
	if err != nil {
		return types.EnvRequestV1{}, fmt.Errorf("failed to marshal client public key: %w", err)
	}

	clientRSAPublicPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: clientPublicKeyBytes,
	})

	// Create JWTWithRSAKey structure
	jwtWithKey := types.JWTWithRSAKey{
		JWT:    jwt,
		RSAKey: string(clientRSAPublicPEM),
	}

	jwtWithKeyJSON, err := json.Marshal(jwtWithKey)
	if err != nil {
		return types.EnvRequestV1{}, fmt.Errorf("failed to marshal JWT with key: %w", err)
	}

	// Encrypt using the crypto library like the client does
	encryptedJWTWithRSAKey, err := crypto.EncryptRSAOAEPAndAES256GCMWithPEM(kmsPublicKeyPEM, jwtWithKeyJSON, nil)
	if err != nil {
		return types.EnvRequestV1{}, fmt.Errorf("failed to encrypt JWT with RSA key: %w", err)
	}

	return types.EnvRequestV1{
		EncryptedJWTWithRSAKey: string(encryptedJWTWithRSAKey),
	}, nil
}
