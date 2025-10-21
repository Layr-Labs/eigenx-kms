//go:generate mockgen -source=kms.go -destination=mocks/mock_kms.go -package=mocks KMSClient

package kms

import (
	"context"
	"crypto/sha256"
	"fmt"
	"hash/crc32"
	"log/slog"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/Layr-Labs/eigenx-kms/pkg/crypto"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const keyNameTemplate = "projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/1"

type KMSClient interface {
	DeriveMnemonic(ctx context.Context, appID string) (string, error)
	SignMessage(ctx context.Context, message string) ([]byte, error)
	DecryptBytes(ctx context.Context, encryptedData []byte) ([]byte, error)
	DecryptKey(alg jwa.KeyEncryptionAlgorithm, encryptedKey []byte, _ jwe.Recipient, _ *jwe.Message) ([]byte, error)
	Close() error
}

type GcpKmsClient struct {
	logger            *slog.Logger
	client            *kms.KeyManagementClient
	hmacKeyName       string
	encryptionKeyName string
	signingKeyName    string
}

type GcpKmsClientConfig struct {
	ProjectID       string
	LocationID      string
	KeyRingID       string
	HmacKeyID       string
	EncryptionKeyID string
	SigningKeyID    string
}

func NewGcpKmsClient(ctx context.Context, logger *slog.Logger, config GcpKmsClientConfig) (*GcpKmsClient, error) {
	kmsLogger := logger.With("component", "kms_client")
	kmsLogger.Debug("Initializing KMS client", "config", config)
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create KMS client: %w", err)
	}

	hmacKeyName := fmt.Sprintf(keyNameTemplate, config.ProjectID, config.LocationID, config.KeyRingID, config.HmacKeyID)
	encryptionKeyName := fmt.Sprintf(keyNameTemplate, config.ProjectID, config.LocationID, config.KeyRingID, config.EncryptionKeyID)
	signingKeyName := fmt.Sprintf(keyNameTemplate, config.ProjectID, config.LocationID, config.KeyRingID, config.SigningKeyID)

	kmsLogger.Info("KMS client initialized successfully", "hmac_key", hmacKeyName, "encryption_key", encryptionKeyName, "signing_key", signingKeyName)

	return &GcpKmsClient{
		logger:            kmsLogger,
		client:            client,
		hmacKeyName:       hmacKeyName,
		encryptionKeyName: encryptionKeyName,
		signingKeyName:    signingKeyName,
	}, nil
}

func (k *GcpKmsClient) DeriveMnemonic(ctx context.Context, appID string) (string, error) {
	k.logger.Debug("Starting mnemonic derivation", "app_id", appID)

	// Strong domain separation to prevent cross-contamination
	domainSeparator := []byte("COMPUTE_APP_KEY_DERIVATION_V1")

	// Create isolated input that can't collide with other uses
	h := sha256.New()
	h.Write(domainSeparator)
	h.Write([]byte{0x00})  // separator
	h.Write([]byte(appID)) // TODO: other checks?
	isolatedInput := h.Sum(nil)

	req := &kmspb.MacSignRequest{
		Name: k.hmacKeyName,
		Data: isolatedInput,
	}

	result, err := k.client.MacSign(ctx, req)
	if err != nil {
		return "", fmt.Errorf("failed to MAC sign: %w", err)
	}
	if result.Mac == nil {
		return "", fmt.Errorf("failed to MAC sign: no MAC returned")
	}

	k.logger.Debug("MAC signed successfully", "mac_length", len(result.Mac))

	// cap the MAC to 256 bits
	entropy := result.Mac[:32]
	// derive mnemonic from MAC
	mnemonic, err := hdwallet.NewMnemonicFromEntropy(entropy)
	if err != nil {
		return "", fmt.Errorf("failed to derive mnemonic: %w", err)
	}
	k.logger.Debug("Mnemonic derived successfully", "app_id", appID)
	return mnemonic, nil
}

func (k *GcpKmsClient) SignMessage(ctx context.Context, message string) ([]byte, error) {
	k.logger.Debug("Starting message signing")

	// Calculate the digest of the message.
	digest := crypto.CalculateSignableDigest(crypto.KMSSignatureHeader, []byte(message))

	// Optional but recommended: Compute digest's CRC32C.
	crc32c := func(data []byte) uint32 {
		t := crc32.MakeTable(crc32.Castagnoli)
		return crc32.Checksum(data, t)

	}
	digestCRC32C := crc32c(digest)

	// Build the signing request.
	//
	// Note: Key algorithms will require a varying hash function. For example,
	// EC_SIGN_P384_SHA384 requires SHA-384.
	req := &kmspb.AsymmetricSignRequest{
		Name: k.signingKeyName,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest,
			},
		},
		DigestCrc32C: wrapperspb.Int64(int64(digestCRC32C)),
	}

	// Call the API.
	result, err := k.client.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to sign digest: %w", err)
	}

	// Optional, but recommended: perform integrity verification on result.
	// For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
	// https://cloud.google.com/kms/docs/data-integrity-guidelines
	if !result.VerifiedDigestCrc32C {
		return nil, fmt.Errorf("AsymmetricSign: request corrupted in-transit")
	}
	if result.Name != req.Name {
		return nil, fmt.Errorf("AsymmetricSign: request corrupted in-transit")
	}
	if int64(crc32c(result.Signature)) != result.SignatureCrc32C.Value {
		return nil, fmt.Errorf("AsymmetricSign: response corrupted in-transit")
	}

	k.logger.Debug("Message signed successfully")
	return result.Signature, nil
}

// DecryptBytes decrypts data using the KMS encryption key
func (k *GcpKmsClient) DecryptBytes(ctx context.Context, encryptedData []byte) ([]byte, error) {
	k.logger.Debug("Starting byte decryption")

	// Optional but recommended: Compute ciphertext's CRC32C.
	crc32c := func(data []byte) uint32 {
		t := crc32.MakeTable(crc32.Castagnoli)
		return crc32.Checksum(data, t)
	}
	ciphertextCRC32C := crc32c(encryptedData)

	// Build the request.
	req := &kmspb.AsymmetricDecryptRequest{
		Name:             k.encryptionKeyName,
		Ciphertext:       encryptedData,
		CiphertextCrc32C: wrapperspb.Int64(int64(ciphertextCRC32C)),
	}

	// Call the API.
	result, err := k.client.AsymmetricDecrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}

	// Optional, but recommended: perform integrity verification on result.
	if !result.VerifiedCiphertextCrc32C {
		return nil, fmt.Errorf("AsymmetricDecrypt: request corrupted in-transit")
	}
	if int64(crc32c(result.Plaintext)) != result.PlaintextCrc32C.Value {
		return nil, fmt.Errorf("AsymmetricDecrypt: response corrupted in-transit")
	}

	k.logger.Debug("Bytes decrypted successfully")
	return result.Plaintext, nil
}

// DecryptKey implements key decryption for JWE operations
func (k *GcpKmsClient) DecryptKey(alg jwa.KeyEncryptionAlgorithm, encryptedKey []byte, _ jwe.Recipient, _ *jwe.Message) ([]byte, error) {
	ctx := context.Background() // TODO: use context from caller...
	if alg != jwa.RSA_OAEP_256() {
		return nil, fmt.Errorf("unsupported algorithm: %s", alg)
	}

	return k.DecryptBytes(ctx, encryptedKey)
}

func (k *GcpKmsClient) Close() error {
	return k.client.Close()
}
