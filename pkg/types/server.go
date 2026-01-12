package types

import (
	"github.com/ethereum/go-ethereum/common"
)

const DashboardJWTAudience = "EigenX Dashboard"
const KMSJWTAudience = "EigenX KMS"
const MnemonicEnvVarName = "MNEMONIC"
const NumAddressesToDerive = 5

// generic type for signed responses
type SignedResponse[T any] struct {
	Data      T      `json:"data"`
	Signature []byte `json:"signature"`
}

type EnvRequestV1 struct {
	EncryptedJWTWithRSAKey string `json:"encryptedJwtWithRsaKey"`
}

type EnvRequestV2 struct {
	JWTWithAttestedRSAKey string `json:"jwtWithAttestedRsaKey"`
	RSAKeyPEM             string `json:"rsaKey"`
}

// EnvRequestV3 represents a V3 request with raw attestation bytes (self-verified)
type EnvRequestV3 struct {
	// Attestation is base64-encoded raw attestation protobuf bytes.
	// The attestation's report data contains a hash of the RSA key, binding them together.
	Attestation string `json:"attestation"`
	// RSAKeyPEM is the RSA public key in PEM format, attested via the nonce in the attestation.
	RSAKeyPEM string `json:"rsaKey"`
}

type Env map[string]string

type EnvResponseV1 struct {
	EncryptedCombinedEnv string `json:"encryptedCombinedEnv"`
}

type EnvResponseV2 = EnvResponseV1

// EnvResponseV3 is identical to V1/V2 response
type EnvResponseV3 = EnvResponseV1

type EVMAddressAndDerivationPath struct {
	Address        common.Address `json:"address" swaggertype:"string" example:"0x1234567890abcdef1234567890abcdef12345678"`
	DerivationPath string         `json:"derivationPath"`
}

type SolanaAddressAndDerivationPath struct {
	Address        string `json:"address"`
	DerivationPath string `json:"derivationPath"`
}

type AddressesResponseV1 struct {
	EVMAddresses    []EVMAddressAndDerivationPath    `json:"evmAddresses"`
	SolanaAddresses []SolanaAddressAndDerivationPath `json:"solanaAddresses"`
}

type AddressesResponseV2 struct {
	AppID           string                           `json:"appId"`
	EVMAddresses    []EVMAddressAndDerivationPath    `json:"evmAddresses"`
	SolanaAddresses []SolanaAddressAndDerivationPath `json:"solanaAddresses"`
}

type JWTWithRSAKey struct {
	JWT    string `json:"jwt"`
	RSAKey string `json:"rsaKey"`
}
