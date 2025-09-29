package types

import (
	"github.com/ethereum/go-ethereum/common"
)

// generic type for signed responses
type SignedResponse[T any] struct {
	Data      T      `json:"data"`
	Signature []byte `json:"signature"`
}

type EnvRequest struct {
	EncryptedJWTWithRSAKey string `json:"encryptedJwtWithRsaKey"`
}

type Env map[string]string

type EnvResponse struct {
	EncryptedCombinedEnv string `json:"encryptedCombinedEnv"`
}

type EVMAddressAndDerivationPath struct {
	Address        common.Address `json:"address" swaggertype:"string" example:"0x1234567890abcdef1234567890abcdef12345678"`
	DerivationPath string         `json:"derivationPath"`
}

type SolanaAddressAndDerivationPath struct {
	Address        string `json:"address"`
	DerivationPath string `json:"derivationPath"`
}

type AddressesResponse struct {
	EVMAddresses    []EVMAddressAndDerivationPath    `json:"evmAddresses"`
	SolanaAddresses []SolanaAddressAndDerivationPath `json:"solanaAddresses"`
}

type JWTWithRSAKey struct {
	JWT    string `json:"jwt"`
	RSAKey string `json:"rsaKey"`
}
