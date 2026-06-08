//go:generate mockgen -destination=../chainclient/mocks/mock_app_interfaces.go -package=mocks . AppController,AppUpgradedIterator,ImageAllowlist
package types

import (
	"math/big"

	imageAllowlistV1 "github.com/Layr-Labs/eigenx-contracts/pkg/bindings/v1/ImageAllowlist"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
)

// AppRelease is the version-agnostic projection of an AppUpgraded event that the
// KMS consumes. Both the v1.4 (3-field Release) and v1.5 (4-field Release with
// containerPolicy) AppController bindings are mapped into this shape by their
// respective adapters, so the chainclient release-fetch logic stays independent
// of which on-chain ABI an environment runs.
type AppRelease struct {
	RmsReleaseID    *big.Int
	LogIndex        uint
	BlockNumber     uint64
	ArtifactDigests [][32]byte
	PublicEnv       []byte
	EncryptedEnv    []byte
}

type AppUpgradedIterator interface {
	Next() bool
	// Event returns the current AppUpgraded log projected into the
	// version-agnostic AppRelease shape.
	Event() *AppRelease
}

type AppController interface {
	GetAppCreator(opts *bind.CallOpts, app common.Address) (common.Address, error)
	GetAppOperatorSetId(opts *bind.CallOpts, app common.Address) (uint32, error)
	GetAppLatestReleaseBlockNumber(opts *bind.CallOpts, app common.Address) (uint32, error)
	GetAppStatus(opts *bind.CallOpts, app common.Address) (uint8, error)
	FilterAppUpgraded(opts *bind.FilterOpts, apps []common.Address) (AppUpgradedIterator, error)
	ReleaseManager(opts *bind.CallOpts) (common.Address, error)
	ComputeAVSRegistrar(opts *bind.CallOpts) (common.Address, error)
}

type ImageAllowlist interface {
	IsImageAllowed(opts *bind.CallOpts, cvm uint8, pcrs []imageAllowlistV1.IImageAllowlistPCR) (bool, error)
	IsTCBValid(opts *bind.CallOpts, cvm uint8, tcb uint64) (bool, error)
}
