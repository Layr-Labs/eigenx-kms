package chainclient

import (
	"fmt"

	appcontrollerV1 "github.com/Layr-Labs/eigenx-contracts/pkg/bindings/v1/AppController"
	imageAllowlistV1 "github.com/Layr-Labs/eigenx-contracts/pkg/bindings/v1/ImageAllowlist"
	appcontrollerV14 "github.com/Layr-Labs/eigenx-kms/pkg/chainclient/bindings/appcontrollerv14"
	"github.com/Layr-Labs/eigenx-kms/pkg/types"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
)

// Release ABI versions selectable via the RELEASE_ABI_VERSION config. They mirror
// the on-chain AppController Release struct shape per environment: v1.4 has a
// 3-field Release; v1.5 adds a 4th containerPolicy field, which changes the
// AppUpgraded event signature (topic0), so the two are NOT cross-decodable.
const (
	ReleaseAbiV14 = "v1.4"
	ReleaseAbiV15 = "v1.5"
)

// NewAppController constructs an AppController bound to the address, decoding
// AppUpgraded events with the ABI matching abiVersion. An empty version defaults
// to v1.5 (the latest on-chain release shape).
func NewAppController(abiVersion string, address common.Address, backend bind.ContractBackend) (types.AppController, error) {
	switch abiVersion {
	case "", ReleaseAbiV15:
		ctrl, err := appcontrollerV1.NewAppController(address, backend)
		if err != nil {
			return nil, fmt.Errorf("bind v1.5 AppController at %s: %w", address.Hex(), err)
		}
		return WrapAppController(ctrl), nil
	case ReleaseAbiV14:
		ctrl, err := appcontrollerV14.NewAppController(address, backend)
		if err != nil {
			return nil, fmt.Errorf("bind v1.4 AppController at %s: %w", address.Hex(), err)
		}
		return WrapAppControllerV14(ctrl), nil
	default:
		return nil, fmt.Errorf("unknown release ABI version %q (want %q or %q)", abiVersion, ReleaseAbiV14, ReleaseAbiV15)
	}
}

// --- v1.5 AppController (4-field Release, current eigenx-contracts dependency) ---

// appUpgradedIteratorV15 adapts the generated v1.5 iterator to types.AppUpgradedIterator,
// projecting each event into the version-agnostic types.AppRelease.
type appUpgradedIteratorV15 struct {
	*appcontrollerV1.AppControllerAppUpgradedIterator
}

func (a *appUpgradedIteratorV15) Next() bool {
	return a.AppControllerAppUpgradedIterator.Next()
}

func (a *appUpgradedIteratorV15) Event() *types.AppRelease {
	e := a.AppControllerAppUpgradedIterator.Event
	digests := make([][32]byte, len(e.Release.RmsRelease.Artifacts))
	for i, art := range e.Release.RmsRelease.Artifacts {
		digests[i] = art.Digest
	}
	return &types.AppRelease{
		RmsReleaseID:    e.RmsReleaseId,
		LogIndex:        e.Raw.Index,
		BlockNumber:     e.Raw.BlockNumber,
		ArtifactDigests: digests,
		PublicEnv:       e.Release.PublicEnv,
		EncryptedEnv:    e.Release.EncryptedEnv,
	}
}

// AppControllerAdapter adapts the generated v1.5 AppController to types.AppController.
type AppControllerAdapter struct {
	*appcontrollerV1.AppController
}

// WrapAppController wraps the v1.5 contract binding to implement types.AppController.
func WrapAppController(appController *appcontrollerV1.AppController) types.AppController {
	return &AppControllerAdapter{AppController: appController}
}

func (a *AppControllerAdapter) GetAppCreator(opts *bind.CallOpts, app common.Address) (common.Address, error) {
	return a.AppController.GetAppCreator(opts, app)
}

func (a *AppControllerAdapter) GetAppOperatorSetId(opts *bind.CallOpts, app common.Address) (uint32, error) {
	return a.AppController.GetAppOperatorSetId(opts, app)
}

func (a *AppControllerAdapter) GetAppLatestReleaseBlockNumber(opts *bind.CallOpts, app common.Address) (uint32, error) {
	return a.AppController.GetAppLatestReleaseBlockNumber(opts, app)
}

func (a *AppControllerAdapter) GetAppStatus(opts *bind.CallOpts, app common.Address) (uint8, error) {
	return a.AppController.GetAppStatus(opts, app)
}

func (a *AppControllerAdapter) ReleaseManager(opts *bind.CallOpts) (common.Address, error) {
	return a.AppController.ReleaseManager(opts)
}

func (a *AppControllerAdapter) ComputeAVSRegistrar(opts *bind.CallOpts) (common.Address, error) {
	return a.AppController.ComputeAVSRegistrar(opts)
}

func (a *AppControllerAdapter) FilterAppUpgraded(opts *bind.FilterOpts, apps []common.Address) (types.AppUpgradedIterator, error) {
	iter, err := a.AppController.FilterAppUpgraded(opts, apps)
	if err != nil {
		return nil, err
	}
	return &appUpgradedIteratorV15{iter}, nil
}

// --- v1.4 AppController (3-field Release, vendored binding) ---

// appUpgradedIteratorV14 adapts the generated v1.4 iterator to types.AppUpgradedIterator.
type appUpgradedIteratorV14 struct {
	*appcontrollerV14.AppControllerAppUpgradedIterator
}

func (a *appUpgradedIteratorV14) Next() bool {
	return a.AppControllerAppUpgradedIterator.Next()
}

func (a *appUpgradedIteratorV14) Event() *types.AppRelease {
	e := a.AppControllerAppUpgradedIterator.Event
	digests := make([][32]byte, len(e.Release.RmsRelease.Artifacts))
	for i, art := range e.Release.RmsRelease.Artifacts {
		digests[i] = art.Digest
	}
	return &types.AppRelease{
		RmsReleaseID:    e.RmsReleaseId,
		LogIndex:        e.Raw.Index,
		BlockNumber:     e.Raw.BlockNumber,
		ArtifactDigests: digests,
		PublicEnv:       e.Release.PublicEnv,
		EncryptedEnv:    e.Release.EncryptedEnv,
	}
}

// AppControllerV14Adapter adapts the vendored v1.4 AppController to types.AppController.
type AppControllerV14Adapter struct {
	*appcontrollerV14.AppController
}

// WrapAppControllerV14 wraps the v1.4 contract binding to implement types.AppController.
func WrapAppControllerV14(appController *appcontrollerV14.AppController) types.AppController {
	return &AppControllerV14Adapter{AppController: appController}
}

func (a *AppControllerV14Adapter) GetAppCreator(opts *bind.CallOpts, app common.Address) (common.Address, error) {
	return a.AppController.GetAppCreator(opts, app)
}

func (a *AppControllerV14Adapter) GetAppOperatorSetId(opts *bind.CallOpts, app common.Address) (uint32, error) {
	return a.AppController.GetAppOperatorSetId(opts, app)
}

func (a *AppControllerV14Adapter) GetAppLatestReleaseBlockNumber(opts *bind.CallOpts, app common.Address) (uint32, error) {
	return a.AppController.GetAppLatestReleaseBlockNumber(opts, app)
}

func (a *AppControllerV14Adapter) GetAppStatus(opts *bind.CallOpts, app common.Address) (uint8, error) {
	return a.AppController.GetAppStatus(opts, app)
}

func (a *AppControllerV14Adapter) ReleaseManager(opts *bind.CallOpts) (common.Address, error) {
	return a.AppController.ReleaseManager(opts)
}

func (a *AppControllerV14Adapter) ComputeAVSRegistrar(opts *bind.CallOpts) (common.Address, error) {
	return a.AppController.ComputeAVSRegistrar(opts)
}

func (a *AppControllerV14Adapter) FilterAppUpgraded(opts *bind.FilterOpts, apps []common.Address) (types.AppUpgradedIterator, error) {
	iter, err := a.AppController.FilterAppUpgraded(opts, apps)
	if err != nil {
		return nil, err
	}
	return &appUpgradedIteratorV14{iter}, nil
}

// Compile-time interface checks.
var (
	_ types.AppController       = (*AppControllerAdapter)(nil)
	_ types.AppController       = (*AppControllerV14Adapter)(nil)
	_ types.AppUpgradedIterator = (*appUpgradedIteratorV15)(nil)
	_ types.AppUpgradedIterator = (*appUpgradedIteratorV14)(nil)
)

// --- ImageAllowlist (unchanged, v1 binding) ---

// ImageAllowlistAdapter adapts the generated ImageAllowlist to our interface.
type ImageAllowlistAdapter struct {
	*imageAllowlistV1.ImageAllowlist
}

// WrapImageAllowlist wraps the contract binding to implement the ImageAllowlist interface.
func WrapImageAllowlist(imageAllowlist *imageAllowlistV1.ImageAllowlist) types.ImageAllowlist {
	return &ImageAllowlistAdapter{ImageAllowlist: imageAllowlist}
}

func (a *ImageAllowlistAdapter) IsImageAllowed(opts *bind.CallOpts, cvm uint8, pcrs []imageAllowlistV1.IImageAllowlistPCR) (bool, error) {
	return a.ImageAllowlist.IsImageAllowed(opts, cvm, pcrs)
}

func (a *ImageAllowlistAdapter) IsTCBValid(opts *bind.CallOpts, cvm uint8, tcb uint64) (bool, error) {
	return a.ImageAllowlist.IsTCBValid(opts, cvm, tcb)
}
