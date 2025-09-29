package chainclient

import (
	appcontrollerV1 "github.com/Layr-Labs/eigenx-contracts/pkg/bindings/v1/AppController"
	"github.com/Layr-Labs/eigenx-kms/pkg/types"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
)

// AppUpgradedIteratorAdapter adapts the generated iterator to our interface
type AppUpgradedIteratorAdapter struct {
	*appcontrollerV1.AppControllerAppUpgradedIterator
}

func (a *AppUpgradedIteratorAdapter) Next() bool {
	return a.AppControllerAppUpgradedIterator.Next()
}

func (a *AppUpgradedIteratorAdapter) Event() *appcontrollerV1.AppControllerAppUpgraded {
	return a.AppControllerAppUpgradedIterator.Event
}

// AppControllerAdapter adapts the generated AppController to our interface
type AppControllerAdapter struct {
	*appcontrollerV1.AppController
}

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
	return &AppUpgradedIteratorAdapter{iter}, nil
}
