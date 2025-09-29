//go:generate mockgen -destination=../chainclient/mocks/mock_app_interfaces.go -package=mocks . AppController,AppUpgradedIterator
package types

import (
	appcontrollerV1 "github.com/Layr-Labs/eigenx-contracts/pkg/bindings/v1/AppController"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
)

type AppUpgradedIterator interface {
	Next() bool
	Event() *appcontrollerV1.AppControllerAppUpgraded
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
