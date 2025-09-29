//go:generate mockgen -source=chainclient.go -destination=mocks/mock_chainclient.go -package=mocks ChainClient

package chainclient

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	appcontrollerV1 "github.com/Layr-Labs/eigenx-contracts/pkg/bindings/v1/AppController"
	"github.com/Layr-Labs/eigenx-kms/pkg/types"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
)

type ChainClient interface {
	GetLatestRelease(ctx context.Context, appID string) ([32]byte, types.Env, []byte, error)
}

type chainClientImpl struct {
	logger                     *slog.Logger
	appController              types.AppController
	releaseManagerAddress      common.Address
	computeAVSRegistrarAddress common.Address
}

func NewChainClient(logger *slog.Logger, appController types.AppController) (ChainClient, error) {
	ccLogger := logger.With("component", "chain_client")

	releaseManagerAddress, err := appController.ReleaseManager(&bind.CallOpts{})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch release manager: %v", err)
	}

	computeAVSRegistrarAddress, err := appController.ComputeAVSRegistrar(&bind.CallOpts{})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch compute avs registrar: %v", err)
	}

	ccLogger.Info("Chain client initialized successfully",
		"release_manager_address", releaseManagerAddress,
		"compute_avs_registrar_address", computeAVSRegistrarAddress)

	return &chainClientImpl{logger: ccLogger, appController: appController, releaseManagerAddress: releaseManagerAddress, computeAVSRegistrarAddress: computeAVSRegistrarAddress}, nil
}

func (c *chainClientImpl) GetLatestRelease(ctx context.Context, appID string) ([32]byte, types.Env, []byte, error) {
	c.logger.Debug("Getting latest release", "app_id", appID)

	appAddress := common.HexToAddress(appID)
	c.logger.Debug("Fetching app latest release block number", "app_address", appAddress)
	latestReleaseBlockNumber, err := c.appController.GetAppLatestReleaseBlockNumber(&bind.CallOpts{Context: ctx}, appAddress)
	if err != nil {
		return [32]byte{}, types.Env{}, nil, fmt.Errorf("failed to get app latest release block number: %v", err)
	}
	c.logger.Debug("App latest release block number fetched successfully", "block_number", latestReleaseBlockNumber)

	// get the latest release deployed at the block number
	releaseBlockNumberUint64 := uint64(latestReleaseBlockNumber)
	c.logger.Debug("Filtering app upgraded events", "block_number", releaseBlockNumberUint64, "app_address", appAddress)
	appUpgrades, err := c.appController.FilterAppUpgraded(&bind.FilterOpts{Context: ctx, Start: releaseBlockNumberUint64, End: &releaseBlockNumberUint64}, []common.Address{appAddress})
	if err != nil {
		return [32]byte{}, types.Env{}, nil, fmt.Errorf("failed to filter app upgraded: %v", err)
	}
	c.logger.Debug("App upgraded events filtered successfully")

	// get the latest release deployed of all returned logs
	var lastAppUpgrade *appcontrollerV1.AppControllerAppUpgraded
	for appUpgrades.Next() {
		release := appUpgrades.Event()
		if lastAppUpgrade == nil {
			lastAppUpgrade = release
		} else if release.Raw.Index > lastAppUpgrade.Raw.Index {
			lastAppUpgrade = release
		}
	}
	if lastAppUpgrade == nil {
		return [32]byte{}, types.Env{}, nil, fmt.Errorf("no app upgrade found for app %s at block %d", appID, releaseBlockNumberUint64)
	}

	release := lastAppUpgrade.Release
	c.logger.Debug("Found app upgraded event", "app_id", appID, "release_id", lastAppUpgrade.RmsReleaseId, "block", lastAppUpgrade.Raw.BlockNumber)

	if len(release.RmsRelease.Artifacts) != 1 {
		return [32]byte{}, types.Env{}, nil, fmt.Errorf("expected 1 artifact, got %d", len(release.RmsRelease.Artifacts))
	}
	c.logger.Debug("Release retrieved successfully", "app_id", appID, "artifact_digest", fmt.Sprintf("%x", release.RmsRelease.Artifacts[0].Digest))

	publicEnv := types.Env{}
	err = json.Unmarshal(release.PublicEnv, &publicEnv)
	if err != nil {
		return [32]byte{}, types.Env{}, nil, fmt.Errorf("failed to unmarshal env: %v", err)
	}
	c.logger.Debug("Latest release data prepared", "app_id", appID, "public_env_vars_count", len(publicEnv))

	return release.RmsRelease.Artifacts[0].Digest, publicEnv, release.EncryptedEnv, nil
}
