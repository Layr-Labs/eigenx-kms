//go:generate mockgen -source=chainclient.go -destination=mocks/mock_chainclient.go -package=mocks ChainClient

package chainclient

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	imageAllowlistV1 "github.com/Layr-Labs/eigenx-contracts/pkg/bindings/v1/ImageAllowlist"
	"github.com/Layr-Labs/eigenx-kms/pkg/types"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
)

type ChainClient interface {
	GetLatestRelease(ctx context.Context, appID string) ([32]byte, types.Env, []byte, error)
	// V3 methods for image allowlist validation
	IsImageAllowed(ctx context.Context, cvm uint8, pcrs []imageAllowlistV1.IImageAllowlistPCR) (bool, error)
	IsTCBValid(ctx context.Context, cvm uint8, tcb uint64) (bool, error)
}

type chainClientImpl struct {
	logger                     *slog.Logger
	appController              types.AppController
	imageAllowlist             types.ImageAllowlist
	releaseManagerAddress      common.Address
	computeAVSRegistrarAddress common.Address
}

// NewChainClient creates a new ChainClient.
func NewChainClient(logger *slog.Logger, appController types.AppController, imageAllowlist types.ImageAllowlist) (ChainClient, error) {
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

	return &chainClientImpl{
		logger:                     ccLogger,
		appController:              appController,
		imageAllowlist:             imageAllowlist,
		releaseManagerAddress:      releaseManagerAddress,
		computeAVSRegistrarAddress: computeAVSRegistrarAddress,
	}, nil
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
	var lastAppUpgrade *types.AppRelease
	for appUpgrades.Next() {
		release := appUpgrades.Event()
		if lastAppUpgrade == nil || release.LogIndex > lastAppUpgrade.LogIndex {
			lastAppUpgrade = release
		}
	}
	if lastAppUpgrade == nil {
		return [32]byte{}, types.Env{}, nil, fmt.Errorf("no app upgrade found for app %s at block %d", appID, releaseBlockNumberUint64)
	}

	c.logger.Debug("Found app upgraded event", "app_id", appID, "release_id", lastAppUpgrade.RmsReleaseID, "block", lastAppUpgrade.BlockNumber)

	if len(lastAppUpgrade.ArtifactDigests) != 1 {
		return [32]byte{}, types.Env{}, nil, fmt.Errorf("expected 1 artifact, got %d", len(lastAppUpgrade.ArtifactDigests))
	}
	c.logger.Debug("Release retrieved successfully", "app_id", appID, "artifact_digest", fmt.Sprintf("%x", lastAppUpgrade.ArtifactDigests[0]))

	publicEnv := types.Env{}
	err = json.Unmarshal(lastAppUpgrade.PublicEnv, &publicEnv)
	if err != nil {
		return [32]byte{}, types.Env{}, nil, fmt.Errorf("failed to unmarshal env: %v", err)
	}
	c.logger.Debug("Latest release data prepared", "app_id", appID, "public_env_vars_count", len(publicEnv))

	return lastAppUpgrade.ArtifactDigests[0], publicEnv, lastAppUpgrade.EncryptedEnv, nil
}

// IsImageAllowed checks if the given PCRs are in the on-chain image allowlist.
func (c *chainClientImpl) IsImageAllowed(ctx context.Context, cvm uint8, pcrs []imageAllowlistV1.IImageAllowlistPCR) (bool, error) {
	c.logger.Debug("Checking image allowlist", "cvm", cvm, "pcr_count", len(pcrs))

	allowed, err := c.imageAllowlist.IsImageAllowed(&bind.CallOpts{Context: ctx}, cvm, pcrs)
	if err != nil {
		return false, fmt.Errorf("failed to check image allowlist: %w", err)
	}

	c.logger.Debug("Image allowlist check result", "allowed", allowed)
	return allowed, nil
}

// IsTCBValid checks if the given TCB version meets the on-chain minimum requirement.
func (c *chainClientImpl) IsTCBValid(ctx context.Context, cvm uint8, tcb uint64) (bool, error) {
	c.logger.Debug("Checking TCB validity", "cvm", cvm, "tcb", tcb)

	valid, err := c.imageAllowlist.IsTCBValid(&bind.CallOpts{Context: ctx}, cvm, tcb)
	if err != nil {
		return false, fmt.Errorf("failed to check TCB validity: %w", err)
	}

	c.logger.Debug("TCB validity check result", "valid", valid)
	return valid, nil
}
