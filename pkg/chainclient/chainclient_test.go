package chainclient

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"

	"github.com/Layr-Labs/eigenx-kms/pkg/chainclient/mocks"
	"github.com/Layr-Labs/eigenx-kms/pkg/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func setupLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestNewChainClient(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	logger := setupLogger()

	t.Run("success with valid inputs", func(t *testing.T) {
		mockAppController := mocks.NewMockAppController(ctrl)

		mockAppController.EXPECT().
			ReleaseManager(gomock.Any()).
			Return(common.HexToAddress("0x2222222222222222222222222222222222222222"), nil)

		mockAppController.EXPECT().
			ComputeAVSRegistrar(gomock.Any()).
			Return(common.HexToAddress("0x3333333333333333333333333333333333333333"), nil)

		client, err := NewChainClient(logger, mockAppController, nil)
		require.NoError(t, err)
		require.NotNil(t, client)
	})

	t.Run("release manager fetch failure", func(t *testing.T) {
		mockAppController := mocks.NewMockAppController(ctrl)

		mockAppController.EXPECT().
			ReleaseManager(gomock.Any()).
			Return(common.Address{}, assert.AnError)

		_, err := NewChainClient(logger, mockAppController, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to fetch release manager")
	})

	t.Run("compute avs registrar fetch failure", func(t *testing.T) {
		mockAppController := mocks.NewMockAppController(ctrl)

		mockAppController.EXPECT().
			ReleaseManager(gomock.Any()).
			Return(common.HexToAddress("0x2222222222222222222222222222222222222222"), nil)

		mockAppController.EXPECT().
			ComputeAVSRegistrar(gomock.Any()).
			Return(common.Address{}, assert.AnError)

		_, err := NewChainClient(logger, mockAppController, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to fetch compute avs registrar")
	})
}

func TestGetLatestRelease(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	logger := setupLogger()
	ctx := context.Background()
	appID := "0x1111111111111111111111111111111111111111"
	appAddress := common.HexToAddress(appID)

	t.Run("single release", func(t *testing.T) {
		mockAppController := mocks.NewMockAppController(ctrl)
		mockIterator := mocks.NewMockAppUpgradedIterator(ctrl)

		latestBlockNumber := uint32(100)

		mockAppController.EXPECT().
			GetAppLatestReleaseBlockNumber(gomock.Any(), appAddress).
			Return(latestBlockNumber, nil)

		mockAppController.EXPECT().
			FilterAppUpgraded(gomock.Any(), []common.Address{appAddress}).
			Return(mockIterator, nil)

		// Create releases at different blocks - latest should be at block 100
		digest1 := [32]byte{1}

		publicEnv1 := types.Env{"key1": "value1"}
		publicEnv1JSON, _ := json.Marshal(publicEnv1)
		encryptedEnv1 := []byte(`{"version":"1.0.0"}`)

		release1 := &types.AppRelease{
			ArtifactDigests: [][32]byte{digest1},
			PublicEnv:       publicEnv1JSON,
			EncryptedEnv:    encryptedEnv1,
			BlockNumber:     uint64(latestBlockNumber),
			LogIndex:        0,
		}

		// Mock iterator behavior: return release1, then release2, then stop
		gomock.InOrder(
			mockIterator.EXPECT().Next().Return(true),
			mockIterator.EXPECT().Event().Return(release1),
			mockIterator.EXPECT().Next().Return(false),
		)

		chainClient := &chainClientImpl{
			logger:        logger,
			appController: mockAppController,
		}

		digest, publicEnv, encryptedEnv, err := chainClient.GetLatestRelease(ctx, appID)
		require.NoError(t, err)
		require.Equal(t, digest1, digest) // Should return release2 (higher block)
		require.Equal(t, publicEnv1, publicEnv)
		require.Equal(t, encryptedEnv1, encryptedEnv)
	})

	t.Run("multiple releases on same block", func(t *testing.T) {
		mockAppController := mocks.NewMockAppController(ctrl)
		mockIterator := mocks.NewMockAppUpgradedIterator(ctrl)

		mockAppController.EXPECT().
			GetAppLatestReleaseBlockNumber(gomock.Any(), appAddress).
			Return(uint32(100), nil)

		mockAppController.EXPECT().
			FilterAppUpgraded(gomock.Any(), []common.Address{appAddress}).
			Return(mockIterator, nil)

		// Create releases at same block - highest log index should be returned
		digest1 := [32]byte{1}
		digest2 := [32]byte{2} // This should be returned (higher log index)

		publicEnv1 := types.Env{"key1": "value1"}
		publicEnv2 := types.Env{"key2": "value2"}
		publicEnv1JSON, _ := json.Marshal(publicEnv1)
		publicEnv2JSON, _ := json.Marshal(publicEnv2)
		encryptedEnv1 := []byte(`{"version":"1.0.0"}`)
		encryptedEnv2 := []byte(`{"version":"2.0.0"}`)

		release1 := &types.AppRelease{
			ArtifactDigests: [][32]byte{digest1},
			PublicEnv:       publicEnv1JSON,
			EncryptedEnv:    encryptedEnv1,
			BlockNumber:     100,
			LogIndex:        5,
		}

		release2 := &types.AppRelease{
			ArtifactDigests: [][32]byte{digest2},
			PublicEnv:       publicEnv2JSON,
			EncryptedEnv:    encryptedEnv2,
			BlockNumber:     100,
			LogIndex:        10,
		}

		// Mock iterator behavior: return release1, then release2, then stop
		gomock.InOrder(
			mockIterator.EXPECT().Next().Return(true),
			mockIterator.EXPECT().Event().Return(release1),
			mockIterator.EXPECT().Next().Return(true),
			mockIterator.EXPECT().Event().Return(release2),
			mockIterator.EXPECT().Next().Return(false),
		)

		chainClient := &chainClientImpl{
			logger:        logger,
			appController: mockAppController,
		}

		digest, publicEnv, encryptedEnv, err := chainClient.GetLatestRelease(ctx, appID)
		require.NoError(t, err)
		require.Equal(t, digest2, digest) // Should return release2 (higher log index)
		require.Equal(t, publicEnv2, publicEnv)
		require.Equal(t, encryptedEnv2, encryptedEnv)
	})

	t.Run("app latest release block number fetch fails", func(t *testing.T) {
		mockAppController := mocks.NewMockAppController(ctrl)

		mockAppController.EXPECT().
			GetAppLatestReleaseBlockNumber(gomock.Any(), appAddress).
			Return(uint32(0), assert.AnError)

		chainClient := &chainClientImpl{
			logger:        logger,
			appController: mockAppController,
		}

		_, _, _, err := chainClient.GetLatestRelease(ctx, appID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get app latest release block number")
	})

	t.Run("filter app upgraded fails", func(t *testing.T) {
		mockAppController := mocks.NewMockAppController(ctrl)

		mockAppController.EXPECT().
			GetAppLatestReleaseBlockNumber(gomock.Any(), appAddress).
			Return(uint32(100), nil)

		mockAppController.EXPECT().
			FilterAppUpgraded(gomock.Any(), []common.Address{appAddress}).
			Return(nil, assert.AnError)

		chainClient := &chainClientImpl{
			logger:        logger,
			appController: mockAppController,
		}

		_, _, _, err := chainClient.GetLatestRelease(ctx, appID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to filter app upgraded")
	})

	t.Run("no app upgrade events", func(t *testing.T) {
		mockAppController := mocks.NewMockAppController(ctrl)
		mockIterator := mocks.NewMockAppUpgradedIterator(ctrl)

		mockAppController.EXPECT().
			GetAppLatestReleaseBlockNumber(gomock.Any(), appAddress).
			Return(uint32(100), nil)

		mockAppController.EXPECT().
			FilterAppUpgraded(gomock.Any(), []common.Address{appAddress}).
			Return(mockIterator, nil)

		// Mock iterator that immediately returns false (no events)
		mockIterator.EXPECT().Next().Return(false)

		chainClient := &chainClientImpl{
			logger:        logger,
			appController: mockAppController,
		}

		_, _, _, err := chainClient.GetLatestRelease(ctx, appID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no app upgrade found")
	})
}

func TestNewAppController(t *testing.T) {
	t.Parallel()

	// A nil backend is sufficient: NewAppController only constructs the bound
	// contract (no RPC calls happen at construction time).
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// isType reports whether ctrl's dynamic type matches T (comma-ok, no panic).
	isV15 := func(ctrl types.AppController) bool { _, ok := ctrl.(*AppControllerAdapter); return ok }
	isV14 := func(ctrl types.AppController) bool { _, ok := ctrl.(*AppControllerV14Adapter); return ok }

	tests := []struct {
		name        string
		version     string
		wantType    func(types.AppController) bool
		errContains string // non-empty => expect an error containing this substring
	}{
		{name: "v1.5 selected", version: ReleaseAbiV15, wantType: isV15},
		{name: "empty defaults to v1.5", version: "", wantType: isV15},
		{name: "v1.4 selected", version: ReleaseAbiV14, wantType: isV14},
		{name: "unknown version errors", version: "v9.9", errContains: "unknown release ABI version"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl, err := NewAppController(tt.version, addr, nil)

			if tt.errContains != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errContains)
				require.Nil(t, ctrl)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, ctrl)
			require.True(t, tt.wantType(ctrl), "unexpected adapter type for version %q", tt.version)
		})
	}
}
