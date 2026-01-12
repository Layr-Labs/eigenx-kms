package policy

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/Layr-Labs/eigenx-contracts/pkg/bindings/v1/ImageAllowlist"
	"github.com/Layr-Labs/eigenx-kms/pkg/policy/mocks"
	"github.com/Layr-Labs/go-tpm-tools/teeverify"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

const testProjectID = "test-project-id"

func setupLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestNewPolicyChecker(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAllowlist := mocks.NewMockImageAllowlistChecker(ctrl)
	logger := setupLogger()

	pc := NewPolicyChecker(logger, testProjectID, mockAllowlist, false)

	require.NotNil(t, pc)
	require.Equal(t, testProjectID, pc.projectID)
	require.Equal(t, false, pc.debugMode)
	require.NotNil(t, pc.imageAllowlistChecker)
}

func TestCheckDebugMode(t *testing.T) {
	logger := setupLogger()

	t.Run("passes when debugMode=true", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAllowlist := mocks.NewMockImageAllowlistChecker(ctrl)
		pc := NewPolicyChecker(logger, testProjectID, mockAllowlist, true)

		// Non-hardened image should pass in debug mode
		claims := &teeverify.Claims{
			Hardened: false,
			TDX:      &teeverify.TDXClaims{Attributes: teeverify.TDAttributes{Debug: true}},
		}

		err := pc.checkDebugMode(claims, teeverify.PlatformTDX)
		require.NoError(t, err)
	})

	t.Run("rejects non-hardened image when debugMode=false", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAllowlist := mocks.NewMockImageAllowlistChecker(ctrl)
		pc := NewPolicyChecker(logger, testProjectID, mockAllowlist, false)

		claims := &teeverify.Claims{
			Hardened: false,
		}

		err := pc.checkDebugMode(claims, teeverify.PlatformTDX)
		require.Error(t, err)
		require.Contains(t, err.Error(), "non-hardened Confidential Space image")
	})

	t.Run("rejects TDX debug mode when debugMode=false", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAllowlist := mocks.NewMockImageAllowlistChecker(ctrl)
		pc := NewPolicyChecker(logger, testProjectID, mockAllowlist, false)

		claims := &teeverify.Claims{
			Hardened: true,
			TDX:      &teeverify.TDXClaims{Attributes: teeverify.TDAttributes{Debug: true}},
		}

		err := pc.checkDebugMode(claims, teeverify.PlatformTDX)
		require.Error(t, err)
		require.Contains(t, err.Error(), "TD is in DEBUG mode")
	})

	t.Run("rejects SEV-SNP debug mode when debugMode=false", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAllowlist := mocks.NewMockImageAllowlistChecker(ctrl)
		pc := NewPolicyChecker(logger, testProjectID, mockAllowlist, false)

		claims := &teeverify.Claims{
			Hardened: true,
			SevSnp:   &teeverify.SevSnpClaims{Policy: teeverify.SevSnpPolicy{Debug: true}},
		}

		err := pc.checkDebugMode(claims, teeverify.PlatformSevSnp)
		require.Error(t, err)
		require.Contains(t, err.Error(), "guest is in DEBUG mode")
	})

	t.Run("passes hardened non-debug TDX", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAllowlist := mocks.NewMockImageAllowlistChecker(ctrl)
		pc := NewPolicyChecker(logger, testProjectID, mockAllowlist, false)

		claims := &teeverify.Claims{
			Hardened: true,
			TDX:      &teeverify.TDXClaims{Attributes: teeverify.TDAttributes{Debug: false}},
		}

		err := pc.checkDebugMode(claims, teeverify.PlatformTDX)
		require.NoError(t, err)
	})

	t.Run("passes hardened non-debug SEV-SNP", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAllowlist := mocks.NewMockImageAllowlistChecker(ctrl)
		pc := NewPolicyChecker(logger, testProjectID, mockAllowlist, false)

		claims := &teeverify.Claims{
			Hardened: true,
			SevSnp:   &teeverify.SevSnpClaims{Policy: teeverify.SevSnpPolicy{Debug: false}},
		}

		err := pc.checkDebugMode(claims, teeverify.PlatformSevSnp)
		require.NoError(t, err)
	})
}

func TestCheckTCB(t *testing.T) {
	ctx := context.Background()
	logger := setupLogger()

	t.Run("valid TDX TCB passes", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAllowlist := mocks.NewMockImageAllowlistChecker(ctrl)
		pc := NewPolicyChecker(logger, testProjectID, mockAllowlist, false)

		// TeeTcbSvn: [minor, major, microcode, ...]
		claims := &teeverify.Claims{
			TDX: &teeverify.TDXClaims{
				TeeTcbSvn: [16]byte{2, 1, 3}, // minor=2, major=1, microcode=3 -> TCB = (1<<16)|(2<<8)|3 = 65795
			},
		}

		// Expected TCB = major<<16 | minor<<8 | microcode = 1<<16 | 2<<8 | 3 = 65795
		expectedTCB := uint64(1<<16 | 2<<8 | 3)
		mockAllowlist.EXPECT().
			IsTCBValid(gomock.Any(), uint8(teeverify.PlatformTDX), expectedTCB).
			Return(true, nil)

		err := pc.checkTCB(ctx, claims, teeverify.PlatformTDX)
		require.NoError(t, err)
	})

	t.Run("valid SEV-SNP TCB passes", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAllowlist := mocks.NewMockImageAllowlistChecker(ctrl)
		pc := NewPolicyChecker(logger, testProjectID, mockAllowlist, false)

		claims := &teeverify.Claims{
			SevSnp: &teeverify.SevSnpClaims{
				CurrentTcb: 12345,
			},
		}

		mockAllowlist.EXPECT().
			IsTCBValid(gomock.Any(), uint8(teeverify.PlatformSevSnp), uint64(12345)).
			Return(true, nil)

		err := pc.checkTCB(ctx, claims, teeverify.PlatformSevSnp)
		require.NoError(t, err)
	})

	t.Run("invalid TDX TCB rejected", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAllowlist := mocks.NewMockImageAllowlistChecker(ctrl)
		pc := NewPolicyChecker(logger, testProjectID, mockAllowlist, false)

		claims := &teeverify.Claims{
			TDX: &teeverify.TDXClaims{
				TeeTcbSvn: [16]byte{1, 0, 0}, // Old version
			},
		}

		mockAllowlist.EXPECT().
			IsTCBValid(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(false, nil)

		err := pc.checkTCB(ctx, claims, teeverify.PlatformTDX)
		require.Error(t, err)
		require.Contains(t, err.Error(), "TCB version does not meet minimum requirement")
	})

	t.Run("TCB check error propagates", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAllowlist := mocks.NewMockImageAllowlistChecker(ctrl)
		pc := NewPolicyChecker(logger, testProjectID, mockAllowlist, false)

		claims := &teeverify.Claims{
			TDX: &teeverify.TDXClaims{},
		}

		mockAllowlist.EXPECT().
			IsTCBValid(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(false, errors.New("chain error"))

		err := pc.checkTCB(ctx, claims, teeverify.PlatformTDX)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to check TCB")
		require.Contains(t, err.Error(), "chain error")
	})

	t.Run("missing TDX claims returns error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAllowlist := mocks.NewMockImageAllowlistChecker(ctrl)
		pc := NewPolicyChecker(logger, testProjectID, mockAllowlist, false)

		claims := &teeverify.Claims{
			TDX: nil,
		}

		err := pc.checkTCB(ctx, claims, teeverify.PlatformTDX)
		require.Error(t, err)
		require.Contains(t, err.Error(), "TDX claims missing")
	})

	t.Run("missing SEV-SNP claims returns error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAllowlist := mocks.NewMockImageAllowlistChecker(ctrl)
		pc := NewPolicyChecker(logger, testProjectID, mockAllowlist, false)

		claims := &teeverify.Claims{
			SevSnp: nil,
		}

		err := pc.checkTCB(ctx, claims, teeverify.PlatformSevSnp)
		require.Error(t, err)
		require.Contains(t, err.Error(), "SEV-SNP claims missing")
	})

	t.Run("unknown platform returns error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAllowlist := mocks.NewMockImageAllowlistChecker(ctrl)
		pc := NewPolicyChecker(logger, testProjectID, mockAllowlist, false)

		claims := &teeverify.Claims{}

		err := pc.checkTCB(ctx, claims, teeverify.PlatformUnknown)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unknown platform")
	})
}

func TestCheckPCRAllowlist(t *testing.T) {
	ctx := context.Background()
	logger := setupLogger()

	t.Run("allowed image passes", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAllowlist := mocks.NewMockImageAllowlistChecker(ctrl)
		pc := NewPolicyChecker(logger, testProjectID, mockAllowlist, false)

		claims := &teeverify.Claims{
			PCRs: map[uint32][32]byte{
				4: {0x01, 0x02, 0x03},
				8: {0x04, 0x05, 0x06},
				9: {0x07, 0x08, 0x09},
			},
		}

		mockAllowlist.EXPECT().
			IsImageAllowed(gomock.Any(), uint8(teeverify.PlatformTDX), gomock.Any()).
			DoAndReturn(func(ctx context.Context, cvm uint8, pcrs []ImageAllowlist.IImageAllowlistPCR) (bool, error) {
				// Verify PCRs are sorted
				require.Len(t, pcrs, 3)
				require.Equal(t, uint8(4), pcrs[0].Index)
				require.Equal(t, uint8(8), pcrs[1].Index)
				require.Equal(t, uint8(9), pcrs[2].Index)
				return true, nil
			})

		err := pc.checkPCRAllowlist(ctx, claims, teeverify.PlatformTDX)
		require.NoError(t, err)
	})

	t.Run("non-allowed image rejected", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAllowlist := mocks.NewMockImageAllowlistChecker(ctrl)
		pc := NewPolicyChecker(logger, testProjectID, mockAllowlist, false)

		claims := &teeverify.Claims{
			PCRs: map[uint32][32]byte{
				4: {0x01},
			},
		}

		mockAllowlist.EXPECT().
			IsImageAllowed(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(false, nil)

		err := pc.checkPCRAllowlist(ctx, claims, teeverify.PlatformTDX)
		require.Error(t, err)
		require.Contains(t, err.Error(), "base image not in allowlist")
	})

	t.Run("allowlist check error propagates", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAllowlist := mocks.NewMockImageAllowlistChecker(ctrl)
		pc := NewPolicyChecker(logger, testProjectID, mockAllowlist, false)

		claims := &teeverify.Claims{
			PCRs: map[uint32][32]byte{},
		}

		mockAllowlist.EXPECT().
			IsImageAllowed(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(false, errors.New("contract error"))

		err := pc.checkPCRAllowlist(ctx, claims, teeverify.PlatformTDX)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to check image allowlist")
		require.Contains(t, err.Error(), "contract error")
	})
}

func TestPcrMapToContractPCRs(t *testing.T) {
	t.Run("converts map correctly and sorts by index", func(t *testing.T) {
		pcrs := map[uint32][32]byte{
			9: {0x09},
			4: {0x04},
			8: {0x08},
		}

		result := pcrMapToContractPCRs(pcrs)

		require.Len(t, result, 3)
		// Should be sorted by index
		require.Equal(t, uint8(4), result[0].Index)
		require.Equal(t, uint8(8), result[1].Index)
		require.Equal(t, uint8(9), result[2].Index)
		// Values should match
		require.Equal(t, [32]byte{0x04}, result[0].Value)
		require.Equal(t, [32]byte{0x08}, result[1].Value)
		require.Equal(t, [32]byte{0x09}, result[2].Value)
	})

	t.Run("handles empty map", func(t *testing.T) {
		pcrs := map[uint32][32]byte{}
		result := pcrMapToContractPCRs(pcrs)
		require.Empty(t, result)
	})

	t.Run("handles single entry", func(t *testing.T) {
		pcrs := map[uint32][32]byte{
			4: {0x01, 0x02, 0x03, 0x04},
		}

		result := pcrMapToContractPCRs(pcrs)

		require.Len(t, result, 1)
		require.Equal(t, uint8(4), result[0].Index)
		require.Equal(t, [32]byte{0x01, 0x02, 0x03, 0x04}, result[0].Value)
	})
}

func TestCheckPolicies(t *testing.T) {
	ctx := context.Background()
	logger := setupLogger()

	t.Run("returns error when GCE claims missing", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAllowlist := mocks.NewMockImageAllowlistChecker(ctrl)
		pc := NewPolicyChecker(logger, testProjectID, mockAllowlist, false)

		claims := &teeverify.Claims{
			Hardened: true,
			GCE:      nil,
		}

		err := pc.CheckPolicies(ctx, claims, teeverify.PlatformTDX)
		require.Error(t, err)
		require.Contains(t, err.Error(), "GCE claims missing")
	})

	t.Run("returns error when project ID mismatch", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAllowlist := mocks.NewMockImageAllowlistChecker(ctrl)
		pc := NewPolicyChecker(logger, testProjectID, mockAllowlist, false)

		claims := &teeverify.Claims{
			Hardened: true,
			GCE: &teeverify.GCEInfo{
				ProjectID: "wrong-project",
			},
		}

		err := pc.CheckPolicies(ctx, claims, teeverify.PlatformTDX)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid project_id")
	})

	t.Run("returns error when debug mode check fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAllowlist := mocks.NewMockImageAllowlistChecker(ctrl)
		pc := NewPolicyChecker(logger, testProjectID, mockAllowlist, false)

		claims := &teeverify.Claims{
			Hardened: false, // This will fail debug mode check
			GCE: &teeverify.GCEInfo{
				ProjectID: testProjectID,
			},
		}

		err := pc.CheckPolicies(ctx, claims, teeverify.PlatformTDX)
		require.Error(t, err)
		require.Contains(t, err.Error(), "non-hardened Confidential Space image")
	})

	// Note: Full CheckPolicies success path testing requires mocking teeverify.VerifyMRTD
	// which is a package-level function. The individual component tests above cover
	// the mockable parts. Integration tests with real attestations would cover the full path.
}

func TestVerifyFirmware(t *testing.T) {
	logger := setupLogger()

	t.Run("returns error when TDX claims missing for TDX platform", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAllowlist := mocks.NewMockImageAllowlistChecker(ctrl)
		pc := NewPolicyChecker(logger, testProjectID, mockAllowlist, false)

		claims := &teeverify.Claims{
			TDX: nil,
		}

		err := pc.verifyFirmware(context.Background(), claims, teeverify.PlatformTDX)
		require.Error(t, err)
		require.Contains(t, err.Error(), "TDX claims missing")
	})

	t.Run("returns error when SEV-SNP claims missing for SEV-SNP platform", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAllowlist := mocks.NewMockImageAllowlistChecker(ctrl)
		pc := NewPolicyChecker(logger, testProjectID, mockAllowlist, false)

		claims := &teeverify.Claims{
			SevSnp: nil,
		}

		err := pc.verifyFirmware(context.Background(), claims, teeverify.PlatformSevSnp)
		require.Error(t, err)
		require.Contains(t, err.Error(), "SEV-SNP claims missing")
	})

	t.Run("returns error for unknown platform", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAllowlist := mocks.NewMockImageAllowlistChecker(ctrl)
		pc := NewPolicyChecker(logger, testProjectID, mockAllowlist, false)

		claims := &teeverify.Claims{}

		err := pc.verifyFirmware(context.Background(), claims, teeverify.PlatformUnknown)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unknown platform")
	})

	// Note: Testing actual firmware verification (VerifyMRTD, VerifySevSnpMeasurement)
	// requires network access to Google's endorsement servers. Those are tested
	// via integration tests or by mocking at a higher level.
}
