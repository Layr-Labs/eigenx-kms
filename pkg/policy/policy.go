//go:generate mockgen -source=policy.go -destination=mocks/mock_policy.go -package=mocks PolicyCheckerInterface

package policy

import (
	"context"
	"fmt"
	"log/slog"
	"sort"

	"github.com/Layr-Labs/eigenx-contracts/pkg/bindings/v1/ImageAllowlist"
	"github.com/Layr-Labs/go-tpm-tools/teeverify"
)

// ImageAllowlistChecker defines the interface for checking image allowlist and TCB.
type ImageAllowlistChecker interface {
	IsImageAllowed(ctx context.Context, cvm uint8, pcrs []ImageAllowlist.IImageAllowlistPCR) (bool, error)
	IsTCBValid(ctx context.Context, cvm uint8, tcb uint64) (bool, error)
}

// PolicyCheckerInterface defines the interface for policy checking.
type PolicyCheckerInterface interface {
	CheckPolicies(ctx context.Context, claims *teeverify.Claims, platform teeverify.Platform) error
}

// PolicyChecker implements policy checking for TEE attestations.
type PolicyChecker struct {
	logger                *slog.Logger
	projectID             string
	imageAllowlistChecker ImageAllowlistChecker
	debugMode             bool
}

// NewPolicyChecker creates a new PolicyChecker instance.
func NewPolicyChecker(
	logger *slog.Logger,
	projectID string,
	imageAllowlistChecker ImageAllowlistChecker,
	debugMode bool,
) *PolicyChecker {
	return &PolicyChecker{
		logger:                logger.With("component", "policy_checker"),
		projectID:             projectID,
		imageAllowlistChecker: imageAllowlistChecker,
		debugMode:             debugMode,
	}
}

// CheckPolicies verifies that the claims meet all policy requirements.
func (pc *PolicyChecker) CheckPolicies(ctx context.Context, claims *teeverify.Claims, platform teeverify.Platform) error {
	// Debug mode rejection
	if err := pc.checkDebugMode(claims, platform); err != nil {
		return err
	}

	// Project ID validation
	if claims.GCE == nil {
		return fmt.Errorf("GCE claims missing")
	}
	if claims.GCE.ProjectID != pc.projectID {
		return fmt.Errorf("invalid project_id: %s, expected %s", claims.GCE.ProjectID, pc.projectID)
	}
	pc.logger.Debug("Project ID validated", "project_id", claims.GCE.ProjectID)

	// Firmware endorsement verification
	if err := pc.verifyFirmware(ctx, claims, platform); err != nil {
		return fmt.Errorf("firmware verification failed: %w", err)
	}
	pc.logger.Debug("Firmware endorsement verified")

	// TCB version check (on-chain)
	if err := pc.checkTCB(ctx, claims, platform); err != nil {
		return fmt.Errorf("TCB check failed: %w", err)
	}
	pc.logger.Debug("TCB version validated")

	// PCR allowlist check (on-chain)
	if err := pc.checkPCRAllowlist(ctx, claims, platform); err != nil {
		return fmt.Errorf("PCR allowlist check failed: %w", err)
	}
	pc.logger.Debug("PCR allowlist validated")

	return nil
}

// checkDebugMode rejects debug mode VMs and non-hardened images unless debugMode is enabled.
func (pc *PolicyChecker) checkDebugMode(claims *teeverify.Claims, platform teeverify.Platform) error {
	if pc.debugMode {
		pc.logger.Debug("Debug mode enabled, skipping debug mode rejection")
		return nil
	}

	// Reject debug Confidential Space images
	if !claims.Hardened {
		return fmt.Errorf("non-hardened Confidential Space image - rejecting")
	}

	// Check TEE debug flags
	switch platform {
	case teeverify.PlatformTDX:
		if claims.TDX != nil && claims.TDX.Attributes.Debug {
			return fmt.Errorf("TD is in DEBUG mode - rejecting")
		}
	case teeverify.PlatformSevSnp:
		if claims.SevSnp != nil && claims.SevSnp.Policy.Debug {
			return fmt.Errorf("guest is in DEBUG mode - rejecting")
		}
	}

	pc.logger.Debug("Debug mode check passed")
	return nil
}

// verifyFirmware verifies the firmware measurement against Google's endorsements.
func (pc *PolicyChecker) verifyFirmware(ctx context.Context, claims *teeverify.Claims, platform teeverify.Platform) error {
	switch platform {
	case teeverify.PlatformTDX:
		if claims.TDX == nil {
			return fmt.Errorf("TDX claims missing for TDX platform")
		}
		_, err := teeverify.VerifyMRTD(ctx, claims.TDX.MRTD[:])
		return err
	case teeverify.PlatformSevSnp:
		if claims.SevSnp == nil {
			return fmt.Errorf("SEV-SNP claims missing for SEV-SNP platform")
		}
		_, err := teeverify.VerifySevSnpMeasurement(ctx, claims.SevSnp.Measurement[:])
		return err
	default:
		return fmt.Errorf("unknown platform: %d", platform)
	}
}

// checkTCB verifies the TCB version against the on-chain minimum.
func (pc *PolicyChecker) checkTCB(ctx context.Context, claims *teeverify.Claims, platform teeverify.Platform) error {
	cvm := uint8(platform)
	var tcb uint64

	switch platform {
	case teeverify.PlatformTDX:
		if claims.TDX == nil {
			return fmt.Errorf("TDX claims missing for TCB check")
		}
		// Pack TCB from TeeTcbSvn: major<<16 | minor<<8 | microcode
		major := uint64(claims.TDX.TeeTcbSvn[1])
		minor := uint64(claims.TDX.TeeTcbSvn[0])
		microcode := uint64(claims.TDX.TeeTcbSvn[2])
		tcb = major<<16 | minor<<8 | microcode
	case teeverify.PlatformSevSnp:
		if claims.SevSnp == nil {
			return fmt.Errorf("SEV-SNP claims missing for TCB check")
		}
		tcb = claims.SevSnp.CurrentTcb
	default:
		return fmt.Errorf("unknown platform: %d", platform)
	}

	valid, err := pc.imageAllowlistChecker.IsTCBValid(ctx, cvm, tcb)
	if err != nil {
		return fmt.Errorf("failed to check TCB: %w", err)
	}
	if !valid {
		return fmt.Errorf("TCB version does not meet minimum requirement")
	}

	return nil
}

// checkPCRAllowlist verifies the PCRs against the on-chain allowlist.
func (pc *PolicyChecker) checkPCRAllowlist(ctx context.Context, claims *teeverify.Claims, platform teeverify.Platform) error {
	cvm := uint8(platform)
	pcrs := pcrMapToContractPCRs(claims.PCRs)

	allowed, err := pc.imageAllowlistChecker.IsImageAllowed(ctx, cvm, pcrs)
	if err != nil {
		return fmt.Errorf("failed to check image allowlist: %w", err)
	}
	if !allowed {
		return fmt.Errorf("base image not in allowlist")
	}

	return nil
}

// pcrMapToContractPCRs converts a PCR map to a sorted slice of contract PCR structs.
func pcrMapToContractPCRs(pcrs map[uint32][32]byte) []ImageAllowlist.IImageAllowlistPCR {
	result := make([]ImageAllowlist.IImageAllowlistPCR, 0, len(pcrs))
	for idx, val := range pcrs {
		result = append(result, ImageAllowlist.IImageAllowlistPCR{
			Index: uint8(idx),
			Value: val,
		})
	}
	// Sort by index for deterministic hashing
	sort.Slice(result, func(i, j int) bool {
		return result[i].Index < result[j].Index
	})
	return result
}
