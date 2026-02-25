//go:generate mockgen -source=bound_attestation_evidence.go -destination=mocks/mock_bound_attestation_evidence_verifier.go -package=mocks BoundAttestationEvidenceVerifier

package attestation

import (
	"context"
	"fmt"

	"github.com/Layr-Labs/go-tpm-tools/teeverify"
)

// VerifiedAttestation holds the claims extracted from a verified raw TPM attestation.
// TEEClaims is nil for GCP Shielded VM (no TEE binding on that platform).
type VerifiedAttestation struct {
	TPMClaims *teeverify.TPMClaims
	TEEClaims *teeverify.TEEClaims
}

// BoundAttestationEvidenceVerifier verifies raw bound attestation evidence against a
// challenge and returns the extracted TPM and (where applicable) TEE claims.
type BoundAttestationEvidenceVerifier interface {
	Verify(ctx context.Context, attestationBytes, challenge []byte) (*VerifiedAttestation, error)
}

type teeverifyVerifier struct{}

// NewBoundAttestationEvidenceVerifier returns the production BoundAttestationEvidenceVerifier.
func NewBoundAttestationEvidenceVerifier() BoundAttestationEvidenceVerifier {
	return &teeverifyVerifier{}
}

func (v *teeverifyVerifier) Verify(_ context.Context, attestationBytes, challenge []byte) (*VerifiedAttestation, error) {
	attest, err := teeverify.ParseAttestation(attestationBytes)
	if err != nil {
		return nil, fmt.Errorf("attestation parsing failed: %w", err)
	}
	verified, err := attest.VerifyTPM(challenge, nil)
	if err != nil {
		return nil, fmt.Errorf("TPM verification failed: %w", err)
	}
	claims, err := verified.ExtractClaims(teeverify.ExtractOptions{PCRIndices: []uint32{4, 8, 9}})
	if err != nil {
		return nil, fmt.Errorf("failed to extract claims: %w", err)
	}
	result := &VerifiedAttestation{TPMClaims: claims}
	if attest.Platform() != teeverify.PlatformGCPShieldedVM {
		teeVerified, err := attest.VerifyBoundTEE(challenge, nil)
		if err != nil {
			return nil, fmt.Errorf("TEE verification failed: %w", err)
		}
		teeClaims, err := teeVerified.ExtractTEEClaims()
		if err != nil {
			return nil, fmt.Errorf("failed to extract TEE claims: %w", err)
		}
		result.TEEClaims = teeClaims
	}
	return result, nil
}
