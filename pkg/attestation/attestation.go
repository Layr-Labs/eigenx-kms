//go:generate mockgen -source=attestation.go -destination=mocks/mock_attestation.go -package=mocks AttestationVerifierInterface

package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const (
	instanceNameDelimiter     = "-"
	confidentialSpaceJWKURL   = "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com"
	confidentialSpaceIssuer   = "https://confidentialcomputing.googleapis.com"
	confidentialSpaceAudience = "https://sts.googleapis.com"
)

type AttestationVerifierInterface interface {
	VerifyAttestation(ctx context.Context, tokenString string) (*AttestationClaims, error)
}

type AttestationClaims struct {
	AppID       string   `json:"app_id"`
	ImageDigest string   `json:"image_digest"`
	Nonces      []string `json:"nonces"`
	jwt.Token
}

// Structured types for attestation token parsing
type ConfidentialSpaceToken struct {
	Issuer      string   `json:"iss"`
	Audience    any      `json:"aud"`
	Exp         int64    `json:"exp"`
	Nbf         int64    `json:"nbf"`
	EatNonces   []string `json:"eat_nonces,omitempty"`
	SwName      string   `json:"swname"`
	AttesterTCB []string `json:"attester_tcb"`
	HwModel     string   `json:"hwmodel"`
	DbgStat     string   `json:"dbgstat"`
	SwVersion   []string `json:"swversion"`
	SubMods     SubMods  `json:"submods"`
}

type SubMods struct {
	Container         Container         `json:"container"`
	GCE               GCE               `json:"gce"`
	ConfidentialSpace ConfidentialSpace `json:"confidential_space"`
}

type ConfidentialSpace struct {
	SupportAttributes []string `json:"support_attributes"`
}

type Container struct {
	ImageDigest string `json:"image_digest"`
}

type GCE struct {
	Zone         string `json:"zone"`
	ProjectID    string `json:"project_id"`
	InstanceName string `json:"instance_name"`
}

type AttestationVerifier struct {
	logger    *slog.Logger
	jwksCache jwk.Set
	projectID string
	debugMode bool
}

func NewAttestationVerifier(ctx context.Context, logger *slog.Logger, projectID string, refreshInterval time.Duration, debugMode bool) (*AttestationVerifier, error) {
	avLogger := logger.With("component", "attestation_verifier")
	avLogger.Debug("Initializing attestation verifier", "project_id", projectID, "refresh_interval", refreshInterval)

	avLogger.Debug("Creating JWK cache", "jwk_url", confidentialSpaceJWKURL)
	jwksCache, err := NewJWKCache(ctx, confidentialSpaceJWKURL, refreshInterval)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK cache: %w", err)
	}
	avLogger.Info("Attestation verifier initialized successfully", "project_id", projectID)

	return &AttestationVerifier{
		logger:    avLogger,
		projectID: projectID,
		jwksCache: jwksCache,
		debugMode: debugMode,
	}, nil
}

func (av *AttestationVerifier) VerifyAttestation(ctx context.Context, tokenString string) (*AttestationClaims, error) {
	av.logger.Debug("Starting attestation verification", "token_length", len(tokenString))

	// Parse and verify the token
	av.logger.Debug("Parsing and verifying JWT token")
	token, err := jwt.Parse(
		[]byte(tokenString),
		jwt.WithKeySet(av.jwksCache),
		jwt.WithValidate(true),
		jwt.WithIssuer(confidentialSpaceIssuer),
		jwt.WithAudience(confidentialSpaceAudience),
	)
	if err != nil {
		return nil, fmt.Errorf("token parsing/verification failed: %w", err)
	}

	csToken := &ConfidentialSpaceToken{}

	tokenBytes, err := json.Marshal(token)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal token to JSON: %w", err)
	}
	if err := json.Unmarshal(tokenBytes, csToken); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token JSON to ConfidentialSpaceToken: %w", err)
	}

	err = av.validateConfidentialSpaceToken(csToken)
	if err != nil {
		return nil, err
	}

	appID, err := extractAppIDFromInstanceName(csToken.SubMods.GCE.InstanceName)
	if err != nil {
		return nil, fmt.Errorf("failed to extract app ID from instance name: %w", err)
	}

	// Ensure Nonces is an empty slice instead of nil if not present
	nonces := csToken.EatNonces
	if nonces == nil {
		nonces = []string{}
	}

	result := &AttestationClaims{
		AppID:       appID,
		ImageDigest: csToken.SubMods.Container.ImageDigest,
		Nonces:      nonces,
	}

	av.logger.Debug("Attestation claims extracted", "app_id", appID, "image_digest", csToken.SubMods.Container.ImageDigest)
	return result, nil
}

// validateConfidentialSpaceToken validates the business logic of the token claims
func (av *AttestationVerifier) validateConfidentialSpaceToken(csToken *ConfidentialSpaceToken) error {
	// Validate software name
	if csToken.SwName != "CONFIDENTIAL_SPACE" {
		return fmt.Errorf("invalid software name: %s. Expected CONFIDENTIAL_SPACE", csToken.SwName)
	}
	av.logger.Debug("Software name validated", "sw_name", csToken.SwName)

	// Validate attester TCB
	if len(csToken.AttesterTCB) != 1 || csToken.AttesterTCB[0] != "INTEL" {
		return fmt.Errorf("invalid attester_tcb: %v. Expected [\"INTEL\"]", csToken.AttesterTCB)
	}
	av.logger.Debug("Attester TCB validated", "attester_tcb", csToken.AttesterTCB)

	// Validate hardware model
	if csToken.HwModel != "GCP_INTEL_TDX" {
		return fmt.Errorf("invalid hwmodel: %s. Expected GCP_INTEL_TDX", csToken.HwModel)
	}
	av.logger.Debug("Hardware model validated", "hwmodel", csToken.HwModel)

	// Validate software version (must be >= 250300 for TDX support)
	if len(csToken.SwVersion) == 0 {
		return fmt.Errorf("empty swversion array")
	}
	// Parse first version string as integer
	var swVersionInt int64
	if _, err := fmt.Sscanf(csToken.SwVersion[0], "%d", &swVersionInt); err != nil {
		return fmt.Errorf("failed to parse swversion: %w", err)
	}
	if swVersionInt < 250300 {
		return fmt.Errorf("invalid swversion: %d. Expected >= 250300 for TDX support", swVersionInt)
	}
	av.logger.Debug("Software version validated", "swversion", swVersionInt)

	// Validate confidential space support attributes - only check in production (non-debug) mode
	if !av.debugMode {
		if csToken.DbgStat != "disabled-since-boot" {
			return fmt.Errorf("invalid dbgstat: %s. Expected disabled-since-boot", csToken.DbgStat)
		}
		supportAttrs := csToken.SubMods.ConfidentialSpace.SupportAttributes
		if !slices.Contains(supportAttrs, "STABLE") {
			return fmt.Errorf("invalid confidential_space.support_attributes: %v. Expected to contain STABLE", supportAttrs)
		}
		av.logger.Debug("Confidential space support attributes validated", "support_attributes", supportAttrs)
	} else {
		av.logger.Debug("Debug mode enabled, skipping support and debug status validation")
	}

	// Validate project ID
	projectID := csToken.SubMods.GCE.ProjectID
	if projectID != av.projectID {
		return fmt.Errorf("invalid project_id: %s. Expected %s", projectID, av.projectID)
	}
	av.logger.Debug("Project ID validated", "project_id", projectID)

	return nil
}

func extractAppIDFromInstanceName(instanceName string) (string, error) {
	instanceNameParts := strings.Split(instanceName, instanceNameDelimiter)
	if len(instanceNameParts) < 2 {
		return "", fmt.Errorf("invalid instance name: %s. Expected at least %d parts", instanceName, 2)
	}
	return instanceNameParts[len(instanceNameParts)-1], nil
}

func NewJWKCache(ctx context.Context, jwkUrl string, refreshInterval time.Duration) (jwk.Set, error) {
	cache, err := jwk.NewCache(ctx, httprc.NewClient())
	if err != nil {
		return nil, fmt.Errorf("failed to create jwk cache: %w", err)
	}

	// register a constant refresh interval for this URL.
	err = cache.Register(ctx, jwkUrl, jwk.WithConstantInterval(refreshInterval))
	if err != nil {
		return nil, fmt.Errorf("failed to register jwk location: %w", err)
	}

	// fetch once on application startup
	_, err = cache.Refresh(ctx, jwkUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch on startup: %w", err)
	}

	// create the cached key set
	return cache.CachedSet(jwkUrl)
}
