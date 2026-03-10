// @title		Compute TEE KMS API
// @version	1.0
// @description	KMS service for Compute TEE
// @host		localhost:8080
// @BasePath	/
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	appcontrollerV1 "github.com/Layr-Labs/eigenx-contracts/pkg/bindings/v1/AppController"
	"github.com/Layr-Labs/eigenx-contracts/pkg/bindings/v1/ImageAllowlist"
	"github.com/Layr-Labs/eigenx-kms/internal/auth"
	"github.com/Layr-Labs/eigenx-kms/internal/handlers"
	"github.com/Layr-Labs/eigenx-kms/internal/kms"
	"github.com/Layr-Labs/eigenx-kms/internal/utils"
	"github.com/Layr-Labs/eigenx-kms/pkg/attestation"
	"github.com/Layr-Labs/eigenx-kms/pkg/chainclient"
	"github.com/Layr-Labs/eigenx-kms/pkg/policy"
	_ "github.com/Layr-Labs/eigenx-kms/pkg/types"
	_ "github.com/Layr-Labs/eigenx-kms/swagger"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	echoSwagger "github.com/swaggo/echo-swagger"
	"github.com/urfave/cli/v2"
	"golang.org/x/time/rate"
)

func main() {
	app := &cli.App{
		Name:  "kms-server",
		Usage: "KMS service for Compute TEE",
		Flags: []cli.Flag{
			utils.PortFlag,
			utils.LogLevelFlag,
			utils.DebugFlag,
			utils.APIKeyFlag,
			utils.EnvRateLimitFlag,
			utils.ProjectIDFlag,
			utils.AttestationProjectIDFlag,
			utils.KMSLocationFlag,
			utils.KMSKeyRingFlag,
			utils.KMSHmacKeyNameFlag,
			utils.KMSEncryptionKeyNameFlag,
			utils.KMSSigningKeyNameFlag,
			utils.RPCURLFlag,
			utils.AppControllerAddressFlag,
			utils.ImageAllowlistAddressFlag,
			utils.AttestJWTSigningKeyFlag,
			utils.AttestJWTExpirationFlag,
		},
		Action: runServer,
	}

	if err := app.Run(os.Args); err != nil {
		slog.Error("Application failed", "error", err)
		os.Exit(1)
	}
}

func runServer(c *cli.Context) error {
	cfg, err := utils.NewServerConfigFromCLI(c)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	ctx := context.Background()

	// Initialize components
	attestationVerifier, err := attestation.NewAttestationVerifier(ctx, cfg.Logger, cfg.AttestationProjectID, 1*time.Hour, cfg.Debug)
	if err != nil {
		return fmt.Errorf("failed to initialize attestation verifier: %w", err)
	}

	ethClient, err := ethclient.Dial(cfg.RPCURL)
	if err != nil {
		return fmt.Errorf("failed to initialize eth client: %w", err)
	}

	appController, err := appcontrollerV1.NewAppController(common.HexToAddress(cfg.AppControllerAddress), ethClient)
	if err != nil {
		return fmt.Errorf("failed to initialize app controller: %w", err)
	}

	imageAllowlist, err := ImageAllowlist.NewImageAllowlist(common.HexToAddress(cfg.ImageAllowlistAddress), ethClient)
	if err != nil {
		return fmt.Errorf("failed to initialize image allowlist: %w", err)
	}

	chainClient, err := chainclient.NewChainClient(cfg.Logger, chainclient.WrapAppController(appController), chainclient.WrapImageAllowlist(imageAllowlist))
	if err != nil {
		return fmt.Errorf("failed to initialize chain client: %w", err)
	}

	policyChecker := policy.NewPolicyChecker(
		cfg.Logger,
		cfg.AttestationProjectID,
		chainClient,
		cfg.Debug,
	)

	kmsClient, err := kms.NewGcpKmsClient(ctx, cfg.Logger, kms.GcpKmsClientConfig{
		ProjectID:       cfg.ProjectID,
		LocationID:      cfg.KMSLocation,
		KeyRingID:       cfg.KMSKeyRing,
		HmacKeyID:       cfg.KMSHmacKeyName,
		EncryptionKeyID: cfg.KMSEncryptionKeyName,
		SigningKeyID:    cfg.KMSSigningKeyName,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize KMS client: %w", err)
	}

	attestationEvidenceVerifier := attestation.NewBoundAttestationEvidenceVerifier()

	// Initialize Echo router
	e := echo.New()
	// set this to extract the client's IP directly from the request
	e.IPExtractor = echo.ExtractIPDirect()

	// API key auth middleware for protected endpoints
	keyAuth := middleware.KeyAuthWithConfig(middleware.KeyAuthConfig{
		Validator: func(key string, c echo.Context) (bool, error) {
			return key == cfg.APIKey, nil
		},
	})

	e.GET("/health", func(c echo.Context) error {
		return handlers.HandleHealth(c)
	})
	e.GET("/addresses", func(c echo.Context) error {
		return handlers.HandleAddresses(c, cfg.Logger, kmsClient)
	}, keyAuth)
	e.GET("/addresses/v2", func(c echo.Context) error {
		return handlers.HandleAddressesV2(c, cfg.Logger, kmsClient)
	}, keyAuth)

	// env endpoint with rate limiting
	e.POST("/env", func(c echo.Context) error {
		return handlers.HandleEnv(c, cfg.Logger, attestationVerifier, chainClient, kmsClient, cfg.Debug)
	}, middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(rate.Limit(cfg.EnvRateLimit))))

	// env v2 endpoint with rate limiting
	e.POST("/env/v2", func(c echo.Context) error {
		return handlers.HandleEnvV2(c, cfg.Logger, attestationVerifier, chainClient, kmsClient, cfg.Debug)
	}, middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(rate.Limit(cfg.EnvRateLimit))))

	// env v3 endpoint with rate limiting (self-verification)
	e.POST("/env/v3", func(c echo.Context) error {
		return handlers.HandleEnvV3(c, cfg.Logger, attestationEvidenceVerifier, policyChecker, chainClient, kmsClient, cfg.Debug)
	}, middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(rate.Limit(cfg.EnvRateLimit))))

	// Conditionally register /auth/attest if signing key is configured
	if cfg.AttestJWTSigningKeyPEM != "" {
		jwtSigner, err := auth.NewJWTSigner(cfg.AttestJWTSigningKeyPEM, cfg.AttestJWTExpiration)
		if err != nil {
			return fmt.Errorf("failed to initialize JWT signer: %w", err)
		}
		cfg.Logger.Info("Attestation JWT signing enabled", "expiration", cfg.AttestJWTExpiration)

		e.POST("/auth/attest", func(c echo.Context) error {
			return handlers.HandleAttest(c, cfg.Logger, jwtSigner, attestationEvidenceVerifier, policyChecker, kmsClient, cfg.Debug)
		}, middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(rate.Limit(cfg.EnvRateLimit))))
	}

	// Swagger endpoint
	e.GET("/swagger/*", echoSwagger.WrapHandler)

	// Start server
	cfg.Logger.Info("Starting KMS service", "port", cfg.Port)

	if err := e.Start(":" + cfg.Port); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	return nil
}
