package utils

import "github.com/urfave/cli/v2"

var (
	PortFlag = &cli.StringFlag{
		Name:    "port",
		Value:   "8080",
		Usage:   "Port to listen on",
		EnvVars: []string{"PORT"},
	}

	LogLevelFlag = &cli.StringFlag{
		Name:    "log-level",
		Value:   "info",
		Usage:   "Log level",
		EnvVars: []string{"LOG_LEVEL"},
	}

	DebugFlag = &cli.BoolFlag{
		Name:    "debug",
		Value:   false,
		Usage:   "Enable debug mode",
		EnvVars: []string{"DEBUG_MODE"},
	}

	APIKeyFlag = &cli.StringFlag{
		Name:     "api-key",
		Usage:    "API key for accessing /addresses and /health endpoints",
		EnvVars:  []string{"API_KEY"},
		Required: true,
	}

	EnvRateLimitFlag = &cli.Float64Flag{
		Name:     "env-rate-limit",
		Usage:    "Rate limit for /env endpoint (requests per second per IP)",
		EnvVars:  []string{"ENV_RATE_LIMIT"},
		Required: true,
	}

	ProjectIDFlag = &cli.StringFlag{
		Name:     "project-id",
		Usage:    "Google Cloud Project ID",
		EnvVars:  []string{"GOOGLE_CLOUD_PROJECT"},
		Required: true,
	}

	AttestationProjectIDFlag = &cli.StringFlag{
		Name:     "attestation-project-id",
		Usage:    "Google Cloud Project ID for to validate attestation tokens",
		EnvVars:  []string{"ATTESTATION_PROJECT_ID"},
		Required: true,
	}

	KMSLocationFlag = &cli.StringFlag{
		Name:     "kms-location",
		Usage:    "KMS location",
		EnvVars:  []string{"KMS_LOCATION"},
		Required: true,
	}

	KMSKeyRingFlag = &cli.StringFlag{
		Name:     "kms-key-ring",
		Usage:    "KMS key ring",
		EnvVars:  []string{"KMS_KEY_RING"},
		Required: true,
	}

	KMSHmacKeyNameFlag = &cli.StringFlag{
		Name:     "kms-hmac-key-name",
		Usage:    "KMS HMAC key name",
		EnvVars:  []string{"KMS_HMAC_KEY_NAME"},
		Required: true,
	}

	KMSEncryptionKeyNameFlag = &cli.StringFlag{
		Name:     "kms-encryption-key-name",
		Usage:    "KMS encryption key name",
		EnvVars:  []string{"KMS_ENCRYPTION_KEY_NAME"},
		Required: true,
	}

	KMSSigningKeyNameFlag = &cli.StringFlag{
		Name:     "kms-signing-key-name",
		Usage:    "KMS signing key name",
		EnvVars:  []string{"KMS_SIGNING_KEY_NAME"},
		Required: true,
	}

	RPCURLFlag = &cli.StringFlag{
		Name:     "rpc-url",
		Usage:    "Blockchain RPC URL",
		EnvVars:  []string{"RPC_URL"},
		Required: true,
	}

	AppControllerAddressFlag = &cli.StringFlag{
		Name:     "app-controller-address",
		Usage:    "App controller contract address",
		EnvVars:  []string{"APP_CONTROLLER_ADDRESS"},
		Required: true,
	}

	KMSServerURLFlag = &cli.StringFlag{
		Name:     "kms-server-url",
		Usage:    "KMS server URL",
		Required: true,
		EnvVars:  []string{"KMS_SERVER_URL"},
	}

	JWTFileFlag = &cli.StringFlag{
		Name:     "jwt-file",
		Usage:    "Path to JWT file",
		Required: true,
		EnvVars:  []string{"JWT_FILE"},
	}

	KMSEncryptionKeyFileFlag = &cli.StringFlag{
		Name:     "kms-encryption-key-file",
		Usage:    "Path to KMS encryption key PEM file",
		EnvVars:  []string{"KMS_ENCRYPTION_KEY_FILE"},
		Required: true,
	}

	AppIDFlag = &cli.StringFlag{
		Name:    "app-id",
		Usage:   "App ID to spoof (debug mode only)",
		EnvVars: []string{"APP_ID"},
	}

	KMSSigningKeyFileFlag = &cli.StringFlag{
		Name:     "kms-signing-key-file",
		Usage:    "Path to KMS signing public key PEM file",
		Value:    "kms-signing-public-key.pem",
		EnvVars:  []string{"KMS_SIGNING_KEY_FILE"},
		Required: true,
	}

	OutputFileFlag = &cli.StringFlag{
		Name:  "output",
		Usage: "Output file path to write environment variables in key=value format",
	}
)
