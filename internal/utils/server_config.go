package utils

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/urfave/cli/v2"
)

// GetLogLevel converts a string log level to slog.Level
func GetLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

type ServerConfig struct {
	Port                 string       `json:"port"`
	LogLevel             string       `json:"log_level"`
	Debug                bool         `json:"debug"`
	APIKey               string       `json:"api_key"`
	EnvRateLimit         float64      `json:"env_rate_limit"`
	ProjectID            string       `json:"project_id"`
	AttestationProjectID string       `json:"attestation_project_id"`
	KMSLocation          string       `json:"kms_location"`
	KMSKeyRing           string       `json:"kms_key_ring"`
	KMSHmacKeyName       string       `json:"kms_hmac_key_name"`
	KMSEncryptionKeyName string       `json:"kms_encryption_key_name"`
	KMSSigningKeyName    string       `json:"kms_signing_key_name"`
	RPCURL               string       `json:"rpc_url"`
	AppControllerAddress string       `json:"app_controller_address"`
	Logger               *slog.Logger `json:"-"`
}

func NewServerConfigFromCLI(c *cli.Context) (*ServerConfig, error) {
	config := &ServerConfig{
		Port:                 c.String(PortFlag.Name),
		LogLevel:             c.String(LogLevelFlag.Name),
		Debug:                c.Bool(DebugFlag.Name),
		APIKey:               c.String(APIKeyFlag.Name),
		EnvRateLimit:         c.Float64(EnvRateLimitFlag.Name),
		ProjectID:            c.String(ProjectIDFlag.Name),
		AttestationProjectID: c.String(AttestationProjectIDFlag.Name),
		KMSLocation:          c.String(KMSLocationFlag.Name),
		KMSKeyRing:           c.String(KMSKeyRingFlag.Name),
		KMSHmacKeyName:       c.String(KMSHmacKeyNameFlag.Name),
		KMSEncryptionKeyName: c.String(KMSEncryptionKeyNameFlag.Name),
		KMSSigningKeyName:    c.String(KMSSigningKeyNameFlag.Name),
		RPCURL:               c.String(RPCURLFlag.Name),
		AppControllerAddress: c.String(AppControllerAddressFlag.Name),
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	config.Logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: GetLogLevel(config.LogLevel)}))

	config.Logger.Info("Configuration loaded and validated",
		"port", config.Port,
		"log_level", config.LogLevel,
		"env_rate_limit", config.EnvRateLimit,
		"debug_mode", config.Debug,
		"project_id", config.ProjectID,
		"attestation_project_id", config.AttestationProjectID,
		"kms_location", config.KMSLocation,
		"kms_key_ring", config.KMSKeyRing,
		"kms_hmac_key_name", config.KMSHmacKeyName,
		"kms_encryption_key_name", config.KMSEncryptionKeyName,
		"kms_signing_key_name", config.KMSSigningKeyName,
		"rpc_url", config.RPCURL,
		"app_controller_address", config.AppControllerAddress,
	)

	return config, nil
}

func (c *ServerConfig) Validate() error {
	if c.EnvRateLimit <= 0 {
		return fmt.Errorf("env-rate-limit must be greater than 0, got: %f", c.EnvRateLimit)
	}

	// Add upper bound to prevent abuse
	if c.EnvRateLimit > 1000 {
		return fmt.Errorf("env-rate-limit too high, maximum is 1000, got: %f", c.EnvRateLimit)
	}

	return nil
}
