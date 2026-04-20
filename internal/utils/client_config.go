package utils

import (
	"log/slog"
	"os"

	"github.com/urfave/cli/v2"
)

type ClientConfig struct {
	ServerURL     string
	KMSSigningKey string
	LogLevel      string
	OutputFile    string
	UserAPIURL    string
	Logger        *slog.Logger
}

type AttestConfig struct {
	ServerURL     string
	KMSSigningKey string
	LogLevel      string
	OutputFile    string
	Audience      string
	ExtraData     string // hex-encoded; empty means no extra data
	Logger        *slog.Logger
}

func NewAttestConfigFromCLI(c *cli.Context) (*AttestConfig, error) {
	config := &AttestConfig{
		ServerURL:     c.String(KMSServerURLFlag.Name),
		KMSSigningKey: c.String(KMSSigningKeyFileFlag.Name),
		LogLevel:      c.String(LogLevelFlag.Name),
		OutputFile:    c.String(OutputFileFlag.Name),
		Audience:      c.String(AudienceFlag.Name),
		ExtraData:     c.String(ExtraDataFlag.Name),
	}

	config.Logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: GetLogLevel(config.LogLevel)}))

	config.Logger.Info("Attest configuration loaded",
		"server_url", config.ServerURL,
		"kms_signing_key", config.KMSSigningKey,
		"log_level", config.LogLevel,
		"output_file", config.OutputFile,
		"audience", config.Audience,
	)

	return config, nil
}

func NewClientConfigFromCLI(c *cli.Context) (*ClientConfig, error) {
	config := &ClientConfig{
		ServerURL:     c.String(KMSServerURLFlag.Name),
		KMSSigningKey: c.String(KMSSigningKeyFileFlag.Name),
		LogLevel:      c.String(LogLevelFlag.Name),
		OutputFile:    c.String(OutputFileFlag.Name),
		UserAPIURL:    c.String(UserAPIURLFlag.Name),
	}

	config.Logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: GetLogLevel(config.LogLevel)}))

	config.Logger.Info("Client configuration loaded",
		"server_url", config.ServerURL,
		"kms_signing_key", config.KMSSigningKey,
		"log_level", config.LogLevel,
		"output_file", config.OutputFile,
		"userapi_url", config.UserAPIURL,
	)

	return config, nil
}
