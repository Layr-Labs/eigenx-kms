package utils

import (
	"log/slog"
	"os"

	"github.com/urfave/cli/v2"
)

type ClientConfig struct {
	ServerURL        string
	JWTFile          string
	KMSEncryptionKey string
	KMSSigningKey    string
	LogLevel         string
	OutputFile       string
	Logger           *slog.Logger
}

func NewClientConfigFromCLI(c *cli.Context) (*ClientConfig, error) {
	config := &ClientConfig{
		ServerURL:        c.String(KMSServerURLFlag.Name),
		JWTFile:          c.String(JWTFileFlag.Name),
		KMSEncryptionKey: c.String(KMSEncryptionKeyFileFlag.Name),
		KMSSigningKey:    c.String(KMSSigningKeyFileFlag.Name),
		LogLevel:         c.String(LogLevelFlag.Name),
		OutputFile:       c.String(OutputFileFlag.Name),
	}

	config.Logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: GetLogLevel(config.LogLevel)}))

	config.Logger.Info("Client configuration loaded",
		"server_url", config.ServerURL,
		"jwt_file", config.JWTFile,
		"kms_encryption_key", config.KMSEncryptionKey,
		"kms_signing_key", config.KMSSigningKey,
		"log_level", config.LogLevel,
		"output_file", config.OutputFile,
	)

	return config, nil
}
