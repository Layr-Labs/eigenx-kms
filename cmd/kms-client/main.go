package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Layr-Labs/eigenx-kms/internal/utils"
	"github.com/Layr-Labs/eigenx-kms/pkg/envclient"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "kms-client",
		Usage: "Client for requesting environment variables from KMS server with JWT + RSA authentication",
		Flags: []cli.Flag{
			utils.KMSServerURLFlag,
			utils.JWTFileFlag,
			utils.KMSEncryptionKeyFileFlag,
			utils.KMSSigningKeyFileFlag,
			utils.AppIDFlag,
			utils.LogLevelFlag,
			utils.OutputFileFlag,
		},
		Action: runClient,
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func runClient(c *cli.Context) error {
	ctx := context.Background()

	// Load configuration
	cfg, err := utils.NewClientConfigFromCLI(c)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Read files
	cfg.Logger.Debug("Reading JWT file", "file", cfg.JWTFile)
	jwtBytes, err := os.ReadFile(cfg.JWTFile)
	if err != nil {
		return fmt.Errorf("failed to read JWT file: %w", err)
	}

	cfg.Logger.Debug("Reading KMS public key", "file", cfg.KMSEncryptionKey)
	kmsEncryptionKeyBytes, err := os.ReadFile(cfg.KMSEncryptionKey)
	if err != nil {
		return fmt.Errorf("failed to read KMS public key: %w", err)
	}

	cfg.Logger.Debug("Reading KMS signing key", "file", cfg.KMSSigningKey)
	kmsSigningKeyBytes, err := os.ReadFile(cfg.KMSSigningKey)
	if err != nil {
		return fmt.Errorf("failed to read KMS signing key: %w", err)
	}

	envClient := envclient.NewEnvClient(cfg.Logger, jwtBytes, kmsEncryptionKeyBytes, kmsSigningKeyBytes, cfg.ServerURL)
	envJSONBytes, err := envClient.GetEnv(ctx)
	if err != nil {
		return fmt.Errorf("failed to get env: %w", err)
	}

	// Handle output based on configuration
	if cfg.OutputFile != "" {
		return writeEnvFile(cfg, envJSONBytes)
	} else {
		responseJSON, _ := json.MarshalIndent(envJSONBytes, "", "  ")
		fmt.Printf("%s\n", responseJSON)
		return nil
	}
}

func writeEnvFile(cfg *utils.ClientConfig, envJSONBytes []byte) error {
	envVars := make(map[string]string)
	err := json.Unmarshal(envJSONBytes, &envVars)
	if err != nil {
		return fmt.Errorf("failed to unmarshal env: %w", err)
	}

	// Convert to key=value format
	var lines []string
	for key, value := range envVars {
		lines = append(lines, fmt.Sprintf("export %s=\"%s\"", key, value))
	}

	// Sort for consistent output
	sort.Strings(lines)

	// Write to file
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(cfg.OutputFile, []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	cfg.Logger.Info("Environment variables written to file", "file", cfg.OutputFile, "count", len(envVars))
	return nil
}
