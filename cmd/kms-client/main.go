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
		Usage: "Client for requesting environment variables from KMS server with attestation",
		Flags: []cli.Flag{
			utils.KMSServerURLFlag,
			utils.KMSSigningKeyFileFlag,
			utils.AppIDFlag,
			utils.LogLevelFlag,
			utils.OutputFileFlag,
			utils.UserAPIURLFlag,
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

	// Read KMS signing key
	cfg.Logger.Debug("Reading KMS signing key", "file", cfg.KMSSigningKey)
	kmsSigningKeyBytes, err := os.ReadFile(cfg.KMSSigningKey)
	if err != nil {
		return fmt.Errorf("failed to read KMS signing key: %w", err)
	}

	// Create attestation provider
	attestationProvider := envclient.NewBoundEvidenceProvider(cfg.Logger)

	envClient := envclient.NewEnvClient(cfg.Logger, attestationProvider, kmsSigningKeyBytes, cfg.ServerURL, cfg.UserAPIURL)
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
