package utils

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	instanceNameDelimiter = "-"
	gceMetadataURL        = "http://metadata.google.internal/computeMetadata/v1/instance/name"
)

// ExtractAppIDFromInstanceName extracts the app ID from a GCE instance name.
// The instance name format is expected to be: <prefix>-<app-id>
func ExtractAppIDFromInstanceName(instanceName string) (string, error) {
	parts := strings.Split(instanceName, instanceNameDelimiter)
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid instance name: %s. Expected at least 2 parts", instanceName)
	}
	return parts[len(parts)-1], nil
}

// GetAppAddressFromMetadata reads the GCE instance name from the metadata server
// and extracts the app address from it.
func GetAppAddressFromMetadata(ctx context.Context) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}

	req, err := http.NewRequestWithContext(ctx, "GET", gceMetadataURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create metadata request: %w", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to query GCE metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GCE metadata returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read metadata response: %w", err)
	}

	instanceName := strings.TrimSpace(string(body))
	return ExtractAppIDFromInstanceName(instanceName)
}
