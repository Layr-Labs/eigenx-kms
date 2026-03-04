package utils

import (
	"fmt"
	"strings"
)

const instanceNameDelimiter = "-"

// ExtractAppIDFromInstanceName extracts the app ID from a GCE instance name.
// The instance name format is expected to be: <prefix>-<app-id>
func ExtractAppIDFromInstanceName(instanceName string) (string, error) {
	parts := strings.Split(instanceName, instanceNameDelimiter)
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid instance name: %s. Expected at least 2 parts", instanceName)
	}
	return parts[len(parts)-1], nil
}
