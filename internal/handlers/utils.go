package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Layr-Labs/eigenx-kms/internal/kms"
	"github.com/Layr-Labs/eigenx-kms/pkg/types"
	"github.com/labstack/echo/v4"
)

const timeout = 10 * time.Second

// httpError wraps an error with an HTTP status code
type httpError struct {
	statusCode int
	message    string
}

func (e *httpError) Error() string {
	return e.message
}

func newHTTPError(statusCode int, format string, args ...interface{}) *httpError {
	return &httpError{
		statusCode: statusCode,
		message:    fmt.Sprintf(format, args...),
	}
}

func returnSuccessWithSignature[T any](c echo.Context, logger *slog.Logger, kmsClient kms.KMSClient, status int, data T) error {
	responseJSON, err := json.Marshal(data)
	if err != nil {
		return returnError(c, logger, http.StatusInternalServerError, fmt.Sprintf("Failed to marshal response: %v", err))
	}

	signature, err := kmsClient.SignMessage(c.Request().Context(), string(responseJSON))
	if err != nil {
		return returnError(c, logger, http.StatusInternalServerError, fmt.Sprintf("Failed to sign response: %v", err))
	}

	logger.Debug("Sending response", "status", status)
	c.JSON(status, types.SignedResponse[T]{Data: data, Signature: signature})
	logger.Debug("Response sent", "status", status)
	return nil
}

func returnError(c echo.Context, logger *slog.Logger, status int, errString string) error {
	logger.Error(errString)
	c.JSON(status, map[string]string{"error": errString})
	return nil
}

// applyDebugOverride checks for the debug appID query parameter and applies it if in debug mode.
// Returns the final appID, or empty string if a debug override was requested but debug mode is off.
func applyDebugOverride(c echo.Context, appID string, debugMode bool) string {
	debugAppID := strings.ToLower(c.QueryParam("appID"))
	if debugAppID != "" {
		if debugMode {
			return debugAppID
		}
		return ""
	}
	return appID
}
