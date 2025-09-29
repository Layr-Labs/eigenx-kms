package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/Layr-Labs/eigenx-kms/internal/kms"
	"github.com/Layr-Labs/eigenx-kms/pkg/types"
	"github.com/labstack/echo/v4"
)

const timeout = 10 * time.Second

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
	return errors.New(errString)
}
