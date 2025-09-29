package handlers

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
)

// HandleHealth godoc
//
//	@Summary		Health check
//	@Description	Get server health status
//	@Tags			health
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	map[string]interface{}
//	@Router			/health [get]
func HandleHealth(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}
