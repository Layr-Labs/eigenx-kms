package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/Layr-Labs/eigenx-kms/internal/kms"
	"github.com/Layr-Labs/eigenx-kms/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms/pkg/types"

	"github.com/labstack/echo/v4"
)

const maxAddresses = 100

// deriveAddressesFromRequest is a helper function that extracts common logic for deriving addresses
func deriveAddressesFromRequest(c echo.Context, ctx context.Context, logger *slog.Logger, kmsClient kms.KMSClient) (string, []types.EVMAddressAndDerivationPath, []types.SolanaAddressAndDerivationPath, error) {
	// Get appId from query parameter
	appID := strings.ToLower(c.QueryParam("appID"))
	if appID == "" {
		return "", nil, nil, newHTTPError(http.StatusBadRequest, "appID query parameter is required")
	}

	// Get number of addresses to derive (default to 1)
	countParam := c.QueryParam("count")
	if countParam == "" {
		countParam = "1"
	}
	count, err := strconv.Atoi(countParam)
	if err != nil {
		return "", nil, nil, newHTTPError(http.StatusBadRequest, "Invalid count parameter: %v", err)
	}
	if count <= 0 || count > maxAddresses {
		return "", nil, nil, newHTTPError(http.StatusBadRequest, "Invalid count parameter: %d", count)
	}

	logger.Debug("Processing addresses request", "app_id", appID, "count", count)

	// Get or generate app mnemonic (KMS encrypted)
	mnemonic, err := kmsClient.DeriveMnemonic(ctx, appID)
	if err != nil {
		return "", nil, nil, newHTTPError(http.StatusInternalServerError, "Failed to get/generate mnemonic: %v", err)
	}

	logger.Debug("Retrieved/generated mnemonic", "app_id", appID)

	// Derive addresses from mnemonic
	evmAddresses, solanaAddresses, err := crypto.DeriveAddressesFromMnemonic(mnemonic, count)
	if err != nil {
		return "", nil, nil, newHTTPError(http.StatusInternalServerError, "Failed to derive addresses: %v", err)
	}

	logger.Debug("Derived addresses", "app_id", appID, "count", count)
	return appID, evmAddresses, solanaAddresses, nil
}

// HandleAddresses godoc
//
//	@Summary		Get EVM addresses
//	@Description	Derive EVM addresses from app's HD wallet
//	@Tags			addresses
//	@Accept			json
//	@Produce		json
//	@Param			appID	query		string	true	"Application ID"
//	@Param			count	query		int		false	"Number of addresses to derive (default: 1, max: 100)"
//	@Success		200		{object}	types.SignedResponse[types.AddressesResponseV1]
//	@Failure		400		{object}	map[string]string
//	@Failure		500		{object}	map[string]string
//	@Router			/addresses [get]
func HandleAddresses(c echo.Context, logger *slog.Logger, kmsClient kms.KMSClient) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	appID, evmAddresses, solanaAddresses, err := deriveAddressesFromRequest(c, ctx, logger, kmsClient)
	if err != nil {
		if httpErr, ok := err.(*httpError); ok {
			returnError(c, logger, httpErr.statusCode, httpErr.message)
		} else {
			returnError(c, logger, http.StatusInternalServerError, err.Error())
		}
		return nil
	}

	// Create response (V1 - without appId)
	response := types.AddressesResponseV1{
		EVMAddresses:    evmAddresses,
		SolanaAddresses: solanaAddresses,
	}

	logger.Debug("Returning response", "app_id", appID)
	return returnSuccessWithSignature(c, logger, kmsClient, http.StatusOK, response)
}

// HandleAddressesV2 godoc
//
//	@Summary		Get EVM addresses (V2)
//	@Description	Derive EVM addresses from app's HD wallet, includes appId in response
//	@Tags			addresses
//	@Accept			json
//	@Produce		json
//	@Param			appID	query		string	true	"Application ID"
//	@Param			count	query		int		false	"Number of addresses to derive (default: 1, max: 100)"
//	@Success		200		{object}	types.SignedResponse[types.AddressesResponseV2]
//	@Failure		400		{object}	map[string]string
//	@Failure		500		{object}	map[string]string
//	@Router			/addresses/v2 [get]
func HandleAddressesV2(c echo.Context, logger *slog.Logger, kmsClient kms.KMSClient) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	appID, evmAddresses, solanaAddresses, err := deriveAddressesFromRequest(c, ctx, logger, kmsClient)
	if err != nil {
		if httpErr, ok := err.(*httpError); ok {
			returnError(c, logger, httpErr.statusCode, httpErr.message)
		} else {
			returnError(c, logger, http.StatusInternalServerError, err.Error())
		}
		return nil
	}

	// Create response (V2 - with appId)
	response := types.AddressesResponseV2{
		AppID:           appID,
		EVMAddresses:    evmAddresses,
		SolanaAddresses: solanaAddresses,
	}

	logger.Debug("Returning response", "app_id", appID)
	return returnSuccessWithSignature(c, logger, kmsClient, http.StatusOK, response)
}
