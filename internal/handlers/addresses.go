package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/Layr-Labs/eigenx-kms/internal/kms"
	"github.com/Layr-Labs/eigenx-kms/pkg/crypto"
	"github.com/Layr-Labs/eigenx-kms/pkg/types"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"

	"github.com/labstack/echo/v4"
)

const maxAddresses = 100

// HandleAddresses godoc
//
//	@Summary		Get EVM addresses
//	@Description	Derive EVM addresses from app's HD wallet
//	@Tags			addresses
//	@Accept			json
//	@Produce		json
//	@Param			appID	query		string	true	"Application ID"
//	@Param			count	query		int		false	"Number of addresses to derive (default: 1, max: 100)"
//	@Success		200		{object}	types.SignedResponse[types.AddressesResponse]
//	@Failure		400		{object}	map[string]string
//	@Failure		500		{object}	map[string]string
//	@Router			/addresses [get]
func HandleAddresses(c echo.Context, logger *slog.Logger, kmsClient kms.KMSClient) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Get appId from query parameter
	appID := strings.ToLower(c.QueryParam("appID"))
	if appID == "" {
		returnError(c, logger, http.StatusBadRequest, "appID query parameter is required")
		return nil
	}

	// Get number of addresses to derive (default to 1)
	countParam := c.QueryParam("count")
	if countParam == "" {
		countParam = "1"
	}
	count, err := strconv.Atoi(countParam)
	if err != nil {
		returnError(c, logger, http.StatusBadRequest, fmt.Sprintf("Invalid count parameter: %v", err))
		return nil
	}
	if count <= 0 || count > maxAddresses {
		returnError(c, logger, http.StatusBadRequest, fmt.Sprintf("Invalid count parameter: %d", count))
		return nil
	}

	logger.Debug("Processing addresses request", "app_id", appID, "count", count)

	// Get or generate app mnemonic (KMS encrypted)
	mnemonic, err := kmsClient.DeriveMnemonic(ctx, appID)
	if err != nil {
		returnError(c, logger, http.StatusInternalServerError, fmt.Sprintf("Failed to get/generate mnemonic: %v", err))
		return nil
	}

	logger.Debug("Retrieved/generated mnemonic", "app_id", appID)

	// Derive addresses from mnemonic
	evmWallet, err := hdwallet.NewFromMnemonic(mnemonic)
	if err != nil {
		returnError(c, logger, http.StatusInternalServerError, fmt.Sprintf("Failed to create EVM wallet from mnemonic: %v", err))
		return nil
	}

	evmAddresses := make([]types.EVMAddressAndDerivationPath, count)
	solanaAddresses := make([]types.SolanaAddressAndDerivationPath, count)
	for i := 0; i < count; i++ {
		evmPath := fmt.Sprintf("m/44'/60'/0'/0/%d", i)
		hdpath := hdwallet.MustParseDerivationPath(evmPath)
		evmAccount, err := evmWallet.Derive(hdpath, false)
		if err != nil {
			returnError(c, logger, http.StatusInternalServerError, fmt.Sprintf("Failed to derive EVM address at index %d: %v", i, err))
			return nil
		}
		solanaPath := fmt.Sprintf("m/44'/501'/%d'/0'", i)
		solanaWallet, err := crypto.GenerateSolanaWalletFromMnemonicSeed(mnemonic, uint32(i))
		if err != nil {
			returnError(c, logger, http.StatusInternalServerError, fmt.Sprintf("Failed to derive Solana address at index %d: %v", i, err))
			return nil
		}

		evmAddresses[i] = types.EVMAddressAndDerivationPath{
			Address:        evmAccount.Address,
			DerivationPath: evmPath,
		}
		solanaAddresses[i] = types.SolanaAddressAndDerivationPath{
			Address:        solanaWallet.PublicKey().String(),
			DerivationPath: solanaPath,
		}
	}

	logger.Debug("Derived addresses", "app_id", appID, "count", count)

	// Create response
	response := types.AddressesResponse{
		EVMAddresses:    evmAddresses,
		SolanaAddresses: solanaAddresses,
	}

	logger.Debug("Returning response", "app_id", appID)
	returnSuccessWithSignature(c, logger, kmsClient, http.StatusOK, response)
	return nil
}
