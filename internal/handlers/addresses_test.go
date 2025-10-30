package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/Layr-Labs/eigenx-kms/internal/kms"
	kmsMocks "github.com/Layr-Labs/eigenx-kms/internal/kms/mocks"
	"github.com/Layr-Labs/eigenx-kms/pkg/types"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

const (
	// Valid BIP39 mnemonic for testing
	testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	testAppID    = "0x1111111111111111111111111111111111111111"
)

type addressesTestConfig struct {
	name     string
	endpoint string
	handler  func(c echo.Context, logger *slog.Logger, kmsClient kms.KMSClient) error
	hasAppID bool // true for V2 (includes appId in response), false for V1
}

// testConfigs defines both V1 and V2 configurations
var addressesTestConfigs = []addressesTestConfig{
	{
		name:     "V1",
		endpoint: "/addresses",
		handler:  HandleAddresses,
		hasAppID: false,
	},
	{
		name:     "V2",
		endpoint: "/addresses/v2",
		handler:  HandleAddressesV2,
		hasAppID: true,
	},
}

func setupLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func setupEchoContext(method, path string) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec), rec
}

// addressesTestData is a common structure for both V1 and V2 response data
type addressesTestData struct {
	AppID           string
	EVMAddresses    []types.EVMAddressAndDerivationPath
	SolanaAddresses []types.SolanaAddressAndDerivationPath
}

// unmarshalAddressesResponse unmarshals the response based on the test config version
func unmarshalAddressesResponse(t *testing.T, tc addressesTestConfig, rec *httptest.ResponseRecorder) addressesTestData {
	if tc.hasAppID {
		var response types.SignedResponse[types.AddressesResponseV2]
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		return addressesTestData{
			AppID:           response.Data.AppID,
			EVMAddresses:    response.Data.EVMAddresses,
			SolanaAddresses: response.Data.SolanaAddresses,
		}
	} else {
		var response types.SignedResponse[types.AddressesResponseV1]
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		return addressesTestData{
			AppID:           "", // V1 doesn't have AppID
			EVMAddresses:    response.Data.EVMAddresses,
			SolanaAddresses: response.Data.SolanaAddresses,
		}
	}
}

func TestHandleAddresses_InputValidation(t *testing.T) {
	for _, tc := range addressesTestConfigs {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			logger := setupLogger()
			mockKMS := kmsMocks.NewMockKMSClient(ctrl)

			t.Run("missing appID parameter", func(t *testing.T) {
				c, rec := setupEchoContext(http.MethodGet, tc.endpoint)

				err := tc.handler(c, logger, mockKMS)

				require.NoError(t, err)
				require.Equal(t, http.StatusBadRequest, rec.Code)

				var response map[string]string
				err = json.Unmarshal(rec.Body.Bytes(), &response)
				require.NoError(t, err)
				require.Contains(t, response["error"], "appID query parameter is required")
			})

			t.Run("empty appID parameter", func(t *testing.T) {
				c, rec := setupEchoContext(http.MethodGet, tc.endpoint+"?appID=")

				err := tc.handler(c, logger, mockKMS)

				require.NoError(t, err)
				require.Equal(t, http.StatusBadRequest, rec.Code)

				var response map[string]string
				err = json.Unmarshal(rec.Body.Bytes(), &response)
				require.NoError(t, err)
				require.Contains(t, response["error"], "appID query parameter is required")
			})

			t.Run("invalid count parameter - non-numeric", func(t *testing.T) {
				c, rec := setupEchoContext(http.MethodGet, tc.endpoint+"?appID=test&count=abc")

				err := tc.handler(c, logger, mockKMS)

				require.NoError(t, err)
				require.Equal(t, http.StatusBadRequest, rec.Code)

				var response map[string]string
				err = json.Unmarshal(rec.Body.Bytes(), &response)
				require.NoError(t, err)
				require.Contains(t, response["error"], "Invalid count parameter")
			})

			t.Run("invalid count parameter - zero", func(t *testing.T) {
				c, rec := setupEchoContext(http.MethodGet, tc.endpoint+"?appID=test&count=0")

				err := tc.handler(c, logger, mockKMS)

				require.NoError(t, err)
				require.Equal(t, http.StatusBadRequest, rec.Code)

				var response map[string]string
				err = json.Unmarshal(rec.Body.Bytes(), &response)
				require.NoError(t, err)
				require.Contains(t, response["error"], "Invalid count parameter: 0")
			})

			t.Run("invalid count parameter - negative", func(t *testing.T) {
				c, rec := setupEchoContext(http.MethodGet, tc.endpoint+"?appID=test&count=-1")

				err := tc.handler(c, logger, mockKMS)

				require.NoError(t, err)
				require.Equal(t, http.StatusBadRequest, rec.Code)

				var response map[string]string
				err = json.Unmarshal(rec.Body.Bytes(), &response)
				require.NoError(t, err)
				require.Contains(t, response["error"], "Invalid count parameter: -1")
			})

			t.Run("invalid count parameter - exceeds maximum", func(t *testing.T) {
				c, rec := setupEchoContext(http.MethodGet, tc.endpoint+"?appID=test&count=101")

				err := tc.handler(c, logger, mockKMS)

				require.NoError(t, err)
				require.Equal(t, http.StatusBadRequest, rec.Code)

				var response map[string]string
				err = json.Unmarshal(rec.Body.Bytes(), &response)
				require.NoError(t, err)
				require.Contains(t, response["error"], "Invalid count parameter: 101")
			})

			t.Run("default count behavior - missing count defaults to 1", func(t *testing.T) {
				c, rec := setupEchoContext(http.MethodGet, fmt.Sprintf("%s?appID=%s", tc.endpoint, testAppID))

				// Mock successful KMS operations
				mockKMS.EXPECT().
					DeriveMnemonic(gomock.Any(), testAppID).
					Return(testMnemonic, nil)

				// Mock successful response signing
				mockKMS.EXPECT().
					SignMessage(gomock.Any(), gomock.Any()).
					Return([]byte("test-signature"), nil)

				err := tc.handler(c, logger, mockKMS)

				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rec.Code)

				data := unmarshalAddressesResponse(t, tc, rec)
				if tc.hasAppID {
					require.Equal(t, testAppID, data.AppID)
				}
				require.Len(t, data.EVMAddresses, 1)
				require.Len(t, data.SolanaAddresses, 1)
			})
		})
	}
}

func TestHandleAddresses_KMSIntegration(t *testing.T) {
	for _, tc := range addressesTestConfigs {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			logger := setupLogger()
			mockKMS := kmsMocks.NewMockKMSClient(ctrl)

			t.Run("successful mnemonic derivation", func(t *testing.T) {
				c, rec := setupEchoContext(http.MethodGet, fmt.Sprintf("%s?appID=%s&count=1", tc.endpoint, testAppID))

				// Mock successful KMS operations
				mockKMS.EXPECT().
					DeriveMnemonic(gomock.Any(), testAppID).
					Return(testMnemonic, nil)

				mockKMS.EXPECT().
					SignMessage(gomock.Any(), gomock.Any()).
					Return([]byte("test-signature"), nil)

				err := tc.handler(c, logger, mockKMS)

				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rec.Code)
			})

			t.Run("KMS mnemonic derivation failure", func(t *testing.T) {
				c, rec := setupEchoContext(http.MethodGet, fmt.Sprintf("%s?appID=%s&count=1", tc.endpoint, testAppID))

				// Mock KMS failure
				mockKMS.EXPECT().
					DeriveMnemonic(gomock.Any(), testAppID).
					Return("", errors.New("KMS unavailable"))

				err := tc.handler(c, logger, mockKMS)

				require.NoError(t, err)
				require.Equal(t, http.StatusInternalServerError, rec.Code)

				var response map[string]string
				err = json.Unmarshal(rec.Body.Bytes(), &response)
				require.NoError(t, err)
				require.Contains(t, response["error"], "Failed to get/generate mnemonic")
			})

			t.Run("KMS signing failure", func(t *testing.T) {
				c, rec := setupEchoContext(http.MethodGet, fmt.Sprintf("%s?appID=%s&count=1", tc.endpoint, testAppID))

				// Mock successful mnemonic derivation but failed signing
				mockKMS.EXPECT().
					DeriveMnemonic(gomock.Any(), testAppID).
					Return(testMnemonic, nil)

				mockKMS.EXPECT().
					SignMessage(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("signing failed"))

				err := tc.handler(c, logger, mockKMS)

				require.NoError(t, err)
				require.Equal(t, http.StatusInternalServerError, rec.Code)

				var response map[string]string
				err = json.Unmarshal(rec.Body.Bytes(), &response)
				require.NoError(t, err)
				require.Contains(t, response["error"], "Failed to sign response")
			})
		})
	}
}

func TestHandleAddresses_WalletIntegration(t *testing.T) {
	for _, tc := range addressesTestConfigs {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			logger := setupLogger()
			mockKMS := kmsMocks.NewMockKMSClient(ctrl)

			t.Run("single address generation", func(t *testing.T) {
				c, rec := setupEchoContext(http.MethodGet, fmt.Sprintf("%s?appID=%s&count=1", tc.endpoint, testAppID))

				mockKMS.EXPECT().
					DeriveMnemonic(gomock.Any(), testAppID).
					Return(testMnemonic, nil)

				mockKMS.EXPECT().
					SignMessage(gomock.Any(), gomock.Any()).
					Return([]byte("test-signature"), nil)

				err := tc.handler(c, logger, mockKMS)

				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rec.Code)

				data := unmarshalAddressesResponse(t, tc, rec)
				if tc.hasAppID {
					require.Equal(t, testAppID, data.AppID)
				}

				require.Len(t, data.EVMAddresses, 1)

				// Verify address format
				evmAddr := data.EVMAddresses[0]
				require.Equal(t, evmAddr.Address.String(), "0x9858EfFD232B4033E47d90003D41EC34EcaEda94")
				require.Equal(t, "m/44'/60'/0'/0/0", evmAddr.DerivationPath)
				require.Equal(t, data.SolanaAddresses[0].Address, "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk")
				require.Equal(t, "m/44'/501'/0'/0'", data.SolanaAddresses[0].DerivationPath)
			})

			t.Run("multiple address generation", func(t *testing.T) {
				c, rec := setupEchoContext(http.MethodGet, fmt.Sprintf("%s?appID=%s&count=5", tc.endpoint, testAppID))

				mockKMS.EXPECT().
					DeriveMnemonic(gomock.Any(), testAppID).
					Return(testMnemonic, nil)

				mockKMS.EXPECT().
					SignMessage(gomock.Any(), gomock.Any()).
					Return([]byte("test-signature"), nil)

				err := tc.handler(c, logger, mockKMS)

				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rec.Code)

				data := unmarshalAddressesResponse(t, tc, rec)
				if tc.hasAppID {
					require.Equal(t, testAppID, data.AppID)
				}

				require.Len(t, data.EVMAddresses, 5)

				// Verify derivation paths are sequential
				for i, addr := range data.EVMAddresses {
					expectedPath := fmt.Sprintf("m/44'/60'/0'/0/%d", i)
					require.Equal(t, expectedPath, addr.DerivationPath)
				}
				for i, addr := range data.SolanaAddresses {
					expectedPath := fmt.Sprintf("m/44'/501'/%d'/0'", i)
					require.Equal(t, expectedPath, addr.DerivationPath)
				}
				require.Equal(t, data.EVMAddresses[0].Address.String(), "0x9858EfFD232B4033E47d90003D41EC34EcaEda94")
				require.Equal(t, data.EVMAddresses[1].Address.String(), "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0")
				require.Equal(t, data.EVMAddresses[2].Address.String(), "0xb6716976A3ebe8D39aCEB04372f22Ff8e6802D7A")
				require.Equal(t, data.EVMAddresses[3].Address.String(), "0xF3f50213C1d2e255e4B2bAD430F8A38EEF8D718E")
				require.Equal(t, data.EVMAddresses[4].Address.String(), "0x51cA8ff9f1C0a99f88E86B8112eA3237F55374cA")
				require.Equal(t, data.SolanaAddresses[0].Address, "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk")
				require.Equal(t, data.SolanaAddresses[1].Address, "Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb")
				require.Equal(t, data.SolanaAddresses[2].Address, "7WktogJEd2wQ9eH2oWusmcoFTgeYi6rS632UviTBJ2jm")
				require.Equal(t, data.SolanaAddresses[3].Address, "3YqEpfo3c818GhvbQ1UmVY1nJxw16vtu4JB9peJXT94k")
				require.Equal(t, data.SolanaAddresses[4].Address, "6nod592sTfEWD3VSVPdQndLMVBCNmMc6ngt7MyGBK21j")
			})

			t.Run("maximum address generation", func(t *testing.T) {
				c, rec := setupEchoContext(http.MethodGet, fmt.Sprintf("%s?appID=%s&count=100", tc.endpoint, testAppID))

				mockKMS.EXPECT().
					DeriveMnemonic(gomock.Any(), testAppID).
					Return(testMnemonic, nil)

				mockKMS.EXPECT().
					SignMessage(gomock.Any(), gomock.Any()).
					Return([]byte("test-signature"), nil)

				err := tc.handler(c, logger, mockKMS)

				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rec.Code)

				data := unmarshalAddressesResponse(t, tc, rec)
				require.Len(t, data.EVMAddresses, 100)
				require.Len(t, data.SolanaAddresses, 100)
			})

			t.Run("invalid mnemonic handling", func(t *testing.T) {
				c, rec := setupEchoContext(http.MethodGet, fmt.Sprintf("%s?appID=%s&count=1", tc.endpoint, testAppID))

				// Mock KMS returning invalid mnemonic
				mockKMS.EXPECT().
					DeriveMnemonic(gomock.Any(), testAppID).
					Return("invalid mnemonic phrase", nil)

				err := tc.handler(c, logger, mockKMS)

				require.NoError(t, err)
				require.Equal(t, http.StatusInternalServerError, rec.Code)

				var response map[string]string
				err = json.Unmarshal(rec.Body.Bytes(), &response)
				require.NoError(t, err)
				require.Contains(t, response["error"], "Failed to create EVM wallet from mnemonic")
			})
		})
	}
}

func TestHandleAddresses_AppIDCasing(t *testing.T) {
	for _, tc := range addressesTestConfigs {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			logger := setupLogger()
			mockKMS := kmsMocks.NewMockKMSClient(ctrl)

			t.Run("uppercase appID is lowercased", func(t *testing.T) {
				upperCaseAppID := "0xABCDEF1234567890ABCDEF1234567890ABCDEF12"
				lowerCaseAppID := "0xabcdef1234567890abcdef1234567890abcdef12"

				c, rec := setupEchoContext(http.MethodGet, fmt.Sprintf("%s?appID=%s&count=1", tc.endpoint, upperCaseAppID))

				// Expect KMS to be called with lowercase appID
				mockKMS.EXPECT().
					DeriveMnemonic(gomock.Any(), lowerCaseAppID).
					Return(testMnemonic, nil)

				mockKMS.EXPECT().
					SignMessage(gomock.Any(), gomock.Any()).
					Return([]byte("test-signature"), nil)

				err := tc.handler(c, logger, mockKMS)

				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rec.Code)

				data := unmarshalAddressesResponse(t, tc, rec)
				if tc.hasAppID {
					require.Equal(t, lowerCaseAppID, data.AppID)
				}
			})

			t.Run("mixed case appID is lowercased", func(t *testing.T) {
				mixedCaseAppID := "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12"
				lowerCaseAppID := "0xabcdef1234567890abcdef1234567890abcdef12"

				c, rec := setupEchoContext(http.MethodGet, fmt.Sprintf("%s?appID=%s&count=1", tc.endpoint, mixedCaseAppID))

				// Expect KMS to be called with lowercase appID
				mockKMS.EXPECT().
					DeriveMnemonic(gomock.Any(), lowerCaseAppID).
					Return(testMnemonic, nil)

				mockKMS.EXPECT().
					SignMessage(gomock.Any(), gomock.Any()).
					Return([]byte("test-signature"), nil)

				err := tc.handler(c, logger, mockKMS)

				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rec.Code)

				data := unmarshalAddressesResponse(t, tc, rec)
				if tc.hasAppID {
					require.Equal(t, lowerCaseAppID, data.AppID)
				}
			})

			t.Run("already lowercase appID remains unchanged", func(t *testing.T) {
				lowerCaseAppID := "0xabcdef1234567890abcdef1234567890abcdef12"

				c, rec := setupEchoContext(http.MethodGet, fmt.Sprintf("%s?appID=%s&count=1", tc.endpoint, lowerCaseAppID))

				// Expect KMS to be called with the same lowercase appID
				mockKMS.EXPECT().
					DeriveMnemonic(gomock.Any(), lowerCaseAppID).
					Return(testMnemonic, nil)

				mockKMS.EXPECT().
					SignMessage(gomock.Any(), gomock.Any()).
					Return([]byte("test-signature"), nil)

				err := tc.handler(c, logger, mockKMS)

				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rec.Code)

				data := unmarshalAddressesResponse(t, tc, rec)
				if tc.hasAppID {
					require.Equal(t, lowerCaseAppID, data.AppID)
				}
			})
		})
	}
}
