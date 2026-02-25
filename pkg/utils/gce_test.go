package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractAppIDFromInstanceName(t *testing.T) {
	tests := []struct {
		name         string
		instanceName string
		wantAppID    string
		wantErr      bool
	}{
		{
			name:         "valid: prefix-appid",
			instanceName: "prefix-appid",
			wantAppID:    "appid",
			wantErr:      false,
		},
		{
			name:         "valid: multi-part with last as app ID",
			instanceName: "a-b-c-d",
			wantAppID:    "d",
			wantErr:      false,
		},
		{
			name:         "valid: ethereum address as app ID",
			instanceName: "eigenx-0x1234567890abcdef1234567890abcdef12345678",
			wantAppID:    "0x1234567890abcdef1234567890abcdef12345678",
			wantErr:      false,
		},
		{
			name:         "valid: complex prefix",
			instanceName: "my-compute-instance-prod-us-west-0xabc123",
			wantAppID:    "0xabc123",
			wantErr:      false,
		},
		{
			name:         "invalid: no delimiter",
			instanceName: "nodelimiter",
			wantAppID:    "",
			wantErr:      true,
		},
		{
			name:         "invalid: empty string",
			instanceName: "",
			wantAppID:    "",
			wantErr:      true,
		},
		{
			name:         "invalid: single character (no delimiter)",
			instanceName: "x",
			wantAppID:    "",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractAppIDFromInstanceName(tt.instanceName)
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), "invalid instance name")
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.wantAppID, got)
			}
		})
	}
}
