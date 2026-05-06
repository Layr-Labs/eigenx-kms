package chainclient

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSanitizeRPCError_NilPassthrough(t *testing.T) {
	if got := sanitizeRPCError(nil); got != nil {
		t.Fatalf("nil input should return nil, got %v", got)
	}
}

func TestSanitizeRPCError_RedactsKnownLeakyShapes(t *testing.T) {
	// Each input is an error string observed or plausible from go-ethereum's
	// HTTP transport. Every one of these would leak an API key if %w-wrapped
	// into a response body. After sanitize, the error message must not contain
	// any substring of the original URL.
	cases := []struct {
		name string
		in   string
	}{
		{
			name: "quicknode TLS internal error (real sepolia-prod incident)",
			in:   `Post "https://shy-dawn-bridge.ethereum-sepolia.quiknode.pro/c78e031cc0e861f82bd1011aa298ffa872b2d634/": remote error: tls: internal error`,
		},
		{
			name: "alchemy 403",
			in:   `Post "https://eth-mainnet.g.alchemy.com/v2/super-secret-api-key": 403 Forbidden`,
		},
		{
			name: "ankr EOF",
			in:   `Post "https://rpc.ankr.com/eth/redacted-api-key-value": EOF`,
		},
		{
			name: "websocket",
			in:   `failed to dial wss://rpc.example.com/v2/apikey123: dial timeout`,
		},
		{
			name: "URL embedded in JSON-ish payload",
			in:   `{"url":"https://foo.example.com/bar","err":"boom"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := sanitizeRPCError(errors.New(tc.in))
			if out == nil {
				t.Fatalf("non-nil input should return non-nil error")
			}
			msg := out.Error()
			// The whole point: no substring of the original can survive.
			for _, bad := range []string{"http://", "https://", "ws://", "wss://"} {
				if strings.Contains(msg, bad) {
					t.Errorf("sanitized message still contains %q: %s", bad, msg)
				}
			}
			// Sentinel comparison — gives callers a stable hook if they ever
			// want to branch on "RPC call failed" vs other errors.
			if !errors.Is(out, errRPCCallFailed) {
				t.Errorf("sanitized error should match errRPCCallFailed sentinel")
			}
		})
	}
}

func TestSanitizeRPCError_WrappedContextPreserved(t *testing.T) {
	// Callers wrap with fmt.Errorf("%w", sanitizeRPCError(err)) to keep the
	// static operation name. Make sure that wrapping still works and that the
	// outer message does not leak the input.
	leaky := errors.New(`Post "https://secret.quiknode.pro/apikey/": EOF`)
	wrapped := fmt.Errorf("failed to check image allowlist: %w", sanitizeRPCError(leaky))

	want := "failed to check image allowlist: rpc call failed"
	if got := wrapped.Error(); got != want {
		t.Errorf("wrapped message = %q, want %q", got, want)
	}
	if !errors.Is(wrapped, errRPCCallFailed) {
		t.Errorf("wrapped error should still satisfy errors.Is(errRPCCallFailed)")
	}
}
