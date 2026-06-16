package chainclient

import "errors"

// errRPCCallFailed is returned in place of RPC call errors that may embed the
// endpoint URL. go-ethereum formats HTTP transport errors as
// `Post "https://host/path": <reason>`, and Alchemy/QuickNode/Ankr-style
// endpoints carry API keys in the path. Any caller that logs or serializes
// the error leaks the credential — including the TEE launcher, which writes
// the KMS response body to public stdout under
// tee.launch_policy.log_redirect=always.
//
// Operators debugging RPC failures should reproduce against the endpoint
// directly (reading the URL from Secret Manager in an authorized context)
// instead of relying on the error message.
var errRPCCallFailed = errors.New("rpc call failed")

// sanitizeRPCError discards the original error and returns a generic sentinel.
// The caller is expected to wrap with fmt.Errorf(%w) to preserve the operation
// context (which is a static string we control and cannot leak).
func sanitizeRPCError(err error) error {
	if err == nil {
		return nil
	}
	return errRPCCallFailed
}
