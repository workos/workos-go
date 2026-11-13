// @oagen-ignore-file

package workos

import "unicode/utf8"

// Error codes the SDK produces itself, for failures that have no OAuth code.
// Codes returned by the token endpoint are passed through unchanged.
const (
	workloadIdentityExchangeFailed       = "exchange_failed"
	workloadIdentityInvalidResponse      = "invalid_response"
	workloadIdentityProviderFailed       = "provider_failed"
	workloadIdentityInvalidConfiguration = "invalid_configuration"
)

// workloadIdentityDescriptionLimit is the most characters of a description
// that a WorkloadIdentityError keeps.
const workloadIdentityDescriptionLimit = 500

// workloadIdentityHints maps an error code to the hint shown with it. This is
// the only place the wording lives.
var workloadIdentityHints = map[string]string{
	"invalid_grant":       "The identity token was not accepted. Check its issuer, audience and subject claims against the trust rule, and that it has not expired. A token that was already exchanged is also refused: each exchange needs a new identity token.",
	"invalid_target":      "The resource is not one the token endpoint accepts. Leave the resource unset to use the default, https://api.workos.com.",
	"invalid_client":      "The client ID is unknown, or the application has no enabled trust rule. Check that the client ID is the M2M application that has the trust rule.",
	"unauthorized_client": "This application cannot use workload identity federation. Check that the feature is enabled for your team and that the application is bound to a non-production environment.",
	"invalid_scope":       "The requested scope is not allowed for this application. Fix the scope or leave it unset.",
	"invalid_request":     "The token request was malformed. Check that the token URL points at the `/oauth2/token` endpoint.",

	workloadIdentityExchangeFailed:       "The token endpoint could not be reached or kept failing. Check the token URL and try again.",
	workloadIdentityInvalidResponse:      "The token endpoint returned a response the SDK could not read. Check that the token URL points at the `/oauth2/token` endpoint.",
	workloadIdentityProviderFailed:       "The identity token provider failed, so there was no token to exchange.",
	workloadIdentityInvalidConfiguration: "Workload identity credentials are missing a required setting.",
}

// workloadIdentityDefaultHint is the hint for an OAuth code with no entry in
// workloadIdentityHints.
const workloadIdentityDefaultHint = "The token endpoint rejected the exchange."

// WorkloadIdentityError reports that workload identity credentials could not
// produce an access token. A request that fails this way is not retried: the
// error is a verdict on the credentials, not a network fault.
//
// Inspect it with errors.As:
//
//	var wifErr *workos.WorkloadIdentityError
//	if errors.As(err, &wifErr) {
//		log.Printf("workload identity failed (%s): %s", wifErr.Code, wifErr.Hint)
//	}
type WorkloadIdentityError struct {
	// Code is the OAuth error code returned by the token endpoint, such as
	// "invalid_grant" or "invalid_client", or one of the SDK's own codes:
	// "exchange_failed", "invalid_response", "provider_failed" or
	// "invalid_configuration".
	Code string
	// Description is the token endpoint's error_description, or a short
	// detail for the SDK's own codes. It is cut to 500 characters and may be
	// empty.
	Description string
	// Hint is one sentence on how to fix the problem. It is never empty.
	Hint string

	cause error
}

// Error returns "workos: <code>: <hint>", followed by the description when
// there is one. It never contains an identity token or an access token.
func (e *WorkloadIdentityError) Error() string {
	msg := "workos: " + e.Code + ": " + e.Hint
	if e.Description != "" {
		msg += " " + e.Description
	}
	return msg
}

// Unwrap returns the underlying failure, such as the identity token
// provider's error, or nil.
func (e *WorkloadIdentityError) Unwrap() error { return e.cause }

func newWorkloadIdentityError(code, description string, cause error) *WorkloadIdentityError {
	hint, ok := workloadIdentityHints[code]
	if !ok {
		hint = workloadIdentityDefaultHint
	}
	return &WorkloadIdentityError{
		Code:        code,
		Description: truncateRunes(description, workloadIdentityDescriptionLimit),
		Hint:        hint,
		cause:       cause,
	}
}

func invalidWorkloadIdentityConfiguration(description string) *WorkloadIdentityError {
	return newWorkloadIdentityError(workloadIdentityInvalidConfiguration, description, nil)
}

// truncateRunes cuts s to at most limit characters without splitting one.
func truncateRunes(s string, limit int) string {
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	return string([]rune(s)[:limit])
}
