// @oagen-ignore-file

package workos

import "fmt"

// clientSecret returns the API key for a request that sends it as
// client_secret. method is the name of the calling method, for the error
// message. Generated code calls clientSecret by this name and signature.
//
// A client with no API key gets "", and the caller leaves the field out of
// the request: a public client runs a PKCE flow that way. A client built with
// NewClientWithCredentials gets an error instead, because it has no API key
// to send as the secret. The caller returns that error before it sends
// anything, so no access token is fetched for the request either.
func (c *Client) clientSecret(method string) (string, error) {
	if c.apiKey != "" {
		return c.apiKey, nil
	}
	// NewClientWithCredentials is the only place that installs this
	// transport. A PublicClient's inner client has no HTTP client at all.
	if c.httpClient != nil {
		if _, ok := c.httpClient.Transport.(*credentialsTransport); ok {
			return "", fmt.Errorf("workos: %s needs an API key: this request sends it as the client secret. A client that authenticates with workload identity has no API key, so use a client built with one for this call.", method)
		}
	}
	return "", nil
}
