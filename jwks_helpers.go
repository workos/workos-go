// @oagen-ignore-file

package workos

import "fmt"

// GetJWKSURL builds the JWKS URL for a given client ID.
func GetJWKSURL(baseURL string, clientID string) string {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return fmt.Sprintf("%s/sso/jwks/%s", baseURL, clientID)
}

// JWKSURLFromClient builds the JWKS URL using the client's configured base URL and client ID.
func (c *Client) JWKSURLFromClient() string {
	return GetJWKSURL(c.baseURL, c.clientID)
}
