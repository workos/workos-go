// Package sso provide functions and client to communicate with WorkOS SSO API.
package sso

const (
	version = "0.0.1"
)

// ConnectionType represents a connection type.
type ConnectionType string

// Constants that enumerate the available connection types.
const (
	AzureSAML ConnectionType = "AzureSAML"
	OktaSAML  ConnectionType = "OktaSAML"
)
