// Package sso ...
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
