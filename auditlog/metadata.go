package auditlog

var globalMetadata = map[string]interface{}{}

// SetMetadata sets the metadata to be merged into an Event before it is
// published to WorkOS. The metadata set through this function will be merged in
// to every event within this process.
func SetMetadata(metadata map[string]interface{}) {
	for k, v := range metadata {
		globalMetadata[k] = v
	}
}
