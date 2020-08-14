package common

// ListMetadata contains pagination options for WorkOS records.
type ListMetadata struct {
	// Pagination cursor to receive records before a provided ID.
	Before string `json:"before"`

	// Pagination cursor to receive records after a provided ID.
	After string `json:"after"`
}
