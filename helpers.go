// @oagen-ignore-file

package workos

// Ptr returns a pointer to v. Use this to pass literal values where the SDK
// expects a pointer to an optional field.
func Ptr[T any](v T) *T { return &v }

// String returns a pointer to s.
func String(s string) *string { return &s }

// Bool returns a pointer to b.
func Bool(b bool) *bool { return &b }

// Int returns a pointer to i.
func Int(i int) *int { return &i }
