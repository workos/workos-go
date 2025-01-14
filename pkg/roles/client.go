package roles

// RoleType represents the type of a Role.
type RoleType string

// Constants that enumerate the type of a Role.
const (
	Environment  RoleType = "EnvironmentRole"
	Organization RoleType = "OrganizationRole"
)

// Role contains data about a WorkOS Role.
type Role struct {
	// The Role's unique identifier.
	ID string `json:"id"`

	Name string `json:"name"`

	// The Role's slug key for referencing it in code.
	Slug string `json:"slug"`

	Description string `json:"description"`

	// The type of role
	Type RoleType `json:"type"`

	// The timestamp of when the Role was created.
	CreatedAt string `json:"created_at"`

	// The timestamp of when the Role was updated.
	UpdatedAt string `json:"updated_at"`
}
