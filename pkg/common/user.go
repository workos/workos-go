package common

// User contains data about a particular User.
type User struct {
	// The User's unique identifier.
	ID string `json:"id"`

	// The User's first name.
	FirstName string `json:"first_name"`

	// The User's last name.
	LastName string `json:"last_name"`

	// The User's email.
	Email string `json:"email"`

	// The timestamp of when the User was created.
	CreatedAt string `json:"created_at"`

	// The timestamp of when the User was updated.
	UpdatedAt string `json:"updated_at"`

	// Whether the User email is verified.
	EmailVerified bool `json:"email_verified"`

	// A URL reference to an image representing the User.
	ProfilePictureURL string `json:"profile_picture_url"`

	// The timestamp when the user last signed in.
	LastSignInAt string `json:"last_sign_in_at"`

	// The User's external id.
	ExternalID string `json:"external_id"`

	// The User's metadata.
	Metadata map[string]string `json:"metadata"`
}
