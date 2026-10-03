package microauth

// JwtClaim represents the extracted claims from a validated JWT.
type JwtClaim struct {
	// Sub is the subject of the token (typically the user ID).
	Sub      string
	// Aud is the audience(s) the token is intended for.
	Aud      []string
	// Roles contains the user roles extracted from the 'roles' claim.
	Roles    []string
	// UserName is the preferred username of the user.
	UserName string
	// Email is the email address of the user.
	Email    string
	// Claims contains the full map of claims from the token.
	Claims   map[string]interface{}
}
