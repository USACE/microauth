package microauth

type JwtClaim struct {
	Sub      string
	Aud      []string
	Roles    []string
	UserName string
	Email    string
	Claims   map[string]interface{}
}
