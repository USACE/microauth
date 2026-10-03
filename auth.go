package microauth

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v5"
)

// Public Key Resource Types
const (
	// KeyFile indicates the public key is retrieved from a file using the provided file path.
	KeyFile int = 0
	// KeyString indicates the public key is retrieved as a string from the environment.
	KeyString = 1
	// KeycloakUrl indicates the public key is retrieved from Keycloak service at the provided URL.
	KeycloakUrl = 2
)

// AuthRouteFunction defines the signature for custom route-level authorization logic.
type AuthRouteFunction func(c *echo.Context, store interface{}, roles []int, claims JwtClaim) bool

// AuthMiddlewareFunction defines the signature for custom middleware-level authorization logic.
type AuthMiddlewareFunction func(c *echo.Context, store interface{}, claims JwtClaim) bool

// Auth provides the core functionality for JWT verification and Echo middleware/route authorization.
type Auth struct {
	// VerifyKeys holds the RSA public keys used to verify incoming JWT signatures.
	VerifyKeys []*rsa.PublicKey
	// Aud is the expected audience claim that must be present in the JWT.
	Aud string
	// AuthRoute is a custom callback for role-based or claim-based route authorization.
	AuthRoute AuthRouteFunction
	// AuthMiddleware is a custom callback for middleware-level authorization.
	AuthMiddleware AuthMiddlewareFunction
	// Store is an arbitrary data structure passed to AuthRoute and AuthMiddleware callbacks.
	Store interface{}
}

// AuthorizeMiddleware returns an Echo middleware that validates the Bearer token in the Authorization header.
// It verifies the signature and ensure the 'aud' claim matches the Auth.Aud configuration.
func (a *Auth) AuthorizeMiddleware(handler echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		auth := c.Request().Header.Get(echo.HeaderAuthorization)
		tokenString := strings.TrimPrefix(auth, "Bearer ")
		claims, err := a.marshalJwt(tokenString)
		if err != nil || !Contains_string(claims.Aud, a.Aud) {
			log.Print(err)
			return echo.NewHTTPError(http.StatusUnauthorized, "bad token")
		}
		if a.AuthMiddleware != nil && a.AuthMiddleware(c, a.Store, claims) {
			return handler(c)
		} else {
			return echo.NewHTTPError(http.StatusUnauthorized, "")
		}
	}
}

// AuthorizeRoute returns an Echo handler wrapper that validates the Bearer token and checks if the user
// possesses at least one of the provided roles.
func (a *Auth) AuthorizeRoute(handler echo.HandlerFunc, roles ...int) echo.HandlerFunc {
	return func(c *echo.Context) error {
		auth := c.Request().Header.Get(echo.HeaderAuthorization)
		tokenString := strings.TrimPrefix(auth, "Bearer ")
		return a.authorization(tokenString, handler, c, roles)
	}
}

// AuthorizeForm returns an Echo handler wrapper that validates the token passed in the "authorization" form field.
func (a *Auth) AuthorizeForm(handler echo.HandlerFunc, roles ...int) echo.HandlerFunc {
	return func(c *echo.Context) error {
		tokenString := c.FormValue("authorization")
		return a.authorization(tokenString, handler, c, roles)
	}
}

// authorization performs the core JWT verification and role check logic.
func (a *Auth) authorization(tokenString string, handler echo.HandlerFunc, c *echo.Context, roles []int) error {
	claims, err := a.marshalJwt(tokenString)
	if err != nil || !Contains_string(claims.Aud, a.Aud) {
		log.Print(err)
		return echo.NewHTTPError(http.StatusUnauthorized, "bad token")
	}
	if a.AuthRoute != nil && a.AuthRoute(c, a.Store, roles, claims) {
		return handler(c)
	} else {
		return echo.NewHTTPError(http.StatusUnauthorized, "")
	}
}

// VerificationKeyOptions configures how a public key should be loaded.
type VerificationKeyOptions struct {
	// KeySource determines the method of retrieval (KeyFile, KeyString, KeycloakUrl).
	KeySource int
	// KeyVal is the actual key string, file path, or Keycloak URL.
	KeyVal string
}

// LoadVerificationKey loads a public key from the specified source and adds it to VerifyKeys.
func (a *Auth) LoadVerificationKey(options VerificationKeyOptions) error {
	switch options.KeySource {
	case KeyString:
		return a.SetVerificationKey(options.KeyVal)
	case KeyFile:
		return a.LoadVerificationKeyFile(options.KeyVal)
	case KeycloakUrl:
		realmInfo, err := FetchKeycloakRealmInfo(options.KeyVal, true)
		if err != nil {
			return err
		}
		return a.SetVerificationKey(realmInfo.PublicKey)
	}
	return errors.New("Invalid Public Key Source")
}

// SetVerificationKey takes a PEM-formatted public key string, wraps it in PEM headers, and adds it to VerifyKeys.
func (a *Auth) SetVerificationKey(key string) error {
	key = fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", key)
	pk, err := jwt.ParseRSAPublicKeyFromPEM([]byte(key))
	if err != nil {
		return err
	}
	a.VerifyKeys = append(a.VerifyKeys, pk)
	return nil
}

// LoadVerificationKeyFile reads a public key from a file and adds it to VerifyKeys.
func (a *Auth) LoadVerificationKeyFile(filePath string) error {
	publicKeyBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}
	return a.loadVerificationKey(publicKeyBytes)
}

// loadVerificationKey parses PEM bytes and adds the resulting key to VerifyKeys.
func (a *Auth) loadVerificationKey(bytes []byte) error {
	pk, err := jwt.ParseRSAPublicKeyFromPEM(bytes)
	if err != nil {
		return err
	}
	a.VerifyKeys = append(a.VerifyKeys, pk)
	return nil
}

// marshalJwt parses a single token string using the first available verification key.
func (a *Auth) marshalJwt(tokenString string) (JwtClaim, error) {

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return a.VerifyKeys[0], nil
	})
	if err != nil {
		return JwtClaim{}, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		jwtUser := JwtClaim{
			Sub:      readClaim("sub", claims),
			Aud:      marshalAud(claims["aud"]),
			Roles:    readClaimArray(claims["roles"]),
			UserName: readClaim("preferred_username", claims),
			Email:    readClaim("email", claims),
			Claims:   claims,
		}
		return jwtUser, nil
	} else {
		return JwtClaim{}, errors.New("Invalid Token")
	}
}

// LoadVerificationKeys reads all .pem files from a directory and adds them to VerifyKeys.
func (a *Auth) LoadVerificationKeys(fieldPath string) error {
	files, err := ioutil.ReadDir(fieldPath)
	if err != nil {
		return err
	}
	for _, v := range files {
		if ext := filepath.Ext(v.Name()); ext == ".pem" {
			fmt.Printf("Loading Public Key: %s\n", v.Name())
			pk, err := loadKeyFile(fieldPath + "/" + v.Name())
			if err != nil {
				return err
			}
			a.VerifyKeys = append(a.VerifyKeys, pk)
		}
	}
	return nil
}

// marshalJwts parses a token string by attempting all loaded verification keys.
func (a *Auth) marshalJwts(tokenString string) (JwtClaim, error) {
	var token *jwt.Token = nil
	var err error
	for _, verificationKey := range a.VerifyKeys {
		token, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return verificationKey, nil
		})
		if err == nil {
			break
		}
	}

	if token == nil {
		return JwtClaim{}, errors.New("Invalid Token")
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		jwtUser := JwtClaim{
			Sub:      readClaim("sub", claims),
			Aud:      marshalAud(claims["aud"]),
			Roles:    readClaimArray(claims["roles"]),
			UserName: readClaim("preferred_username", claims),
			Email:    readClaim("email", claims),
			Claims:   claims,
		}
		return jwtUser, nil
	} else {
		return JwtClaim{}, errors.New("Invalid Token")
	}

}

func readClaim(claimname string, claims jwt.MapClaims) string {
	claim, ok := claims[claimname]
	if !ok || claim == nil {
		return ""
	}
	return claim.(string)
}

func loadKeyFile(filePath string) (*rsa.PublicKey, error) {
	publicKeyBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
}

func readClaimArray(data interface{}) []string {
	a := []string{}
	if data != nil {
		claimarray := data.([]interface{})
		for _, c := range claimarray {
			a = append(a, c.(string))
		}
	}
	return a
}

func marshalAud(aud interface{}) []string {
	a := []string{}
	switch aud.(type) {
	case []interface{}:
		for _, v := range aud.([]interface{}) {
			a = append(a, v.(string))
		}
	case interface{}:
		a = append(a, aud.(string))
	}
	return a
}

// Contains checks if an integer exists in a slice of integers.
func Contains(a []int, x int) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

// Contains_string checks if a string exists in a slice of strings.
func Contains_string(s []string, t string) bool {
	for _, n := range s {
		if t == n {
			return true
		}
	}
	return false
}
