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

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
)

//Public Key Resource Types
const (
	KeyFile     int = 0 //public key is retrieved from a file using the provided file path
	KeyString       = 1 //public key is retrieved as a string from the environment
	KeycloakUrl     = 2 //Public key is retrieved from keycloak service at the provided url
)

type AuthRouteFunction func(c echo.Context, store interface{}, roles []int, claims JwtClaim) bool
type AuthMiddlewareFunction func(c echo.Context, store interface{}, claims JwtClaim) bool

type Auth struct {
	//VerifyKey      *rsa.PublicKey
	VerifyKeys     []*rsa.PublicKey
	Aud            string
	AuthRoute      AuthRouteFunction
	AuthMiddleware AuthMiddlewareFunction
	Store          interface{}
}

func (a *Auth) AuthorizeMiddleware(handler echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		auth := c.Request().Header.Get(echo.HeaderAuthorization)
		tokenString := strings.TrimPrefix(auth, "Bearer ")
		claims, err := a.marshalJwt(tokenString)
		if err != nil || Contains_string(claims.Aud, a.Aud) {
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

func (a *Auth) AuthorizeRoute(handler echo.HandlerFunc, roles ...int) echo.HandlerFunc {
	return func(c echo.Context) error {
		auth := c.Request().Header.Get(echo.HeaderAuthorization)
		tokenString := strings.TrimPrefix(auth, "Bearer ")
		return a.authorization(tokenString, handler, c, roles)
	}
}

func (a *Auth) AuthorizeForm(handler echo.HandlerFunc, roles ...int) echo.HandlerFunc {
	return func(c echo.Context) error {
		tokenString := c.FormValue("authorization")
		return a.authorization(tokenString, handler, c, roles)
	}
}

func (a *Auth) authorization(tokenString string, handler echo.HandlerFunc, c echo.Context, roles []int) error {
	claims, err := a.marshalJwt(tokenString)
	if err != nil || Contains_string(claims.Aud, a.Aud) {
		log.Print(err)
		return echo.NewHTTPError(http.StatusUnauthorized, "bad token")
	}
	if a.AuthRoute != nil && a.AuthRoute(c, a.Store, roles, claims) {
		return handler(c)
	} else {
		return echo.NewHTTPError(http.StatusUnauthorized, "")
	}
}

type VerificationKeyOptions struct {
	KeySource int
	KeyVal    string
}

func (a *Auth) LoadVerificationKey(options VerificationKeyOptions) error {
	switch options.KeySource {
	case KeyString:
		return a.SetVerificationKey(options.KeyVal)
	case KeyFile:
		return a.LoadVerificationKeyFile(options.KeyVal)
	case KeycloakUrl:
		realmInfo, err := FetchKeycloakRealmInfo(options.KeyVal)
		if err != nil {
			return err
		}
		return a.SetVerificationKey(realmInfo.PublicKey)
	}
	return errors.New("Invalid Public Key Source")
}

func (a *Auth) SetVerificationKey(key string) error {
	key = fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", key)
	pk, err := jwt.ParseRSAPublicKeyFromPEM([]byte(key))
	if err != nil {
		return err
	}
	a.VerifyKeys = append(a.VerifyKeys, pk)
	return nil
}

func (a *Auth) LoadVerificationKeyFile(filePath string) error {
	publicKeyBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}
	return a.loadVerificationKey(publicKeyBytes)
}

func (a *Auth) loadVerificationKey(bytes []byte) error {
	pk, err := jwt.ParseRSAPublicKeyFromPEM(bytes)
	if err != nil {
		return err
	}
	a.VerifyKeys = append(a.VerifyKeys, pk)
	return nil
}

func (a *Auth) marshalJwt(tokenString string) (JwtClaim, error) {

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return a.VerifyKeys[0], nil
	})
	if err != nil {
		return JwtClaim{}, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		jwtUser := JwtClaim{
			Sub:      claims["sub"].(string),
			Aud:      marshalAud(claims["aud"]),
			Roles:    getArray(claims["roles"]),
			UserName: claims["preferred_username"].(string),
			Email:    claims["email"].(string),
			Claims:   claims,
		}
		return jwtUser, nil
	} else {
		return JwtClaim{}, errors.New("Invalid Token")
	}
}

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
			Sub:      claims["sub"].(string),
			Aud:      marshalAud(claims["aud"]),
			Roles:    getArray(claims["roles"]),
			UserName: claims["preferred_username"].(string),
			Email:    claims["email"].(string),
			Claims:   claims,
		}
		return jwtUser, nil
	} else {
		return JwtClaim{}, errors.New("Invalid Token")
	}

}

func loadKeyFile(filePath string) (*rsa.PublicKey, error) {
	publicKeyBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
}

func getArray(data interface{}) []string {
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

func Contains(a []int, x int) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

func Contains_string(s []string, t string) bool {
	for _, n := range s {
		if t == n {
			return true
		}
	}
	return false
}
