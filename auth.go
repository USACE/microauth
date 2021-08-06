package microauth

import (
	"crypto/rsa"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
)

type AuthRouteFunction func(c echo.Context, roles []int, claims JwtClaim) bool
type AuthMiddlewareFunction func(c echo.Context, claims JwtClaim) bool

type Auth struct {
	VerifyKey      *rsa.PublicKey
	Aud            string
	AuthRoute      AuthRouteFunction
	AuthMiddleware AuthMiddlewareFunction
}

func (a *Auth) AuthorizeMiddleware(handler echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		auth := c.Request().Header.Get(echo.HeaderAuthorization)
		tokenString := strings.TrimPrefix(auth, "Bearer ")
		claims, err := a.marshalJwt(tokenString)
		if err != nil || contains_string(claims.Aud, a.Aud) {
			log.Print(err)
			return echo.NewHTTPError(http.StatusUnauthorized, "bad token")
		}
		if a.AuthMiddleware != nil && a.AuthMiddleware(c, claims) {
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
	if err != nil || contains_string(claims.Aud, a.Aud) {
		log.Print(err)
		return echo.NewHTTPError(http.StatusUnauthorized, "bad token")
	}
	if a.AuthRoute != nil && a.AuthRoute(c, roles, claims) {
		return handler(c)
	} else {
		return echo.NewHTTPError(http.StatusUnauthorized, "")
	}
}

func loadKeyFile(filePath string) (*rsa.PublicKey, error) {
	publicKeyBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
}

func (a *Auth) LoadVerificationKey(filePath string) error {
	publicKeyBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}
	pk, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		return err
	}
	a.VerifyKey = pk
	return nil
}

func (a *Auth) marshalJwt(tokenString string) (JwtClaim, error) {

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return a.VerifyKey, nil
	})
	if err != nil {
		return JwtClaim{}, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		jwtUser := JwtClaim{
			Sub:      claims["sub"].(string),
			Aud:      getArray(claims["aud"]),
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

func contains(a []int, x int) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

func contains_string(s []string, t string) bool {
	for _, n := range s {
		if t == n {
			return true
		}
	}
	return false
}
