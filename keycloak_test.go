package microauth

import (
	"context"
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

var testurl string = "dev2.crrel.mil/auth/realms/cwbi"
var wantAccountService string = "https://localhost:8443/auth/realms/cwbi/account"

func TestFetchRealmInfo(t *testing.T) {
	realm := "cwbi"
	kconfig := KeycloakConfig{
		KeycloakUrl:        "http://localhost:8090/auth",
		InsecureSkipVerify: true,
	}
	ks := NewKeycloakService(kconfig)
	result, err := ks.GetRealmInfo(context.Background(), realm)
	if err != nil {
		t.Error(err)
	}

	fmt.Println(result)
	if result.AccountService != wantAccountService {
		t.Fail()
	}
}

func TestKeycloakService(t *testing.T) {
	realm := "cwbi"
	kconfig := KeycloakConfig{
		KeycloakUrl:        "http://localhost:8090/auth",
		InsecureSkipVerify: true,
	}
	ks := NewKeycloakService(kconfig)
	realmInfo, err := ks.GetRealmInfo(context.Background(), realm)
	if err != nil {
		t.Error(err)
	}

	client := "ccapi"
	username := "tb.user"
	pass := "tb.user"

	userToken, err := ks.DirectGrant(context.Background(), realm, client, username, pass)
	if err != nil {
		t.Error(err)
	}

	claims := jwt.RegisteredClaims{}
	err = ks.ValidateToken(realmInfo, userToken.AccessToken, &claims)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(claims)

	delegateToken, err := ks.TokenExchange(context.Background(), realm, TokenExchangeInput{
		DelegateClientId:     "ccapi-delegate",
		DelegateClientSecret: "thesecret",
		UserAccessToken:      userToken.AccessToken,
		DownstreamAud:        "ccapi-delegate",
	})
	if err != nil {
		t.Error(err)
	}
	fmt.Println(delegateToken)

}
