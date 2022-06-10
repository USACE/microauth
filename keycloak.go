package microauth

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
)

type KeycloakRealm struct {
	AccountService  string `json:"account-service"`
	PublicKey       string `json:"public_key"`
	Realm           string `json:"realm"`
	TokenService    string `json:"token-service"`
	TokensNotBefore int    `json:"tokens-not-before"`
}

/*
	Fetch the public key from a keycloak instance.
	realm string should be the full url to the realm
	{host}/{context}/realms/{realm}
	for example
	mykeycloak/auth/realms/myrealm
*/
func FetchRealmInfo(realm string) (KeycloakRealm, error) {
	info := KeycloakRealm{}
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	url := fmt.Sprintf("https://%s", realm)
	resp, err := http.Get(url)
	if err != nil {
		return info, err
	}
	defer resp.Body.Close()
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&info)
	return info, err
}
