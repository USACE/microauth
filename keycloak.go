package microauth

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	keycloakRealmTemplate string        = "%s/realms/%s"
	keycloakTokenTemplate string        = "%s/realms/%s/protocol/openid-connect/token"
	defaultTimeoutSeconds time.Duration = 10 * time.Second
)

type KeycloakRealmInfo struct {
	AccountService  string `json:"account-service"`
	PublicKey       string `json:"public_key"`
	Realm           string `json:"realm"`
	TokenService    string `json:"token-service"`
	TokensNotBefore int    `json:"tokens-not-before"`
}

func (kri *KeycloakRealmInfo) RsaPublicKey() (*rsa.PublicKey, error) {
	key := fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", kri.PublicKey)
	return jwt.ParseRSAPublicKeyFromPEM([]byte(key))
}

type KeycloakToken struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
}

type KeycloakConfig struct {
	KeycloakUrl        string
	InsecureSkipVerify bool
	Timeout            time.Duration
}

type KeycloakService struct {
	KeycloakUrl string
	httpClient  *http.Client
}

func NewKeycloakService(cfg KeycloakConfig) *KeycloakService {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify},
		TLSHandshakeTimeout: defaultTimeoutSeconds,
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeoutSeconds
	}

	return &KeycloakService{
		KeycloakUrl: cfg.KeycloakUrl,
		httpClient: &http.Client{
			Transport: tr,
			Timeout:   cfg.Timeout, // Sets the hard limit
		},
	}
}

func (ks *KeycloakService) GetRealmInfo(ctx context.Context, realm string) (KeycloakRealmInfo, error) {
	info := KeycloakRealmInfo{}
	url := fmt.Sprintf(keycloakRealmTemplate, strings.TrimSuffix(ks.KeycloakUrl, "/"), realm)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return info, fmt.Errorf("failed to create request for realm %s: %w", realm, err)
	}
	resp, err := ks.httpClient.Do(req)
	if err != nil {
		return info, fmt.Errorf("network request failed for realm %s: %w", realm, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return info, fmt.Errorf("keycloak returned non-200 status %d for realm %s", resp.StatusCode, realm)
	}

	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return info, fmt.Errorf("failed to decode realm info for %s: %w", realm, err)
	}

	return info, err
}

type TokenExchangeInput struct {
	DelegateClientId       string
	DelegateClientSecret   string
	UserAccessToken        string
	DownstreamAud          string
	OptionalRequestedScope string
}

type TokenExchangeResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	TokenType        string `json:"token_type"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	Scope            string `json:"scope"`
}

func (ks *KeycloakService) TokenExchange(ctx context.Context, realm string, input TokenExchangeInput) (string, error) {
	tokenExchangeUrl := fmt.Sprintf(keycloakTokenTemplate, strings.TrimSuffix(ks.KeycloakUrl, "/"), realm)
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("client_id", input.DelegateClientId)
	form.Set("client_secret", input.DelegateClientSecret)
	form.Set("subject_token", input.UserAccessToken)
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Set("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Set("audience", input.DownstreamAud)

	if input.OptionalRequestedScope != "" {
		form.Set("scope", input.OptionalRequestedScope)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenExchangeUrl, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create http request for realm %s: %w", realm, err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := ks.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange network request failed for realm %s: %w", realm, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("keycloak returned status %d, and failed to read error body: %w", resp.StatusCode, err)
		}
		return "", fmt.Errorf("keycloak returned status code %d for realm %s: %s", resp.StatusCode, realm, string(bodyBytes))
	}

	var tokenResp TokenExchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode keycloak token response for realm %s: %w", realm, err)
	}

	return tokenResp.AccessToken, nil
}

func (ks *KeycloakService) DirectGrant(ctx context.Context, realm, clientID, username, password string) (KeycloakToken, error) {
	var tokenResponse KeycloakToken
	tokenUrl := fmt.Sprintf(keycloakTokenTemplate, strings.TrimSuffix(ks.KeycloakUrl, "/"), realm)

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", clientID)
	data.Set("scope", "openid profile")
	data.Set("username", username)
	data.Set("password", password)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenUrl, strings.NewReader(data.Encode()))
	if err != nil {
		return tokenResponse, fmt.Errorf("failed to create http request for realm %s: %w", realm, err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := ks.httpClient.Do(req)
	if err != nil {
		return tokenResponse, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return tokenResponse, fmt.Errorf("keycloak returned status %d, and failed to read error body: %w", resp.StatusCode, err)
		}
		return tokenResponse, fmt.Errorf("keycloak returned status code %d for realm %s: %s", resp.StatusCode, realm, string(bodyBytes))
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return tokenResponse, fmt.Errorf("failed to decode token response: %w", err)
	}

	return tokenResponse, nil
}

func (ks *KeycloakService) ValidateToken(realmInfo KeycloakRealmInfo, tokenstring string, destClaims jwt.Claims) error {
	publicKey, err := realmInfo.RsaPublicKey()
	if err != nil {
		return err
	}
	_, err = jwt.ParseWithClaims(tokenstring, destClaims, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is RSA
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}
	return err
}

/*
legecy function.  Use the KeycloakService
Fetch the public key from a keycloak instance.
realmUri string should be the full url to the realm
{host}/{context}/realms/{realm}
for example
mykeycloak/auth/realms/myrealm
*/
func FetchKeycloakRealmInfo(realmUri string, insecureSkipVerify bool) (KeycloakRealmInfo, error) {
	info := KeycloakRealmInfo{}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify},
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   defaultTimeoutSeconds, // Sets the hard limit
	}

	url := fmt.Sprintf("https://%s", realmUri)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return info, fmt.Errorf("failed to create request for realm %s: %w", realmUri, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return info, err
	}
	defer resp.Body.Close()
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&info)
	return info, err
}
