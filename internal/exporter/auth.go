package exporter

import (
	"context"
	"net/http"
	"time"

	"solace_exporter/internal/config"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

var OAuthAccessToken string
var OAuthTokenExpiry time.Time

// setAuthHeader sets the appropriate authentication header on the request based on the configured auth type.
// It returns a function that can be used to set the header on an http.Request, or an error if there was an issue obtaining an OAuth token.
func (e *Exporter) setAuthHeader() (func(*http.Request), error) {
	if e.config.SEMPAuth.Scheme == config.AuthSchemeBasic {
		return func(request *http.Request) {
			request.SetBasicAuth(e.config.SEMPAuth.Username, e.config.SEMPAuth.Password)
		}, nil
	}
	if e.config.SEMPAuth.Scheme == config.AuthSchemeOAuth {
		token, err := e.getOAuthToken()
		if err != nil {
			return nil, err
		}
		return func(request *http.Request) {
			request.Header.Set("Authorization", "Bearer "+token)
		}, nil
	}

	// Optionally default to no auth
	return func(request *http.Request) {}, nil
}

// getOAuthToken retrieves a new OAuth token using the client credentials flow if the current token is expired or about to expire.
func (e *Exporter) getOAuthToken() (string, error) {
	if OAuthAccessToken != "" && time.Now().Before(OAuthTokenExpiry.Add(-time.Minute*5)) {
		return OAuthAccessToken, nil
	}

	client := e.basicHTTPClient()
	reqContext := context.WithValue(context.Background(), oauth2.HTTPClient, &client)

	cc := &clientcredentials.Config{
		ClientID:     e.config.SEMPAuth.OAuthClientID,
		ClientSecret: e.config.SEMPAuth.OAuthClientSecret,
		TokenURL:     e.config.SEMPAuth.OAuthTokenURL,
		Scopes:       []string{e.config.SEMPAuth.OAuthClientScope},
	}

	token, err := cc.Token(reqContext)
	if err != nil {
		return "", err
	}

	OAuthAccessToken = token.AccessToken
	OAuthTokenExpiry = token.Expiry

	return OAuthAccessToken, nil
}
