package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

var githubOAuthHTTPClient = &http.Client{Timeout: 10 * time.Second}
var githubAuthorizeURL = "https://github.com/login/oauth/authorize"
var githubTokenURL = "https://github.com/login/oauth/access_token"
var githubUserURL = "https://api.github.com/user"

type githubTokenResponse struct {
	AccessToken string `json:"access_token"`
	Error       string `json:"error"`
}

type githubUser struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Name  string `json:"name"`
}

func (h *Handler) githubOAuthReady() bool {
	return h.githubOAuth.Enabled && h.githubOAuth.ClientID != "" && h.githubOAuth.ClientSecret != ""
}

func (h *Handler) GetGitHubLogin(c echo.Context) error {
	session := ""
	if caller := requestCaller(c); caller.Authenticated && caller.Cookie && !caller.API {
		session = caller.Session
	}
	return h.startProviderLogin(c, "github", "login", session)
}

func (h *Handler) GetGitHubCallback(c echo.Context) error { return h.providerCallback(c, "github") }

func (h *Handler) githubProfile(ctx context.Context, code, verifier string) (githubUser, error) {
	form := url.Values{"client_id": {h.githubOAuth.ClientID}, "client_secret": {h.githubOAuth.ClientSecret},
		"code": {code}, "redirect_uri": {h.githubOAuth.CallbackURL}, "code_verifier": {verifier}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, githubTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return githubUser{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	response, err := githubOAuthHTTPClient.Do(req)
	if err != nil {
		return githubUser{}, err
	}
	defer response.Body.Close()
	var token githubTokenResponse
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&token) != nil || token.AccessToken == "" {
		return githubUser{}, fmt.Errorf("token exchange returned status %d", response.StatusCode)
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, githubUserURL, nil)
	if err != nil {
		return githubUser{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	response, err = githubOAuthHTTPClient.Do(req)
	if err != nil {
		return githubUser{}, err
	}
	defer response.Body.Close()
	var profile githubUser
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&profile) != nil || profile.ID <= 0 || profile.Login == "" {
		return githubUser{}, fmt.Errorf("user lookup returned status %d", response.StatusCode)
	}
	return profile, nil
}
