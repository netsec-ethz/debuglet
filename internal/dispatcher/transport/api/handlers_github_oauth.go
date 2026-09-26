package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
)

const (
	githubOAuthStateCookie = "github_oauth_state"
	githubOAuthPKCECookie  = "github_oauth_pkce"
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

// GetGitHubLogin starts the OAuth authorization-code flow. The state is an
// unpredictable, short-lived, HttpOnly cookie; no return URL comes from the
// request, so the callback cannot become an open redirect.
func (h *Handler) GetGitHubLogin(c echo.Context) error {
	if !h.githubOAuthReady() {
		return apiError(http.StatusNotFound, CodeNotFound, "GitHub login is not enabled")
	}
	stateRaw := make([]byte, 32)
	verifierRaw := make([]byte, 32)
	if _, err := rand.Read(stateRaw); err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to start GitHub login", err)
	}
	if _, err := rand.Read(verifierRaw); err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to start GitHub login", err)
	}
	state := base64.RawURLEncoding.EncodeToString(stateRaw)
	verifier := base64.RawURLEncoding.EncodeToString(verifierRaw)
	challengeHash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])
	c.SetCookie(&http.Cookie{Name: githubOAuthStateCookie, Value: state, Path: "/", MaxAge: 600,
		HttpOnly: true, Secure: h.cookieSecure, SameSite: http.SameSiteLaxMode})
	c.SetCookie(&http.Cookie{Name: githubOAuthPKCECookie, Value: verifier, Path: "/", MaxAge: 600,
		HttpOnly: true, Secure: h.cookieSecure, SameSite: http.SameSiteLaxMode})
	query := url.Values{"client_id": {h.githubOAuth.ClientID}, "redirect_uri": {h.githubOAuth.CallbackURL}, "state": {state},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	return c.Redirect(http.StatusFound, githubAuthorizeURL+"?"+query.Encode())
}

func (h *Handler) GetGitHubCallback(c echo.Context) error {
	if !h.githubOAuthReady() {
		return apiError(http.StatusNotFound, CodeNotFound, "GitHub login is not enabled")
	}
	stateCookie, err := c.Cookie(githubOAuthStateCookie)
	verifierCookie, verifierErr := c.Cookie(githubOAuthPKCECookie)
	h.clearGitHubLoginCookies(c)
	state := c.QueryParam("state")
	if err != nil || state == "" || len(state) > 128 || subtle.ConstantTimeCompare([]byte(state), []byte(stateCookie.Value)) != 1 {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "invalid GitHub login state")
	}
	if verifierErr != nil || len(verifierCookie.Value) < 43 || len(verifierCookie.Value) > 128 {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "invalid GitHub login verifier")
	}
	code := strings.TrimSpace(c.QueryParam("code"))
	if code == "" || len(code) > 512 {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "GitHub did not return an authorization code")
	}
	profile, err := h.githubProfile(c.Request().Context(), code, verifierCookie.Value)
	if err != nil {
		return apiErrorFrom(http.StatusBadGateway, CodeInternal, "GitHub login failed", err)
	}
	tx, err := h.db.BeginTx(c.Request().Context(), nil)
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to create a session", err)
	}
	defer tx.Rollback()
	userID, err := githubOAuthUser(c.Request().Context(), tx, profile)
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to store the GitHub account", err)
	}
	token, csrf, expires, err := issueSession(c.Request().Context(), database.New(tx), userID)
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to create a session", err)
	}
	if err := tx.Commit(); err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to create a session", err)
	}
	h.writeSessionCookies(c, token, csrf, expires)
	return c.Redirect(http.StatusFound, h.githubOAuth.SuccessURL)
}

func (h *Handler) clearGitHubLoginCookies(c echo.Context) {
	for _, name := range []string{githubOAuthStateCookie, githubOAuthPKCECookie} {
		c.SetCookie(&http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: true, Secure: h.cookieSecure, SameSite: http.SameSiteLaxMode})
	}
}

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
		return githubUser{}, fmt.Errorf("token exchange returned status %d (%s)", response.StatusCode, token.Error)
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

func githubOAuthUser(ctx context.Context, tx *sql.Tx, profile githubUser) (int64, error) {
	subject := strconv.FormatInt(profile.ID, 10)
	queries := database.New(tx)
	userID, err := queries.GetOAuthIdentity(ctx, database.GetOAuthIdentityParams{Provider: "github", Subject: subject})
	if err == nil {
		err = queries.UpdateOAuthIdentityLogin(ctx, database.UpdateOAuthIdentityLoginParams{Provider: "github", Subject: subject, Login: profile.Login, UpdatedAt: models.NewUTCTime(time.Now().UTC())})
		return userID, err
	}
	if err != sql.ErrNoRows {
		return 0, err
	}
	name := strings.TrimSpace(profile.Name)
	if name == "" {
		name = profile.Login
	}
	user, err := queries.CreateUserWithRole(ctx, database.CreateUserWithRoleParams{Uuid: uuid.New(), Name: name, Role: RoleUser})
	if err != nil {
		return 0, err
	}
	now := models.NewUTCTime(time.Now().UTC())
	err = queries.CreateOAuthIdentity(ctx, database.CreateOAuthIdentityParams{Provider: "github", Subject: subject, UserID: user.ID, Login: profile.Login, CreatedAt: now, UpdatedAt: now})
	return user.ID, err
}
