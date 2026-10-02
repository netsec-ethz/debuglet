// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"golang.org/x/oauth2"
)

const oauthLifetime = 10 * time.Minute

type externalProfile struct{ Provider, Issuer, Subject, Login, Name string }

func (h *Handler) providerReady(provider string) bool {
	switch provider {
	case "github":
		return h.githubOAuthReady()
	case "cilogon":
		return h.cilogonReady()
	}
	return false
}
func (h *Handler) providerSuccessURL(provider string) string {
	if provider == "github" {
		return h.githubOAuth.SuccessURL
	}
	return h.cilogonOIDC.SuccessURL
}
func (h *Handler) providerIssuer(provider string) string {
	if provider == "github" {
		return "https://github.com"
	}
	return h.cilogonOIDC.Issuer
}

func (h *Handler) GetAuthProviders(c echo.Context) error {
	type providerInfo struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		LoginURL string `json:"login_url"`
		Enabled  bool   `json:"enabled"`
	}
	providers := []providerInfo{}
	for _, provider := range []struct{ id, name string }{{"github", "GitHub"}, {"cilogon", "CILogon"}} {
		if h.providerReady(provider.id) {
			providers = append(providers, providerInfo{provider.id, provider.name, "/auth/" + provider.id, true})
		}
	}
	return c.JSON(http.StatusOK, struct {
		Providers       []providerInfo `json:"providers"`
		Audience        string         `json:"audience"`
		VerificationURI string         `json:"device_verification_uri"`
	}{providers, h.authPublicURL, h.deviceVerificationURL})
}

func (h *Handler) startProviderLogin(c echo.Context, provider, purpose, session string) error {
	if !h.providerReady(provider) {
		return apiError(http.StatusNotFound, CodeNotFound, "this sign-in provider is not enabled")
	}
	if err := h.limitAuthentication(c); err != nil {
		return err
	}
	state, _, err := newSecret()
	if err != nil {
		return err
	}
	verifier, _, err := newSecret()
	if err != nil {
		return err
	}
	nonce, _, err := newSecret()
	if err != nil {
		return err
	}
	stateHash, challengeHash := sha256.Sum256([]byte(state)), sha256.Sum256([]byte(verifier))
	var authorizationURL string
	if provider == "github" {
		query := url.Values{"client_id": {h.githubOAuth.ClientID}, "redirect_uri": {h.githubOAuth.CallbackURL}, "state": {state}, "code_challenge": {encodeSecret(challengeHash[:])}, "code_challenge_method": {"S256"}}
		authorizationURL = githubAuthorizeURL + "?" + query.Encode()
	} else {
		discovery, err := h.cilogonProvider(c.Request().Context())
		if err != nil {
			return apiError(http.StatusBadGateway, CodeInternal, "CILogon is temporarily unavailable; try again later")
		}
		cfg := h.cilogonClient(discovery)
		authorizationURL = cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce))
	}
	queries := database.New(h.db)
	now := models.NewUTCTime(time.Now().UTC())
	if err := queries.DeleteExpiredOAuthAttempts(c.Request().Context(), now); err != nil {
		return err
	}
	inserted, err := queries.CreateOAuthAttempt(c.Request().Context(), database.CreateOAuthAttemptParams{
		StateHash: stateHash[:], Provider: provider, Verifier: verifier, Nonce: nonce, Purpose: purpose, SessionSelector: session, ExpiresAt: models.NewUTCTime(now.Add(oauthLifetime)),
	})
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "could not start sign-in", err)
	}
	if inserted == 0 {
		return apiError(http.StatusTooManyRequests, CodeRateLimited, "too many pending sign-ins; retry later")
	}
	for name, value := range map[string]string{provider + "_oauth_state": state, provider + "_oauth_pkce": verifier} {
		c.SetCookie(&http.Cookie{Name: name, Value: value, Path: "/", MaxAge: int(oauthLifetime.Seconds()), HttpOnly: true, Secure: h.cookieSecure, SameSite: http.SameSiteLaxMode})
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	if purpose == "link" {
		return c.JSON(http.StatusOK, map[string]string{"authorization_url": authorizationURL})
	}
	return c.Redirect(http.StatusFound, authorizationURL)
}

func (h *Handler) providerCallback(c echo.Context, provider string) error {
	if !h.providerReady(provider) {
		return apiError(http.StatusNotFound, CodeNotFound, "this sign-in provider is not enabled")
	}
	stateCookie, cookieErr := c.Cookie(provider + "_oauth_state")
	verifierCookie, verifierErr := c.Cookie(provider + "_oauth_pkce")
	for _, name := range []string{provider + "_oauth_state", provider + "_oauth_pkce"} {
		c.SetCookie(&http.Cookie{Name: name, Path: "/", MaxAge: -1, HttpOnly: true, Secure: h.cookieSecure, SameSite: http.SameSiteLaxMode})
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("Referrer-Policy", "no-referrer")
	state := c.QueryParam("state")
	if cookieErr != nil || verifierErr != nil || len(state) < 43 || len(state) > 128 || subtle.ConstantTimeCompare([]byte(state), []byte(stateCookie.Value)) != 1 {
		return h.oauthFailure(c, provider, "expired")
	}
	stateHash := sha256.Sum256([]byte(state))
	ctx := c.Request().Context()
	attempt, err := database.New(h.db).ConsumeOAuthAttempt(ctx, database.ConsumeOAuthAttemptParams{StateHash: stateHash[:], Provider: provider, ExpiresAt: models.NewUTCTime(time.Now().UTC())})
	if err != nil || subtle.ConstantTimeCompare([]byte(attempt.Verifier), []byte(verifierCookie.Value)) != 1 {
		return h.oauthFailure(c, provider, "expired")
	}
	if c.QueryParam("error") != "" {
		return h.oauthFailure(c, provider, "cancelled")
	}
	code := strings.TrimSpace(c.QueryParam("code"))
	if code == "" || len(code) > 4096 {
		return h.oauthFailure(c, provider, "expired")
	}
	var profile externalProfile
	if provider == "github" {
		github, lookupErr := h.githubProfile(ctx, code, attempt.Verifier)
		err = lookupErr
		profile = externalProfile{Provider: "github", Issuer: "https://github.com", Subject: strconv.FormatInt(github.ID, 10), Login: github.Login, Name: github.Name}
	} else {
		profile, err = h.cilogonProfile(ctx, code, attempt.Verifier, attempt.Nonce)
	}
	if err != nil {
		return h.oauthFailure(c, provider, "provider_unavailable")
	}
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	queries := database.New(tx)
	// Serialize first sign-in and linking against concurrent identity changes.
	if _, err := tx.ExecContext(ctx, "UPDATE users SET name = name WHERE id = 0"); err != nil {
		return err
	}
	if attempt.Purpose == "link" {
		session, err := recentIdentitySession(ctx, queries, attempt.SessionSelector)
		if err != nil {
			return h.oauthFailure(c, provider, "expired")
		}
		if owner, lookupErr := queries.FindExternalIdentity(ctx, database.FindExternalIdentityParams{Issuer: profile.Issuer, Subject: profile.Subject}); lookupErr == nil && owner != session.UserID {
			return h.oauthFailure(c, provider, "identity_conflict")
		} else if lookupErr != nil && !errors.Is(lookupErr, sql.ErrNoRows) {
			return lookupErr
		}
		if err := queries.DeleteExpiredIdentityLinks(ctx, models.NewUTCTime(time.Now().UTC())); err != nil {
			return err
		}
		if err := queries.StorePendingIdentityLink(ctx, database.StorePendingIdentityLinkParams{UserID: session.UserID, Provider: profile.Provider, Issuer: profile.Issuer, Subject: profile.Subject, Login: profile.Login, SessionSelector: attempt.SessionSelector, ExpiresAt: models.NewUTCTime(time.Now().UTC().Add(oauthLifetime))}); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		destination, _ := url.Parse(h.providerSuccessURL(provider))
		query := destination.Query()
		query.Set("auth_action", "link_pending")
		query.Set("provider", provider)
		destination.RawQuery = query.Encode()
		return c.Redirect(http.StatusFound, destination.String())
	}
	userID, err := externalIdentityUser(ctx, queries, profile)
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "could not store the sign-in account", err)
	}
	if attempt.SessionSelector != "" {
		if err := queries.RevokeSessionBySelector(ctx, attempt.SessionSelector); err != nil {
			return err
		}
	}
	token, csrf, expires, err := issueSession(ctx, queries, userID)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	h.writeSessionCookies(c, token, csrf, expires)
	return c.Redirect(http.StatusFound, h.providerSuccessURL(provider))
}

func (h *Handler) oauthFailure(c echo.Context, provider, code string) error {
	destination, err := url.Parse(h.providerSuccessURL(provider))
	if err != nil {
		return apiError(http.StatusBadGateway, CodeInternal, "sign-in failed; try again")
	}
	query := destination.Query()
	query.Set("auth_error", code)
	destination.RawQuery = query.Encode()
	return c.Redirect(http.StatusFound, destination.String())
}

func externalIdentityUser(ctx context.Context, queries *database.Queries, profile externalProfile) (int64, error) {
	userID, err := queries.FindExternalIdentity(ctx, database.FindExternalIdentityParams{Issuer: profile.Issuer, Subject: profile.Subject})
	now := models.NewUTCTime(time.Now().UTC())
	if err == nil {
		return userID, queries.RefreshExternalIdentity(ctx, database.RefreshExternalIdentityParams{Login: profile.Login, UpdatedAt: now, Issuer: profile.Issuer, Subject: profile.Subject})
	}
	if !errors.Is(err, sql.ErrNoRows) {
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
	return user.ID, queries.CreateExternalIdentity(ctx, database.CreateExternalIdentityParams{Provider: profile.Provider, Issuer: profile.Issuer, Subject: profile.Subject, UserID: user.ID, Login: profile.Login, CreatedAt: now, UpdatedAt: now})
}

func recentIdentitySession(ctx context.Context, queries *database.Queries, selector string) (database.GetIdentitySessionRow, error) {
	session, err := queries.GetIdentitySession(ctx, selector)
	now := time.Now().UTC()
	if err != nil || session.Revoked != 0 || !now.Before(session.ExpiresAt.Time) || now.Sub(session.AuthenticatedAt.Time) > oauthLifetime {
		return database.GetIdentitySessionRow{}, unauthorized()
	}
	return session, nil
}
