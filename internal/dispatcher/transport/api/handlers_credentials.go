// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"go.uber.org/zap"
)

const maxAccountCredentials = 100

// CredentialRequest grants only the selected existing account operations.
type CredentialRequest struct {
	Audience string   `json:"audience"`
	Scopes   []string `json:"scopes"`
	Label    string   `json:"label"`
}

type CredentialInfo struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind"`
	Audience  string   `json:"audience"`
	Scopes    []string `json:"scopes"`
	Label     string   `json:"label"`
	CreatedAt int64    `json:"created_at"`
	ExpiresAt int64    `json:"expires_at"`
	Current   bool     `json:"current"`
}

// IssuedCredential contains the secret once, at creation. Subsequent listings
// expose metadata only.
type IssuedCredential struct {
	Token        string   `json:"token"`
	CredentialID string   `json:"credential_id"`
	Audience     string   `json:"audience"`
	Scopes       []string `json:"scopes"`
	ExpiresAt    int64    `json:"expires_at"`
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Role         string   `json:"role"`
}

func (h *Handler) registerCredentialRoutes(e *echo.Echo) {
	e.GET("/auth/credential", h.GetCredentialStatus)
	e.GET("/me/credentials", h.ListCredentials)
	e.POST("/me/credentials", h.CreateCredential)
	e.DELETE("/me/credentials/:id", h.RevokeCredential)
	e.DELETE("/me/credentials", h.RevokeAllCredentials)
	e.POST("/auth/device/start", h.StartDeviceLogin)
	e.POST("/auth/device/poll", h.PollDeviceLogin)
	e.POST("/auth/device/cancel", h.CancelDeviceLogin)
	e.POST("/auth/device/inspect", h.InspectDeviceLogin)
	e.POST("/auth/device/approve", h.ApproveDeviceLogin)
	e.POST("/auth/device/deny", h.DenyDeviceLogin)
}

func (h *Handler) credentialRequest(req CredentialRequest) (string, error) {
	if h.authPublicURL == "" {
		return "", apiError(http.StatusNotFound, CodeNotFound, "browser-assisted credentials are not configured")
	}
	if req.Audience != h.authPublicURL {
		return "", apiError(http.StatusBadRequest, CodeInvalidRequest, "credential audience must be this dispatcher")
	}
	if strings.TrimSpace(req.Label) == "" || len(req.Label) > 80 || strings.ContainsFunc(req.Label, unicode.IsControl) {
		return "", apiError(http.StatusBadRequest, CodeInvalidRequest, "credential label must contain 1 to 80 printable characters")
	}
	return normalizeCredentialScopes(req.Scopes)
}

func credentialFailure(err error) error {
	return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to update credentials", err)
}

func (h *Handler) CreateCredential(c echo.Context) error {
	account, err := requireRecentBrowserSession(c)
	if err != nil {
		return err
	}
	if err := h.limitAuthentication(c); err != nil {
		return err
	}
	var req CredentialRequest
	if err := c.Bind(&req); err != nil {
		return bindError(err)
	}
	scopes, err := h.credentialRequest(req)
	if err != nil {
		return err
	}
	ctx := c.Request().Context()
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return credentialFailure(err)
	}
	defer tx.Rollback()
	q := database.New(tx)
	user, err := q.GetUserByUUID(ctx, account.UserUUID)
	if err != nil {
		return credentialFailure(err)
	}
	response, err := issueAPICredential(ctx, q, user.ID, req.Audience, scopes, req.Label)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return credentialFailure(err)
	}
	h.logger.Info("API credential issued", zap.String("account", account.UserUUID.String()), zap.String("credential", response.CredentialID))
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.JSON(http.StatusCreated, response)
}

func issueAPICredential(ctx context.Context, q *database.Queries, userID int64, audience, scopes, label string) (IssuedCredential, error) {
	now := time.Now().UTC()
	count, err := q.CountAccountCredentials(ctx, database.CountAccountCredentialsParams{UserID: userID, Now: models.NewUTCTime(now)})
	if err != nil {
		return IssuedCredential{}, credentialFailure(err)
	}
	if count >= maxAccountCredentials {
		return IssuedCredential{}, apiError(http.StatusTooManyRequests, CodeRateLimited, "revoke an existing credential before creating another")
	}
	user, err := q.GetCredentialUser(ctx, userID)
	if err != nil {
		return IssuedCredential{}, credentialFailure(err)
	}
	token, selector, digest, err := newCredential(apiCredentialPrefix)
	if err != nil {
		return IssuedCredential{}, credentialFailure(err)
	}
	expires := now.Add(SessionLifetime)
	err = q.CreateAPICredential(ctx, database.CreateAPICredentialParams{Selector: selector, VerifierHash: digest, UserID: userID, CreatedAt: models.NewUTCTime(now), ExpiresAt: models.NewUTCTime(expires), Audience: audience, Scopes: scopes, Label: label})
	if err != nil {
		return IssuedCredential{}, credentialFailure(err)
	}
	return IssuedCredential{Token: token, CredentialID: selector, Audience: audience, Scopes: strings.Fields(scopes), ExpiresAt: expires.Unix(), ID: user.Uuid.String(), Name: user.Name, Role: user.Role}, nil
}

func (h *Handler) ListCredentials(c echo.Context) error {
	account, err := requireRecentBrowserSession(c)
	if err != nil {
		return err
	}
	rows, err := database.New(h.db).ListAccountCredentials(c.Request().Context(), database.ListAccountCredentialsParams{Uuid: account.UserUUID, Now: models.NewUTCTime(time.Now().UTC())})
	if err != nil {
		return credentialFailure(err)
	}
	result := make([]CredentialInfo, 0, len(rows))
	for _, row := range rows {
		result = append(result, CredentialInfo{ID: row.Selector, Kind: row.Kind, Audience: row.Audience, Scopes: strings.Fields(row.Scopes), Label: row.Label, CreatedAt: row.CreatedAt.Unix(), ExpiresAt: row.ExpiresAt.Unix(), Current: row.Selector == account.Session})
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.JSON(http.StatusOK, result)
}

func (h *Handler) RevokeCredential(c echo.Context) error {
	account, err := requireRecentBrowserSession(c)
	if err != nil {
		return err
	}
	if len(c.Param("id")) > maxCredentialLength {
		return apiError(http.StatusNotFound, CodeNotFound, "credential not found")
	}
	changed, err := database.New(h.db).RevokeAccountCredential(c.Request().Context(), database.RevokeAccountCredentialParams{Selector: c.Param("id"), Uuid: account.UserUUID})
	if err != nil {
		return credentialFailure(err)
	}
	if changed == 0 {
		return apiError(http.StatusNotFound, CodeNotFound, "credential not found")
	}
	h.logger.Info("Credential revoked", zap.String("account", account.UserUUID.String()), zap.String("credential", c.Param("id")))
	if c.Param("id") == account.Session {
		h.clearSessionCookies(c)
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *Handler) RevokeAllCredentials(c echo.Context) error {
	account, err := requireRecentBrowserSession(c)
	if err != nil {
		return err
	}
	if err := database.New(h.db).RevokeUserSessions(c.Request().Context(), account.UserUUID); err != nil {
		return credentialFailure(err)
	}
	h.logger.Info("All credentials revoked", zap.String("account", account.UserUUID.String()))
	h.clearSessionCookies(c)
	return c.NoContent(http.StatusNoContent)
}

func (h *Handler) GetCredentialStatus(c echo.Context) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	row, err := database.New(h.db).GetSessionBySelector(c.Request().Context(), account.Session)
	if errors.Is(err, sql.ErrNoRows) {
		return unauthorized()
	}
	if err != nil {
		return credentialFailure(err)
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.JSON(http.StatusOK, CredentialInfo{ID: account.Session, Kind: row.Kind, Audience: row.Audience, Scopes: strings.Fields(row.Scopes), CreatedAt: row.CreatedAt.Unix(), ExpiresAt: row.ExpiresAt.Unix(), Current: true})
}
