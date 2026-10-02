// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"go.uber.org/zap"
)

func (h *Handler) GetIdentities(c echo.Context) error {
	caller, err := requireAccount(c)
	if err != nil {
		return err
	}
	if caller.API || !caller.Cookie {
		return apiError(http.StatusForbidden, CodeForbidden, "manage sign-in methods in the browser")
	}
	queries := database.New(h.db)
	rows, err := queries.ListExternalIdentities(c.Request().Context(), caller.UserUUID)
	if err != nil {
		return err
	}
	type identity struct {
		Provider string `json:"provider"`
		Issuer   string `json:"issuer"`
		Login    string `json:"login"`
		LinkedAt int64  `json:"linked_at"`
		Enabled  bool   `json:"enabled"`
	}
	identities := []identity{}
	for _, row := range rows {
		identities = append(identities, identity{row.Provider, row.Issuer, row.Login, row.CreatedAt.Unix(), h.providerReady(row.Provider) && h.providerIssuer(row.Provider) == row.Issuer})
	}
	user, err := queries.GetUserByUUID(c.Request().Context(), caller.UserUUID)
	if err != nil {
		return err
	}
	pendingRows, err := queries.ListPendingIdentityLinks(c.Request().Context(), database.ListPendingIdentityLinksParams{UserID: user.ID, SessionSelector: caller.Session, ExpiresAt: models.NewUTCTime(time.Now().UTC())})
	if err != nil {
		return err
	}
	type pendingIdentity struct {
		Provider  string `json:"provider"`
		Login     string `json:"login"`
		ExpiresAt int64  `json:"expires_at"`
	}
	pending := []pendingIdentity{}
	for _, row := range pendingRows {
		pending = append(pending, pendingIdentity{row.Provider, row.Login, row.ExpiresAt.Unix()})
	}
	return c.JSON(http.StatusOK, struct {
		Identities               []identity        `json:"identities"`
		Pending                  []pendingIdentity `json:"pending"`
		ReauthenticationRequired bool              `json:"reauthentication_required"`
	}{identities, pending, time.Since(caller.CreatedAt) > oauthLifetime})
}

func (h *Handler) PostIdentityLink(c echo.Context) error {
	caller, err := requireRecentBrowserSession(c)
	if err != nil {
		return err
	}
	provider := c.Param("provider")
	if !h.providerReady(provider) {
		return apiError(http.StatusNotFound, CodeNotFound, "this sign-in provider is not enabled")
	}
	return h.startProviderLogin(c, provider, "link", caller.Session)
}

func (h *Handler) ConfirmIdentityLink(c echo.Context) error { return h.changeIdentity(c, true) }
func (h *Handler) DeleteIdentity(c echo.Context) error      { return h.changeIdentity(c, false) }

func (h *Handler) changeIdentity(c echo.Context, linking bool) error {
	caller, err := requireRecentBrowserSession(c)
	if err != nil {
		return err
	}
	var request struct {
		Confirm bool `json:"confirm"`
	}
	if err := c.Bind(&request); err != nil {
		return bindError(err)
	}
	if !request.Confirm {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "confirm this sign-in method change explicitly")
	}
	provider := c.Param("provider")
	if provider != "github" && provider != "cilogon" {
		return apiError(http.StatusNotFound, CodeNotFound, "unknown sign-in provider")
	}
	ctx := c.Request().Context()
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	queries := database.New(tx)
	// Acquire the SQLite write lock before reading the remaining methods, so
	// two concurrent removals cannot each observe the other's method.
	if _, err := tx.ExecContext(ctx, "UPDATE users SET name = name WHERE uuid = ?", caller.UserUUID); err != nil {
		return err
	}
	session, err := recentIdentitySession(ctx, queries, caller.Session)
	if err != nil {
		return err
	}
	if session.Uuid != caller.UserUUID {
		return unauthorized()
	}
	if linking {
		if !h.providerReady(provider) {
			return apiError(http.StatusConflict, CodeIdentityConflict, "the sign-in provider is disabled")
		}
		pending, err := queries.ConsumePendingIdentityLink(ctx, database.ConsumePendingIdentityLinkParams{UserID: session.UserID, Provider: provider, SessionSelector: caller.Session, ExpiresAt: models.NewUTCTime(time.Now().UTC())})
		if errors.Is(err, sql.ErrNoRows) {
			return apiError(http.StatusConflict, CodeIdentityConflict, "the link confirmation expired; start again")
		}
		if err != nil {
			return err
		}
		if pending.Issuer != h.providerIssuer(provider) {
			return apiError(http.StatusConflict, CodeIdentityConflict, "the sign-in provider changed; start again")
		}
		existing, err := queries.FindExternalIdentity(ctx, database.FindExternalIdentityParams{Issuer: pending.Issuer, Subject: pending.Subject})
		if err == nil {
			if existing != session.UserID {
				return apiError(http.StatusConflict, CodeIdentityConflict, "that identity belongs to a different account")
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		} else {
			linked, err := queries.ListExternalIdentities(ctx, caller.UserUUID)
			if err != nil {
				return err
			}
			for _, identity := range linked {
				if identity.Provider == provider {
					return apiError(http.StatusConflict, CodeIdentityConflict, "remove the existing method for this provider before linking another")
				}
			}
			now := models.NewUTCTime(time.Now().UTC())
			if err := queries.CreateExternalIdentity(ctx, database.CreateExternalIdentityParams{Provider: provider, Issuer: pending.Issuer, Subject: pending.Subject, UserID: session.UserID, Login: pending.Login, CreatedAt: now, UpdatedAt: now}); err != nil {
				return err
			}
		}
	} else {
		linked, err := queries.ListExternalIdentities(ctx, caller.UserUUID)
		if err != nil {
			return err
		}
		found, usable := false, 0
		for _, identity := range linked {
			if identity.Provider == provider {
				found = true
				continue
			}
			if h.providerReady(identity.Provider) && h.providerIssuer(identity.Provider) == identity.Issuer {
				usable++
			}
		}
		if !found {
			return apiError(http.StatusNotFound, CodeNotFound, "this sign-in method is not linked")
		}
		recovery, err := queries.CountRecoveryCredentials(ctx, session.UserID)
		if err != nil {
			return err
		}
		if usable == 0 && recovery == 0 {
			return apiError(http.StatusConflict, CodeIdentityConflict, "link another enabled sign-in method before removing the last one")
		}
		if _, err := queries.DeleteExternalIdentity(ctx, database.DeleteExternalIdentityParams{Provider: provider, UserID: session.UserID}); err != nil {
			return err
		}
	}
	if err := queries.RevokeUserSessions(ctx, caller.UserUUID); err != nil {
		return err
	}
	token, csrf, expires, err := issueSession(ctx, queries, session.UserID)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	action := "identity_unlinked"
	if linking {
		action = "identity_linked"
	}
	h.logger.Info("account sign-in method changed", zap.String("event", action), zap.String("account_id", caller.UserUUID.String()), zap.String("provider", provider))
	h.writeSessionCookies(c, token, csrf, expires)
	return c.NoContent(http.StatusNoContent)
}
