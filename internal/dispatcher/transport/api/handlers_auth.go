package api

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"

	"github.com/labstack/echo/v4"
)

// LoginRequest exchanges an account key for a session. An empty account key is
// the local development bootstrap and is refused by every other deployment.
type LoginRequest struct {
	AccountKey string `json:"account_key"`
}

// RecoverRequest exchanges a recovery code for fresh account credentials.
type RecoverRequest struct {
	RecoveryCode string `json:"recovery_code"`
}

// SessionResponse is an issued session. token is the bearer credential a
// native client repeats on every request; csrf_token is the value a browser
// client, which received the session in a cookie, repeats in the
// X-Debuglet-CSRF header of every state-changing request.
type SessionResponse struct {
	Token     string `json:"token"`
	CSRFToken string `json:"csrf_token"`
	ExpiresAt int64  `json:"expires_at"`
	ID        string `json:"id"`
	Name      string `json:"name"`
	Role      string `json:"role"`
}

// AccountResponse is an account together with the credentials just issued for
// it. The two credentials are returned exactly once, by the operation that
// minted them; the dispatcher keeps only their digests and cannot show them
// again.
type AccountResponse struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Role         string `json:"role"`
	AccountKey   string `json:"account_key"`
	RecoveryCode string `json:"recovery_code"`
}

// POST /auth/login
//
// PostLogin verifies an account key and issues a session for the account it
// names. It is the only route that turns a long-lived credential into one, and
// it never accepts a user identifier, a run identifier or a payment auth key.
func (h *Handler) PostLogin(c echo.Context) error {
	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		return bindError(err)
	}
	ctx := c.Request().Context()
	key := strings.TrimSpace(req.AccountKey)
	if key == "" && !h.localDevelopment {
		return unauthorized()
	}
	// Keep key verification and session creation in one transaction so recovery
	// either revokes this session or invalidates the key before it can be used.
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to issue a session", err)
	}
	defer tx.Rollback()
	queries := database.New(tx)

	var userID int64
	var response SessionResponse
	if key == "" {
		// The documented local development bootstrap: a dispatcher that was
		// explicitly configured for local development issues a credential for
		// its own local account without a browser and without a wallet.
		user, err := localDevelopmentUser(ctx, queries)
		if err != nil {
			return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to prepare the local development account", err)
		}
		userID = user.ID
		response.ID, response.Name, response.Role = user.Uuid.String(), user.Name, user.Role
	} else {
		row, ok := lookupCredential(ctx, queries, accountPrefix, credentialAccount, key)
		if !ok {
			return unauthorized()
		}
		userID = row.UserID
		response.ID, response.Name, response.Role = row.Uuid.String(), row.Name, row.Role
	}

	token, csrf, expires, err := issueSession(ctx, queries, userID)
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to issue a session", err)
	}
	if err := tx.Commit(); err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to issue a session", err)
	}
	response.Token, response.CSRFToken, response.ExpiresAt = token, csrf, expires.Unix()
	h.writeSessionCookies(c, token, csrf, expires)
	return c.JSON(http.StatusOK, response)
}

// POST /auth/logout
//
// PostLogout revokes the session the request authenticated with and clears the
// browser cookies. The revoked token is refused from then on, before its
// expiry.
func (h *Handler) PostLogout(c echo.Context) error {
	established, err := requireCaller(c)
	if err != nil {
		return err
	}
	if established.Authenticated {
		if err := database.New(h.db).RevokeSessionBySelector(c.Request().Context(), established.Session); err != nil {
			return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to revoke the session", err)
		}
	}
	h.clearSessionCookies(c)
	return c.NoContent(http.StatusNoContent)
}

// POST /auth/recover
//
// PostRecover consumes a recovery code and returns a new account key and a new
// recovery code for the one account that code belongs to. Every session of
// that account is revoked first, so a recovered account is not still reachable
// with a credential the previous holder kept. A recovery code names its own
// account and nothing else: it can never be redirected at another one.
func (h *Handler) PostRecover(c echo.Context) error {
	var req RecoverRequest
	if err := c.Bind(&req); err != nil {
		return bindError(err)
	}
	ctx := c.Request().Context()
	// Verification consumes the current code in the same transaction that
	// replaces both credentials and revokes the account's sessions.
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to recover the account", err)
	}
	defer tx.Rollback()
	queries := database.New(tx)
	row, ok := lookupCredential(ctx, queries, recoveryPrefix, credentialRecovery, strings.TrimSpace(req.RecoveryCode))
	if !ok {
		return unauthorized()
	}
	if err := queries.RevokeUserSessions(ctx, row.Uuid); err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to revoke the account's sessions", err)
	}
	accountKey, recoveryCode, err := storeAccountCredentials(ctx, queries, row.UserID)
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to issue account credentials", err)
	}
	if err := tx.Commit(); err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to recover the account", err)
	}
	return c.JSON(http.StatusOK, AccountResponse{
		ID:           row.Uuid.String(),
		Name:         row.Name,
		Role:         row.Role,
		AccountKey:   accountKey,
		RecoveryCode: recoveryCode,
	})
}

// localDevelopmentUser returns the fixed local development account, creating
// it on first use. It exists only where local development was explicitly
// enabled; no other deployment ever reaches this.
func localDevelopmentUser(ctx context.Context, queries *database.Queries) (database.User, error) {
	user, err := queries.GetUserByUUID(ctx, localDevelopmentAccount)
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return database.User{}, err
	}
	return queries.CreateUserWithRole(ctx, database.CreateUserWithRoleParams{
		Uuid: localDevelopmentAccount,
		Name: localDevelopmentAccountName,
		Role: RoleOperator,
	})
}
