// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// The account system is the credential issuer of this API. An account is
// created with PUT /user, which returns its account key and recovery code
// once; the account key is exchanged for a session at POST /auth/login. A
// user identifier is not a credential and names no authority: it appears in
// responses only to the account it belongs to and to an operator.

// GET /me
// GetMe returns the authenticated account. It requires a credential even in
// local development, because the local development bypass names no account.
func (h *Handler) GetMe(c echo.Context) error {
	established, err := requireAccount(c)
	if err != nil {
		return err
	}

	queries := database.New(h.db)
	user, err := queries.GetUserByUUID(c.Request().Context(), established.UserUUID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return apiError(http.StatusNotFound, CodeNotFound, "user does not exist")
		}
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to retrieve user", err)
	}

	return c.JSON(http.StatusOK, UserResponse{
		ID:   user.Uuid.String(),
		Name: user.Name,
		Role: user.Role,
	})
}

// GET /user-ids
// ListUserIDs enumerates the accounts of this dispatcher. Enumeration is an
// operator operation: an ordinary account has no reason to learn which other
// accounts exist, and an identifier it learned was once enough to impersonate
// one.
func (h *Handler) ListUserIDs(c echo.Context) error {
	if _, err := requireOperator(c); err != nil {
		return err
	}
	queries := database.New(h.db)
	uuids, err := queries.ListUserUUIDs(c.Request().Context())
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to retrieve user IDs", err)
	}

	ids := make([]string, len(uuids))
	for i, u := range uuids {
		ids[i] = u.String()
	}
	return c.JSON(http.StatusOK, ids)
}

// PUT /user
// CreateUser registers an account and issues its first credentials. The
// account key and the recovery code are returned exactly once; only their
// digests are stored. The role of a self-registered account is always the
// ordinary one.
func (h *Handler) CreateUser(c echo.Context) error {
	var req CreateUserRequest
	if err := c.Bind(&req); err != nil {
		return bindError(err)
	}
	if strings.TrimSpace(req.Name) == "" {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "missing user name")
	}

	ctx := c.Request().Context()
	newUUID := uuid.New()
	queries := database.New(h.db)
	user, err := queries.CreateUser(ctx, database.CreateUserParams{
		Uuid: newUUID,
		Name: req.Name,
	})
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to create user", err)
	}
	accountKey, recoveryCode, err := h.issueAccountCredentials(ctx, user.ID)
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to issue account credentials", err)
	}

	return c.JSON(http.StatusOK, AccountResponse{
		ID:           user.Uuid.String(),
		Name:         user.Name,
		Role:         user.Role,
		AccountKey:   accountKey,
		RecoveryCode: recoveryCode,
	})
}
