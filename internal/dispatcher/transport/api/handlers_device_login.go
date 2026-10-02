// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"go.uber.org/zap"
)

const deviceLoginLifetime = 10 * time.Minute
const deviceLoginPrefix = "dbd"
const maxDeviceLogins = 4096

type DeviceLoginStart struct {
	DeviceCode      string   `json:"device_code"`
	UserCode        string   `json:"user_code"`
	VerificationURI string   `json:"verification_uri"`
	Audience        string   `json:"audience"`
	Scopes          []string `json:"scopes"`
	ExpiresAt       int64    `json:"expires_at"`
	Interval        int64    `json:"interval"`
}

type DeviceLoginRequest struct {
	DeviceCode string `json:"device_code"`
	Audience   string `json:"audience"`
}

type DeviceApprovalRequest struct {
	UserCode string `json:"user_code"`
	Audience string `json:"audience"`
	Confirm  bool   `json:"confirm"`
}

type DeviceLoginInfo struct {
	UserCode  string   `json:"user_code"`
	Audience  string   `json:"audience"`
	Scopes    []string `json:"scopes"`
	Label     string   `json:"label"`
	ExpiresAt int64    `json:"expires_at"`
	State     string   `json:"state"`
}

type DeviceLoginPoll struct {
	State      string            `json:"state"`
	Interval   int64             `json:"interval,omitempty"`
	Credential *IssuedCredential `json:"credential,omitempty"`
}

func (h *Handler) StartDeviceLogin(c echo.Context) error {
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
	if h.deviceVerificationURL == "" {
		return apiError(http.StatusNotFound, CodeNotFound, "browser-assisted login is not configured")
	}
	token, selector, digest, err := newCredential(deviceLoginPrefix)
	if err != nil {
		return credentialFailure(err)
	}
	raw := make([]byte, 7)
	if _, err = rand.Read(raw); err != nil {
		return credentialFailure(err)
	}
	code := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)[:10]
	sum := sha256.Sum256([]byte(code))
	now := time.Now().Unix()
	expires := now + int64(deviceLoginLifetime/time.Second)
	ctx := c.Request().Context()
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return credentialFailure(err)
	}
	defer tx.Rollback()
	q := database.New(tx)
	if err = q.DeleteExpiredDeviceLogins(ctx, now); err != nil {
		return credentialFailure(err)
	}
	count, err := q.CountDeviceLogins(ctx)
	if err != nil {
		return credentialFailure(err)
	}
	if count >= maxDeviceLogins {
		return apiError(http.StatusTooManyRequests, CodeRateLimited, "too many pending logins; retry later")
	}
	err = q.CreateDeviceLogin(ctx, database.CreateDeviceLoginParams{Selector: selector, VerifierHash: digest, UserCodeHash: sum[:], Audience: req.Audience, Scopes: scopes, Label: req.Label, ExpiresAt: expires, NextPollAt: now + 5})
	if err != nil {
		return credentialFailure(err)
	}
	if err = tx.Commit(); err != nil {
		return credentialFailure(err)
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.JSON(http.StatusCreated, DeviceLoginStart{DeviceCode: token, UserCode: code[:5] + "-" + code[5:], VerificationURI: h.deviceVerificationURL, Audience: req.Audience, Scopes: strings.Fields(scopes), ExpiresAt: expires, Interval: 5})
}

func (h *Handler) deviceRequest(c echo.Context) (DeviceLoginRequest, string, string, error) {
	var req DeviceLoginRequest
	if err := c.Bind(&req); err != nil {
		return req, "", "", bindError(err)
	}
	selector, verifier, ok := parseCredential(deviceLoginPrefix, req.DeviceCode)
	if !ok || h.authPublicURL == "" || req.Audience != h.authPublicURL {
		return req, "", "", unauthorized()
	}
	return req, selector, verifier, nil
}

func (h *Handler) PollDeviceLogin(c echo.Context) error {
	if err := h.limitAuthentication(c); err != nil {
		return err
	}
	req, selector, verifier, err := h.deviceRequest(c)
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
	// Acquire SQLite's write lock before reading the state. Concurrent polling,
	// cancellation and approval then observe a single ordered transition.
	if err = q.LockDeviceLogin(ctx, selector); err != nil {
		return credentialFailure(err)
	}
	row, err := q.GetDeviceLogin(ctx, selector)
	if errors.Is(err, sql.ErrNoRows) {
		return unauthorized()
	}
	if err != nil {
		return credentialFailure(err)
	}
	if !verifierMatches(row.VerifierHash, verifier) || row.Audience != req.Audience {
		return unauthorized()
	}
	now := time.Now().Unix()
	response := DeviceLoginPoll{}
	switch {
	case now >= row.ExpiresAt:
		response.State = "expired_token"
	case row.State == "denied" || row.State == "cancelled":
		response.State = "access_denied"
	case row.State == "consumed":
		response.State = "consumed"
	case now < row.NextPollAt:
		interval := min(row.PollInterval+5, 60)
		if _, err = q.UpdateDeviceLoginPoll(ctx, database.UpdateDeviceLoginPollParams{NextPollAt: now + interval, PollInterval: interval, Selector: selector}); err != nil {
			return credentialFailure(err)
		}
		response = DeviceLoginPoll{State: "slow_down", Interval: interval}
	case row.State == "pending":
		if _, err = q.UpdateDeviceLoginPoll(ctx, database.UpdateDeviceLoginPollParams{NextPollAt: now + row.PollInterval, PollInterval: row.PollInterval, Selector: selector}); err != nil {
			return credentialFailure(err)
		}
		response = DeviceLoginPoll{State: "authorization_pending", Interval: row.PollInterval}
	case row.State == "approved" && row.UserID.Valid:
		approval, err := q.GetSessionBySelector(ctx, row.ApproverSession)
		if errors.Is(err, sql.ErrNoRows) || err == nil && (approval.Revoked != 0 || approval.Kind != "browser" || !time.Now().Before(approval.ExpiresAt.Time)) {
			if err = q.CancelDeviceLogin(ctx, selector); err != nil {
				return credentialFailure(err)
			}
			response.State = "access_denied"
			break
		}
		if err != nil {
			return credentialFailure(err)
		}
		changed, err := q.ConsumeDeviceLogin(ctx, database.ConsumeDeviceLoginParams{Selector: selector, Now: now})
		if err != nil {
			return credentialFailure(err)
		}
		if changed != 1 {
			return unauthorized()
		}
		credential, err := issueAPICredential(ctx, q, row.UserID.Int64, row.Audience, row.Scopes, row.Label)
		if err != nil {
			return err
		}
		response = DeviceLoginPoll{State: "authorized", Credential: &credential}
	default:
		return unauthorized()
	}
	if err = tx.Commit(); err != nil {
		return credentialFailure(err)
	}
	if response.Credential != nil {
		h.logger.Info("Device login completed", zap.String("account", response.Credential.ID), zap.String("credential", response.Credential.CredentialID))
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.JSON(http.StatusOK, response)
}

func (h *Handler) CancelDeviceLogin(c echo.Context) error {
	if err := h.limitAuthentication(c); err != nil {
		return err
	}
	req, selector, verifier, err := h.deviceRequest(c)
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
	if err = q.LockDeviceLogin(ctx, selector); err != nil {
		return credentialFailure(err)
	}
	row, err := q.GetDeviceLogin(ctx, selector)
	if errors.Is(err, sql.ErrNoRows) {
		return unauthorized()
	}
	if err != nil {
		return credentialFailure(err)
	}
	if !verifierMatches(row.VerifierHash, verifier) || row.Audience != req.Audience {
		return unauthorized()
	}
	if err = q.CancelDeviceLogin(ctx, selector); err != nil {
		return credentialFailure(err)
	}
	if err = tx.Commit(); err != nil {
		return credentialFailure(err)
	}
	return c.NoContent(http.StatusNoContent)
}

func normalizeUserCode(code string) (string, []byte, error) {
	code = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	if len(code) != 10 {
		return "", nil, apiError(http.StatusNotFound, CodeNotFound, "login request not found or expired")
	}
	for _, r := range code {
		if !(r >= 'A' && r <= 'Z' || r >= '2' && r <= '7') {
			return "", nil, apiError(http.StatusNotFound, CodeNotFound, "login request not found or expired")
		}
	}
	sum := sha256.Sum256([]byte(code))
	return code[:5] + "-" + code[5:], sum[:], nil
}

func (h *Handler) approvalRequest(c echo.Context) (*caller, DeviceApprovalRequest, string, []byte, error) {
	account, err := requireRecentBrowserSession(c)
	if err != nil {
		return nil, DeviceApprovalRequest{}, "", nil, err
	}
	if err = h.limitAuthentication(c); err != nil {
		return nil, DeviceApprovalRequest{}, "", nil, err
	}
	var req DeviceApprovalRequest
	if err = c.Bind(&req); err != nil {
		return nil, req, "", nil, bindError(err)
	}
	if req.Audience != h.authPublicURL || h.authPublicURL == "" {
		return nil, req, "", nil, apiError(http.StatusBadRequest, CodeInvalidRequest, "login audience must be this dispatcher")
	}
	code, hash, err := normalizeUserCode(req.UserCode)
	return account, req, code, hash, err
}

func deviceApprovalRow(q *database.Queries, c echo.Context, hash []byte, audience string) (database.DeviceLogin, error) {
	row, err := q.GetDeviceLoginByUserCode(c.Request().Context(), hash)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (row.State != "pending" || row.ExpiresAt <= time.Now().Unix() || row.Audience != audience) {
		return row, apiError(http.StatusNotFound, CodeNotFound, "login request not found or expired")
	}
	if err != nil {
		return row, credentialFailure(err)
	}
	return row, nil
}

func (h *Handler) InspectDeviceLogin(c echo.Context) error {
	_, req, code, hash, err := h.approvalRequest(c)
	if err != nil {
		return err
	}
	row, err := deviceApprovalRow(database.New(h.db), c, hash, req.Audience)
	if err != nil {
		return err
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.JSON(http.StatusOK, DeviceLoginInfo{UserCode: code, Audience: row.Audience, Scopes: strings.Fields(row.Scopes), Label: row.Label, ExpiresAt: row.ExpiresAt, State: row.State})
}

func (h *Handler) ApproveDeviceLogin(c echo.Context) error { return h.decideDeviceLogin(c, true) }
func (h *Handler) DenyDeviceLogin(c echo.Context) error    { return h.decideDeviceLogin(c, false) }
func (h *Handler) decideDeviceLogin(c echo.Context, approve bool) error {
	account, req, _, hash, err := h.approvalRequest(c)
	if err != nil {
		return err
	}
	if approve && !req.Confirm {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "review the dispatcher, device, code and scopes before confirming")
	}
	ctx := c.Request().Context()
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil { return credentialFailure(err) }
	defer tx.Rollback()
	q := database.New(tx)
	if err := recheckBrowserSession(ctx, q, account); err != nil { return err }
	row, err := deviceApprovalRow(q, c, hash, req.Audience)
	if err != nil {
		return err
	}
	var changed int64
	if approve {
		user, lookupErr := q.GetUserByUUID(ctx, account.UserUUID)
		if lookupErr != nil {
			return credentialFailure(lookupErr)
		}
		changed, err = q.ApproveDeviceLogin(ctx, database.ApproveDeviceLoginParams{Selector: row.Selector, UserID: sql.NullInt64{Int64: user.ID, Valid: true}, ApproverSession: account.Session, Now: time.Now().Unix()})
	} else {
		changed, err = q.DenyDeviceLogin(ctx, database.DenyDeviceLoginParams{Selector: row.Selector, Now: time.Now().Unix()})
	}
	if err != nil {
		return credentialFailure(err)
	}
	if changed != 1 {
		return apiError(http.StatusNotFound, CodeNotFound, "login request not found or expired")
	}
	if err := tx.Commit(); err != nil { return credentialFailure(err) }
	h.logger.Info("Device login decision", zap.String("account", account.UserUUID.String()), zap.Bool("approved", approve))
	return c.NoContent(http.StatusNoContent)
}
