// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/assistantkeys"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/studio"
)

func assistantKeyFailure() error {
	return apiError(http.StatusServiceUnavailable, CodeUnavailable, "personal assistant key storage is unavailable; no operator credential was used")
}

// Resolve once per request. A configured but unreadable/rejected personal key
// must never retry against the operator's account.
func (h *Handler) assistantClient(ctx context.Context, account uuid.UUID) (*studio.Assistant, bool, error) {
	if h.assistant.keys != nil {
		key, found, err := h.assistant.keys.Load(ctx, account)
		if err != nil {
			return nil, false, assistantKeyFailure()
		}
		if found {
			client, err := h.assistant.newPersonal(key)
			if err != nil {
				return nil, false, assistantKeyFailure()
			}
			return client, true, nil
		}
	}
	return h.assistant.client, false, nil
}

func (h *Handler) assistantKeyStatus(c echo.Context) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	if err := assistantRoute(c); err != nil {
		return err
	}
	result := struct {
		Enabled    bool   `json:"enabled"`
		Configured bool   `json:"configured"`
		Model      string `json:"model,omitempty"`
	}{Enabled: h.assistant.keys != nil}
	if result.Enabled {
		result.Configured, err = h.assistant.keys.Configured(c.Request().Context(), account.UserUUID)
		if err != nil {
			return assistantKeyFailure()
		}
		result.Model = h.assistant.personalModel
	}
	return c.JSON(http.StatusOK, result)
}

func (h *Handler) assistantKeySave(c echo.Context) error   { return h.assistantKeyWrite(c, false) }
func (h *Handler) assistantKeyDelete(c echo.Context) error { return h.assistantKeyWrite(c, true) }

func (h *Handler) assistantKeyWrite(c echo.Context, remove bool) error {
	account, err := requireRecentBrowserSession(c)
	if err != nil {
		return err
	}
	if err := assistantRoute(c); err != nil {
		return err
	}
	if h.assistant.keys == nil {
		return assistantKeyFailure()
	}
	if err := h.limitAuthentication(c); err != nil {
		return err
	}
	var input struct {
		APIKey string `json:"api_key"`
	}
	if !remove {
		media, _, err := mime.ParseMediaType(c.Request().Header.Get(echo.HeaderContentType))
		if err != nil || media != echo.MIMEApplicationJSON || c.Request().Header.Get("Content-Encoding") != "" {
			return apiError(http.StatusUnsupportedMediaType, CodeUnsupportedMediaType, "key body must be uncompressed application/json")
		}
		dec := json.NewDecoder(http.MaxBytesReader(c.Response(), c.Request().Body, 16<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&input); err != nil || !assistantkeys.ValidKey(input.APIKey) {
			return apiError(http.StatusBadRequest, CodeInvalidRequest, "provide an API key of 1–8192 bytes without whitespace")
		}
		if dec.Decode(new(any)) != io.EOF {
			return apiError(http.StatusBadRequest, CodeInvalidRequest, "provide one JSON object")
		}
	}
	ctx := c.Request().Context()
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return assistantKeyFailure()
	}
	defer tx.Rollback()
	q := database.New(tx)
	if err := recheckBrowserSession(ctx, q, account); err != nil {
		return err
	}
	if remove {
		err = q.DeleteAssistantKey(ctx, account.UserUUID)
	} else {
		err = h.assistant.keys.SaveIn(ctx, q, account.UserUUID, input.APIKey)
	}
	if err != nil {
		return assistantKeyFailure()
	}
	if err := tx.Commit(); err != nil {
		return assistantKeyFailure()
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *Handler) assistantKeyTest(c echo.Context) error {
	account, err := requireRecentBrowserSession(c)
	if err != nil {
		return err
	}
	if err := assistantRoute(c); err != nil {
		return err
	}
	if h.assistant.keys == nil {
		return assistantKeyFailure()
	}
	if err := h.limitAuthentication(c); err != nil {
		return err
	}
	if !h.assistant.slots.acquire(account.UserUUID) {
		return apiError(http.StatusTooManyRequests, CodeRateLimited, "experiment assistant is busy; retry shortly")
	}
	defer h.assistant.slots.release(account.UserUUID)
	if !h.assistant.requests.Allow() {
		return apiError(http.StatusTooManyRequests, CodeRateLimited, "experiment assistant request limit reached; retry shortly")
	}
	ctx, cancel := context.WithTimeout(c.Request().Context(), 15*time.Second)
	defer cancel()
	client, personal, err := h.assistantClient(ctx, account.UserUUID)
	if err != nil {
		return err
	}
	if !personal {
		return apiError(http.StatusConflict, CodeInvalidRequest, "save your personal key before testing it")
	}
	defer client.Close()
	if err := client.CheckAccess(ctx); err != nil {
		return assistantFailure(err, ctx.Err())
	}
	return c.NoContent(http.StatusNoContent)
}
