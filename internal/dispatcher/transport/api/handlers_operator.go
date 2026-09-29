// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/enrollment"
)

type OwnedExecutorResponse struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Ready    bool   `json:"ready"`
	LastSeen int64  `json:"last_seen,omitempty"`
	Version  string `json:"version,omitempty"`
}

type OwnedExecutorsResponse struct {
	Enabled       bool                    `json:"enabled"`
	Executors     []OwnedExecutorResponse `json:"executors"`
	DispatcherURL string                  `json:"dispatcher_url,omitempty"`
}

type ExecutorSetupResponse struct {
	Executor      OwnedExecutorResponse `json:"executor"`
	Token         string                `json:"token"`
	ExpiresAt     int64                 `json:"expires_at"`
	DispatcherURL string                `json:"dispatcher_url"`
}

func (h *Handler) onboardingEnabled() bool { return h.onboarding.Enabled && h.issuer != nil }

func (h *Handler) ownedExecutor(id, name string, enrolled bool) OwnedExecutorResponse {
	result := OwnedExecutorResponse{ID: id, Name: name, Status: "pending"}
	if enrolled {
		result.Status = "offline"
		if node, ok := h.dispatcher.GetExecutor(id); ok {
			result.Ready, result.Version = node.Ready, node.Version
			if !node.LastSeen.IsZero() {
				result.LastSeen = node.LastSeen.Unix()
			}
			if node.Ready {
				result.Status = "online"
			}
		}
	}
	return result
}

func (h *Handler) GetOwnedExecutors(c echo.Context) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	rows, err := database.New(h.db).ListOwnedExecutors(c.Request().Context(), account.UserUUID)
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to read your executors", err)
	}
	response := OwnedExecutorsResponse{Enabled: h.onboardingEnabled(), Executors: []OwnedExecutorResponse{}}
	if response.Enabled {
		response.DispatcherURL = h.onboarding.DispatcherURL
	}
	for _, row := range rows {
		response.Executors = append(response.Executors, h.ownedExecutor(row.ExecutorID, row.Name, row.Enrolled))
	}
	return c.JSON(http.StatusOK, response)
}

func onboardingUnavailable() error {
	return apiError(http.StatusServiceUnavailable, CodeUnavailable, "executor registration is not enabled on this dispatcher")
}

func (h *Handler) PostOwnedExecutor(c echo.Context) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	if !h.onboardingEnabled() {
		return onboardingUnavailable()
	}
	var request struct {
		Name string `json:"name"`
	}
	if err := c.Bind(&request); err != nil {
		return bindError(err)
	}
	request.Name = strings.TrimSpace(request.Name)
	if !utf8.ValidString(request.Name) || utf8.RuneCountInString(request.Name) < 1 || utf8.RuneCountInString(request.Name) > 80 || strings.ContainsFunc(request.Name, unicode.IsControl) {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "name must contain 1 to 80 characters without control characters")
	}
	id := uuid.NewString()
	token, expires, err := enrollment.NewStore(h.db).CreateOwned(c.Request().Context(), account.UserUUID, id, request.Name)
	if errors.Is(err, enrollment.ErrNodeLimit) {
		return apiError(http.StatusConflict, CodeCapacityExhausted, "an account may register at most ten executors")
	}
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to register executor", err)
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.JSON(http.StatusCreated, ExecutorSetupResponse{
		Executor: h.ownedExecutor(id, request.Name, false), Token: token,
		ExpiresAt: expires.Unix(), DispatcherURL: h.onboarding.DispatcherURL,
	})
}

func (h *Handler) PostOwnedExecutorToken(c echo.Context) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	if !h.onboardingEnabled() {
		return onboardingUnavailable()
	}
	ctx := c.Request().Context()
	row, err := database.New(h.db).GetOwnedExecutor(ctx, database.GetOwnedExecutorParams{Uuid: account.UserUUID, ExecutorID: c.Param("id")})
	if errors.Is(err, sql.ErrNoRows) {
		return apiError(http.StatusNotFound, CodeNotFound, "executor not found")
	}
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to read executor", err)
	}
	token, expires, err := enrollment.NewStore(h.db).RenewOwned(ctx, account.UserUUID, row.ExecutorID)
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to create setup token", err)
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.JSON(http.StatusOK, ExecutorSetupResponse{
		Executor: h.ownedExecutor(row.ExecutorID, row.Name, row.Enrolled), Token: token,
		ExpiresAt: expires.Unix(), DispatcherURL: h.onboarding.DispatcherURL,
	})
}

// PostExecutorEnrollment exchanges a one-use machine token for a certificate.
// The token authenticates this operation; an account session grants no right
// to issue a certificate. The private key remains on the joining machine.
func (h *Handler) PostExecutorEnrollment(c echo.Context) error {
	if !h.onboardingEnabled() {
		return onboardingUnavailable()
	}
	var request struct {
		ExecutorID string `json:"executor_id"`
		Token      string `json:"token"`
		CSR        string `json:"csr"`
	}
	if err := c.Bind(&request); err != nil {
		return bindError(err)
	}
	if _, err := uuid.Parse(request.ExecutorID); err != nil || request.Token == "" || len(request.Token) > 128 {
		return unauthorized()
	}
	certificate, fingerprint, err := h.issuer.Sign(request.ExecutorID, request.CSR)
	if err != nil {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "could not issue executor certificate from this certificate request")
	}
	if err := enrollment.NewStore(h.db).Admit(c.Request().Context(), request.ExecutorID, fingerprint, request.Token); err != nil {
		if errors.Is(err, enrollment.ErrUnusableToken) || errors.Is(err, enrollment.ErrNotEnrolled) || errors.Is(err, enrollment.ErrWrongNode) {
			return unauthorized()
		}
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to enroll executor", err)
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.JSON(http.StatusOK, struct {
		ExecutorID     string `json:"executor_id"`
		CertificatePEM string `json:"certificate_pem"`
		CAPEM          string `json:"ca_pem"`
		GRPCAddress    string `json:"grpc_address"`
		YamuxAddress   string `json:"yamux_address"`
	}{request.ExecutorID, certificate, h.issuer.CAPEM(), h.onboarding.GRPCAddress, h.onboarding.YamuxAddress})
}
