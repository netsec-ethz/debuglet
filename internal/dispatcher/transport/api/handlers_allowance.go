// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/pkg/wire"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

const (
	// CodeAllowanceExceeded is a TEST intent whose price the account's
	// remaining usage allowance does not cover.
	CodeAllowanceExceeded = "allowance_exceeded"
	// CodeConflict is a request whose idempotency key already names a
	// different request.
	CodeConflict = "conflict"
	// CodeAllowanceOutOfRange is an account whose allowance history cannot be
	// represented: a total of its grants or orders, or what remains, overflows
	// a signed 64-bit integer.
	CodeAllowanceOutOfRange = "allowance_out_of_range"
)

// Bounds of the operator's grant request.
const (
	maxGrantReason         = 200
	maxGrantIdempotencyKey = 128
)

func allowancesDisabled() error {
	return apiError(http.StatusNotFound, CodeNotFound, "allowances are not enabled")
}

// allowanceExceeded refuses an intent the caller's allowance does not cover,
// naming what remains and what the intent needs in TEST units.
func allowanceExceeded(err *payments.AllowanceExceededError) error {
	return apiError(http.StatusTooManyRequests, CodeAllowanceExceeded, fmt.Sprintf(
		"the usage allowance has %d TEST units remaining and this intent requires %d", err.Remaining, err.Required))
}

// allowanceOutOfRange answers an account whose allowance cannot be stated
// without wrapping, instead of any balance.
func allowanceOutOfRange(err error) error {
	return apiErrorFrom(http.StatusConflict, CodeAllowanceOutOfRange,
		"the account's allowance history cannot be represented; the operator must reconcile it", err)
}

func allowanceResponse(allowance payments.Allowance) wire.Allowance {
	return wire.Allowance{
		Currency:    payments.AllowanceCurrency,
		Granted:     strconv.FormatInt(allowance.Granted, 10),
		Reserved:    strconv.FormatInt(allowance.Reserved, 10),
		Consumed:    strconv.FormatInt(allowance.Consumed, 10),
		Remaining:   strconv.FormatInt(allowance.Remaining(), 10),
		PricingRule: PricingRule,
	}
}

// GET /me/allowance
//
// GetMyAllowance reports the caller's usage allowance. The route exists only
// while allowances are enabled.
func (h *Handler) GetMyAllowance(c echo.Context) error {
	caller, err := requireAccount(c)
	if err != nil {
		return err
	}
	if !h.dispatcher.Payment.AllowancesEnabled() {
		return allowancesDisabled()
	}
	allowance, policy, err := h.dispatcher.Payment.AllowanceWithPolicy(c.Request().Context(), caller.UserUUID)
	if errors.As(err, new(*payments.AllowanceRangeError)) {
		return allowanceOutOfRange(err)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return apiError(http.StatusNotFound, CodeNotFound, "user does not exist")
	}
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to read the allowance", err)
	}
	response := allowanceResponse(allowance)
	if policy != nil {
		response.Policy = &wire.AllowancePolicy{Kind: policy.Kind, Researcher: policy.Researcher, EligibleNodes: policy.EligibleNodes, DailyCeiling: strconv.FormatInt(policy.Ceiling, 10), HostingBonus: strconv.FormatInt(policy.HostingBonus, 10), Credited: strconv.FormatInt(policy.Credited, 10), NextReset: policy.NextReset}
		if policy.Kind == "credits" {
			response.Policy.DailyGrant = strconv.FormatInt(policy.DailyGrant, 10)
			response.Policy.BalanceCap = strconv.FormatInt(policy.BalanceCap, 10)
			response.Policy.HostingSeconds = strconv.FormatInt(policy.HostingSeconds, 10)
			response.Policy.HostingRate = strconv.FormatInt(policy.HostingRate, 10)
			response.Policy.HostingEarned = strconv.FormatInt(policy.HostingEarned, 10)
		}
	}
	return c.JSON(http.StatusOK, response)
}

// POST /operator/accounts/:id/allowance
//
// PostAccountAllowance records a grant to an account, issued by the calling
// operator account. A grant is never changed or removed, and a repeated
// request with the same idempotency key issues it once.
func (h *Handler) PostAccountAllowance(c echo.Context) error {
	operator, err := requireAccount(c)
	if err != nil {
		return err
	}
	if !operator.Operator {
		return apiError(http.StatusForbidden, CodeForbidden, "this operation requires an operator account")
	}
	if !h.dispatcher.Payment.AllowancesEnabled() {
		return allowancesDisabled()
	}
	account, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return apiError(http.StatusNotFound, CodeNotFound, "account not found")
	}
	var req wire.AllowanceGrantRequest
	if err := c.Bind(&req); err != nil {
		return bindError(err)
	}
	amount := h.dispatcher.Payment.DefaultAllowanceGrant()
	if req.Amount != "" {
		amount, err = strconv.ParseInt(req.Amount, 10, 64)
		if err != nil || amount <= 0 || strconv.FormatInt(amount, 10) != req.Amount {
			return apiError(http.StatusBadRequest, CodeInvalidRequest, "amount must be a positive decimal number of TEST units")
		}
	}
	reason := strings.TrimSpace(req.Reason)
	if !boundedText(reason, maxGrantReason) {
		return apiError(http.StatusBadRequest, CodeInvalidRequest,
			fmt.Sprintf("reason must contain 1 to %d characters without control characters", maxGrantReason))
	}
	if !boundedText(req.IdempotencyKey, maxGrantIdempotencyKey) || strings.TrimSpace(req.IdempotencyKey) != req.IdempotencyKey {
		return apiError(http.StatusBadRequest, CodeInvalidRequest,
			fmt.Sprintf("idempotency_key must contain 1 to %d characters without control characters or surrounding spaces", maxGrantIdempotencyKey))
	}
	result, err := h.dispatcher.Payment.GrantAllowance(c.Request().Context(), account, operator.UserUUID, amount, reason, req.IdempotencyKey)
	switch {
	case errors.Is(err, payments.ErrUnknownAccount):
		return apiError(http.StatusNotFound, CodeNotFound, "account not found")
	case errors.As(err, new(*payments.AllowanceRangeError)):
		return allowanceOutOfRange(err)
	case errors.Is(err, payments.ErrGrantConflict):
		return apiError(http.StatusConflict, CodeConflict, "idempotency_key already names a grant with a different amount or reason")
	case err != nil:
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to record the grant", err)
	}
	status := http.StatusOK
	if result.Created {
		status = http.StatusCreated
	}
	grant := result.Grant
	return c.JSON(status, wire.AllowanceGrantResult{
		Grant: wire.AllowanceGrant{
			ID: grant.ID, Amount: strconv.FormatInt(grant.Amount, 10), Currency: grant.Currency,
			Reason: grant.Reason, IdempotencyKey: grant.IdempotencyKey,
			GrantedBy: grant.GrantedBy.String(), GrantedAt: grant.GrantedAt.UTC(),
		},
		Allowance: allowanceResponse(result.Allowance),
	})
}

// boundedText reports whether value has 1 to limit characters, is valid UTF-8
// and contains no control characters.
func boundedText(value string, limit int) bool {
	count := utf8.RuneCountInString(value)
	return utf8.ValidString(value) && count >= 1 && count <= limit && !strings.ContainsFunc(value, unicode.IsControl)
}

// PutAccountAllowancePolicy replaces explicit eligibility without rewriting
// ledger history or today's refill decision.
func (h *Handler) PutAccountAllowancePolicy(c echo.Context) error {
	operator, err := requireAccount(c)
	if err != nil {
		return err
	}
	if !operator.Operator {
		return apiError(http.StatusForbidden, CodeForbidden, "this operation requires an operator account")
	}
	if !h.dispatcher.Payment.AllowancesEnabled() {
		return allowancesDisabled()
	}
	account, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return apiError(http.StatusNotFound, CodeNotFound, "account not found")
	}
	var input struct {
		Researcher          *bool    `json:"researcher"`
		ApprovedExecutorIDs []string `json:"approved_executor_ids"`
	}
	if err := decodeMeasurementRequest(c, &input); err != nil {
		return err
	}
	if input.Researcher == nil {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "researcher must be explicitly true or false")
	}
	req := wire.AllowanceEligibilityRequest{Researcher: *input.Researcher, ApprovedExecutorIDs: input.ApprovedExecutorIDs}
	if req.ApprovedExecutorIDs == nil || len(req.ApprovedExecutorIDs) > 100 {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "approved_executor_ids must be an array of at most 100 owned executor IDs")
	}
	ids := make([]uuid.UUID, len(req.ApprovedExecutorIDs))
	for i, raw := range req.ApprovedExecutorIDs {
		ids[i], err = uuid.Parse(raw)
		if err != nil {
			return apiError(http.StatusBadRequest, CodeInvalidRequest, "invalid executor ID")
		}
	}
	err = h.dispatcher.Payment.SetAllowanceEligibility(c.Request().Context(), account, operator.UserUUID, req.Researcher, ids)
	switch {
	case errors.Is(err, payments.ErrUnknownAccount):
		return apiError(http.StatusNotFound, CodeNotFound, "account not found")
	case errors.Is(err, payments.ErrInvalidHostingApproval):
		return apiError(http.StatusBadRequest, CodeInvalidRequest, err.Error())
	case err != nil:
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to update allowance eligibility", err)
	}
	return c.JSON(http.StatusOK, req)
}
