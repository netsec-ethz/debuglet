// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

const (
	presenceWindow = 2 * time.Minute
	presenceLimit  = 10000
)

// presenceMemo records only recent account heartbeats. It is process-local and
// expires entries on observation, so there is no persistent activity history.
type presenceMemo struct {
	mu   sync.Mutex
	seen map[uuid.UUID]time.Time
}

func (p *presenceMemo) touch(account uuid.UUID, now time.Time) (int, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen == nil {
		p.seen = make(map[uuid.UUID]time.Time)
	}
	for id, seen := range p.seen {
		if now.Sub(seen) >= presenceWindow {
			delete(p.seen, id)
		}
	}
	if _, exists := p.seen[account]; !exists && len(p.seen) >= presenceLimit {
		return 0, false
	}
	p.seen[account] = now
	return len(p.seen), true
}

// PostPresence records a signed-in account's console heartbeat and returns
// only an aggregate. Multiple tabs or sessions for one account count once.
func (h *Handler) PostPresence(c echo.Context) error {
	account, err := requireAccount(c)
	if err != nil {
		return err
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	count, recorded := h.presence.touch(account.UserUUID, time.Now())
	if !recorded {
		c.Response().Header().Set("Retry-After", "30")
		return apiError(http.StatusServiceUnavailable, CodeUnavailable, "console activity count is temporarily unavailable")
	}
	return c.JSON(http.StatusOK, struct {
		ActiveAccounts int `json:"active_accounts"`
		WindowSeconds  int `json:"window_seconds"`
	}{count, int(presenceWindow / time.Second)})
}
