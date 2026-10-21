// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPresenceCountsAccountsAndExpiresWithoutHistory(t *testing.T) {
	var memo presenceMemo
	now := time.Now()
	a, b := uuid.New(), uuid.New()
	for _, step := range []struct {
		account uuid.UUID
		elapsed time.Duration
		count   int
	}{
		{a, 0, 1}, {a, time.Second, 1}, {b, time.Minute, 2},
		{b, presenceWindow + time.Second, 1}, {a, 4*time.Minute + 2*time.Second, 1},
	} {
		count, ok := memo.touch(step.account, now.Add(step.elapsed))
		if !ok || count != step.count {
			t.Fatalf("heartbeat at %s: count=%d accepted=%t, want %d", step.elapsed, count, ok, step.count)
		}
	}
	if len(memo.seen) != 1 {
		t.Fatal("expired accounts retained")
	}
}

func TestPresenceBoundAndConcurrentTabs(t *testing.T) {
	var memo presenceMemo
	now := time.Now()
	account := uuid.New()
	var group sync.WaitGroup
	for range 32 {
		group.Go(func() {
			if count, ok := memo.touch(account, now); !ok || count != 1 {
				t.Errorf("same-account tabs counted separately: %d, %t", count, ok)
			}
		})
	}
	group.Wait()
	for len(memo.seen) < presenceLimit {
		memo.seen[uuid.New()] = now
	}
	if _, ok := memo.touch(uuid.New(), now); ok {
		t.Fatal("exceeded presence bound")
	}
	if count, ok := memo.touch(account, now); !ok || count != presenceLimit {
		t.Fatal("existing account lost at capacity")
	}
	if count, ok := memo.touch(uuid.New(), now.Add(presenceWindow)); !ok || count != 1 {
		t.Fatal("expired capacity not reclaimed")
	}
}

func TestPresenceRequiresSessionAndCSRFAndReturnsOnlyAggregate(t *testing.T) {
	f := credentialFixture(t)
	browser := credentialBrowser(t, f)
	other := credentialBrowser(t, f)
	credential := createTestCredential(t, f, browser, "account:read")
	for _, headers := range []map[string]string{nil, {"Cookie": browser["Cookie"]}, authBearer(credential.Token)} {
		status, _, _, _ := authRequest(t, f, http.MethodPost, "/me/presence", nil, headers)
		if status != http.StatusUnauthorized && status != http.StatusForbidden {
			t.Fatalf("unproven presence accepted: %d", status)
		}
	}
	for i, headers := range []map[string]string{browser, browser, other} {
		status, _, body, response := authRequest(t, f, http.MethodPost, "/me/presence", nil, headers)
		if status != http.StatusOK {
			t.Fatalf("presence status %d: %s", status, body)
		}
		var data map[string]int
		if err := json.Unmarshal(body, &data); err != nil {
			t.Fatal(err)
		}
		want := 1
		if i == 2 {
			want = 2
		}
		if len(data) != 2 || data["active_accounts"] != want || data["window_seconds"] != 120 {
			t.Fatalf("unexpected aggregate: %s", body)
		}
		if response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("presence may be cached")
		}
	}
}
