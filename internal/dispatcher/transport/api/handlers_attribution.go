// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"database/sql"
	"errors"
	"math"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/pkg/wire"

	"github.com/labstack/echo/v4"
	"golang.org/x/time/rate"
)

// The public attribution routes (docs/verification.md). They need no
// credential and answer run and executor identifiers only, never the account
// of a run.
const (
	routeAttributionCandidates = "/attribution/candidates"
	routeDisclosures           = "/attribution/keys"
)

// Limits of the attribution routes.
const (
	// maxAttributionCandidates bounds the runs one lookup lists.
	maxAttributionCandidates = 32
	// maxAttributionKeyPage bounds the epochs one key page spans.
	maxAttributionKeyPage = 1024
	// attributionRate and attributionBurst bound the requests one client
	// address makes to these routes.
	attributionRate  = rate.Limit(10)
	attributionBurst = 40
)

type (
	AttributionCandidatesResponse = wire.AttributionCandidates
	AttributionKeysResponse       = wire.AttributionKeys
)

// GET /attribution/candidates?ip=<ip>&at=<RFC 3339 time>
//
// The runs that were active from ip within one epoch of at, each with its
// executor's chain schedule and the latest disclosed epoch of that chain.
func (h *Handler) GetAttributionCandidates(c echo.Context) error {
	if err := h.attributionLimiter.allow(c); err != nil {
		return err
	}
	rawIP, rawAt := c.QueryParam("ip"), c.QueryParam("at")
	if rawIP == "" || rawAt == "" {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "ip and at query parameters are required")
	}
	addr, err := netip.ParseAddr(rawIP)
	if err != nil {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "ip is not an IP address: "+echoed(rawIP))
	}
	ip := addr.WithZone("").Unmap().String()
	at, err := time.Parse(time.RFC3339Nano, rawAt)
	if err != nil {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "at is not an RFC 3339 time: "+echoed(rawAt))
	}
	ctx := c.Request().Context()
	// Retention and candidates must describe the same snapshot: a concurrent
	// prune must not pair an old coverage marker with newly removed runs.
	tx, err := h.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to read the attribution history", err)
	}
	defer tx.Rollback()
	queries := database.New(tx)
	retainedFrom, err := queries.GetAttributionRetention(ctx)
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to read the attribution history", err)
	}
	rows, err := queries.ListAttributionCandidates(ctx, database.ListAttributionCandidatesParams{
		SourceIp: ip, AtNs: at.UnixNano(), MaxRows: maxAttributionCandidates + 1,
	})
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to read the attribution history", err)
	}
	if err := tx.Commit(); err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to read the attribution history", err)
	}
	resp := AttributionCandidatesResponse{
		IP: ip, At: at.UTC(), RetainedFrom: time.Unix(0, retainedFrom).UTC(),
		Candidates: []wire.AttributionCandidate{}, Truncated: len(rows) > maxAttributionCandidates,
	}
	if resp.Truncated {
		rows = rows[:maxAttributionCandidates]
	}
	for _, row := range rows {
		source := "advertised"
		if row.SourceIpObserved == 1 {
			source = "observed"
		}
		resp.Candidates = append(resp.Candidates, wire.AttributionCandidate{
			ExecutorID: row.ExecutorID, RunID: row.Uuid.String(),
			ActiveFrom: time.Unix(0, row.ActiveFromNs).UTC(), ActiveTo: time.Unix(0, row.ActiveToNs).UTC(),
			IPSource: source,
			Schedule: wire.AttributionSchedule{
				ChainID: row.ChainID, K0: row.Anchor, T0UnixNs: row.T0Ns, EpochSeconds: int64(time.Duration(row.IntervalNs) / time.Second),
				DisclosureDelayEpochs: row.DelayEpochs, ChainLength: row.ChainLength, TagSpec: row.TagSpec,
			},
			DisclosedThrough:     row.DisclosedThrough,
			DisclosedThroughAtNs: row.DisclosedThroughAtNs,
			NextDisclosureAtNs:   nextDisclosureAtNs(row.T0Ns, row.IntervalNs, row.DelayEpochs, row.DisclosedThrough),
		})
	}
	return c.JSON(http.StatusOK, resp)
}

// nextDisclosureAtNs is the earliest Unix nanoseconds the key of epoch
// disclosedThrough+1 may be disclosed: t0 + (disclosedThrough+1+d)*I, with
// d = 1 for an executor that reported none, as the key store enforces. It is
// 0 when the schedule is unknown or the time does not fit.
func nextDisclosureAtNs(t0Ns, intervalNs, delayEpochs, disclosedThrough int64) int64 {
	if intervalNs <= 0 {
		return 0
	}
	d := max(delayEpochs, 1)
	epochs := disclosedThrough + 1 + d
	if epochs <= 0 || epochs > (math.MaxInt64-max(t0Ns, 0))/intervalNs {
		return 0
	}
	return t0Ns + epochs*intervalNs
}

// GET /attribution/keys?executor_id=<id>&chain_id=<chain>[&from_epoch=<n>][&to_epoch=<n>]
//
// One page of the disclosed keys of a chain, from from_epoch (default 1)
// towards to_epoch (default unbounded), spanning at most
// maxAttributionKeyPage epochs.
func (h *Handler) GetAttributionKeys(c echo.Context) error {
	if err := h.attributionLimiter.allow(c); err != nil {
		return err
	}
	executorID, chainID := c.QueryParam("executor_id"), c.QueryParam("chain_id")
	if executorID == "" || chainID == "" {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "executor_id and chain_id query parameters are required")
	}
	from, err := epochParam(c, "from_epoch", 1)
	if err != nil {
		return err
	}
	to, err := epochParam(c, "to_epoch", maxEpochParam)
	if err != nil {
		return err
	}
	if to < from {
		return apiError(http.StatusBadRequest, CodeInvalidRequest, "to_epoch must not be below from_epoch")
	}
	pageEnd := min(from+maxAttributionKeyPage-1, to)

	ctx := c.Request().Context()
	queries := database.New(h.db)
	chainKey := database.GetAttributionChainParams{ExecutorID: executorID, ChainID: chainID}
	if _, err := queries.GetAttributionChain(ctx, chainKey); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return apiError(http.StatusNotFound, CodeNotFound, "no chain of that executor is on record")
		}
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to read the attribution history", err)
	}
	rows, err := queries.ListAttributionKeys(ctx, database.ListAttributionKeysParams{
		ExecutorID: executorID, ChainID: chainID, FromEpoch: from, ToEpoch: pageEnd,
	})
	if err != nil {
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to read the attribution history", err)
	}
	resp := AttributionKeysResponse{ExecutorID: executorID, ChainID: chainID, Keys: make([]wire.AttributionKey, 0, len(rows))}
	for _, row := range rows {
		resp.Keys = append(resp.Keys, wire.AttributionKey{Epoch: row.Epoch, Key: row.Key})
	}
	if pageEnd < to {
		// A further page is announced only while keys beyond this one exist.
		latest, err := queries.LatestAttributionKey(ctx, database.LatestAttributionKeyParams(chainKey))
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to read the attribution history", err)
		}
		if err == nil && latest.Epoch > pageEnd {
			next := pageEnd + 1
			resp.NextEpoch = &next
		}
	}
	return c.JSON(http.StatusOK, resp)
}

// maxEpochParam bounds an epoch parameter, so that from_epoch +
// maxAttributionKeyPage cannot overflow.
const maxEpochParam = 1 << 62

// epochParam parses an optional non-negative epoch query parameter.
func epochParam(c echo.Context, name string, fallback int64) (int64, error) {
	raw := c.QueryParam(name)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < 0 || value > maxEpochParam {
		return 0, apiError(http.StatusBadRequest, CodeInvalidRequest, name+" must be a non-negative integer")
	}
	return value, nil
}

// addressLimiter is a token bucket per client address. The address is the
// TCP peer of the request: forwarding headers are set by whoever sent the
// request and are not trusted, unless the peer is one of the configured
// trusted proxies (see AttributionTrustedProxies). Without one, every client
// behind a reverse proxy shares the proxy's bucket. An IPv6 client is limited
// by its /64.
type addressLimiter struct {
	limit   rate.Limit
	burst   int
	trusted []netip.Prefix
	mu      sync.Mutex
	buckets map[netip.Addr]*addressBucket
	now     func() time.Time
}

type addressBucket struct {
	limiter *rate.Limiter
	seen    time.Time
}

// Bounds of the limiter's own state: an idle bucket is full again after
// burst/limit seconds and can be dropped, and the table is never larger than
// maxAddressBuckets.
const (
	addressBucketIdle = 10 * time.Minute
	maxAddressBuckets = 1 << 16
)

func newAddressLimiter(limit rate.Limit, burst int) *addressLimiter {
	return &addressLimiter{limit: limit, burst: burst, buckets: make(map[netip.Addr]*addressBucket), now: time.Now}
}

// allow spends one token of the request's client address, or answers 429
// with code rate_limited and a Retry-After of one second.
func (l *addressLimiter) allow(c echo.Context) error {
	if l == nil {
		return nil
	}
	key := clientAddress(c.Request(), l.trusted)
	now := l.now()
	l.mu.Lock()
	bucket := l.buckets[key]
	if bucket == nil {
		if len(l.buckets) >= maxAddressBuckets {
			for addr, b := range l.buckets {
				if now.Sub(b.seen) > addressBucketIdle {
					delete(l.buckets, addr)
				}
			}
			if len(l.buckets) >= maxAddressBuckets {
				clear(l.buckets)
			}
		}
		bucket = &addressBucket{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.buckets[key] = bucket
	}
	bucket.seen = now
	allowed := bucket.limiter.AllowN(now, 1)
	l.mu.Unlock()
	if !allowed {
		c.Response().Header().Set("Retry-After", "1")
		return apiError(http.StatusTooManyRequests, CodeRateLimited, "too many attribution requests from this address; retry later")
	}
	return nil
}

// clientAddress is the limiter key of a request: its client address, an IPv6
// client reduced to its /64. The client address is the TCP peer, unless the
// peer is a trusted proxy: X-Forwarded-For is then read from the right, each
// entry appended by the hop before it, and the first entry that is not a
// trusted proxy is the client. Entries left of it were written by the client
// itself and are ignored. A malformed entry ends the walk at the last trusted
// hop, so a client cannot choose its bucket by sending garbage.
func clientAddress(r *http.Request, trusted []netip.Prefix) netip.Addr {
	addr := parseHostAddr(r.RemoteAddr)
	if addr.IsValid() && isTrustedProxy(addr, trusted) {
		hops := strings.Split(strings.Join(r.Header.Values(echo.HeaderXForwardedFor), ","), ",")
		for i := len(hops) - 1; i >= 0; i-- {
			hop := parseHostAddr(strings.TrimSpace(hops[i]))
			if !hop.IsValid() {
				break
			}
			addr = hop
			if !isTrustedProxy(hop, trusted) {
				break
			}
		}
	}
	return limiterKey(addr)
}

// parseHostAddr parses an address with or without a port, or returns the
// zero Addr.
func parseHostAddr(value string) netip.Addr {
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		host = value
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr.WithZone("").Unmap()
}

func isTrustedProxy(addr netip.Addr, trusted []netip.Prefix) bool {
	for _, prefix := range trusted {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// limiterKey reduces an IPv6 address to its /64.
func limiterKey(addr netip.Addr) netip.Addr {
	if !addr.IsValid() {
		return netip.Addr{}
	}
	if addr.Is6() {
		if prefix, err := addr.Prefix(64); err == nil {
			return prefix.Addr()
		}
	}
	return addr
}

// AttributionTrustedProxies names the reverse proxies whose X-Forwarded-For
// header the attribution rate limit trusts (attribution.trusted_proxies).
// With none, the limit counts the TCP peer of every request.
func AttributionTrustedProxies(prefixes []netip.Prefix) Option {
	return func(h *Handler) {
		if h.attributionLimiter != nil {
			h.attributionLimiter.trusted = slices.Clone(prefixes)
		}
	}
}
