// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// Verify attributes captured packets to Debuglet runs (docs/verification.md).
// It groups the packets by source address and epoch, looks up the runs that
// were active from each address at the time in the dispatcher's public
// attribution history, and checks the tags against the disclosed keys
// offline. Groups whose key is not disclosed yet are then sent to the
// dispatcher (the first 64 bytes of at most 256 packets per group), whose
// executor answers before disclosure; each answer comes with a signed
// receipt, which Verify checks and the evidence bundle keeps, and the group
// records method server. A group the server could not answer, and every such
// group with opts.Offline, is pending: then packets never leave this
// process. It needs no credential, and it fails only when the capture or the
// dispatcher cannot be read or a receipt does not verify; every group
// verdict, including invalid ones, is part of the report.
//
// The lookups are paced to the dispatcher's per-client rate limit
// (opts.RequestRate, opts.RequestBurst). A rate-limited request is retried
// after the dispatcher's Retry-After until ctx ends, and then Verify fails
// with a *RateLimitedError: give ctx a deadline.
//
// An offline verdict rests on the capture's timestamps: a key is used only
// if it was still secret at the capture time plus opts.ClockTolerance.
func (c *Client) Verify(ctx context.Context, packets []CapturedPacket, opts VerifyOptions) (VerifyReport, error) {
	if c == nil || c.http == nil {
		return VerifyReport{}, errors.New("client: Client must be created with New")
	}
	if opts.RequestBurst < 0 {
		return VerifyReport{}, errors.New("client: verify: negative request burst")
	}
	rate, burst := opts.RequestRate, opts.RequestBurst
	if rate == 0 {
		rate = DefaultVerifyRequestRate
	}
	if burst == 0 {
		burst = DefaultVerifyRequestBurst
	}
	src := &clientSource{c: c, pace: newPacer(rate, burst, time.Now)}
	rep, err := verifyOffline(ctx, src, packets, opts, time.Now())
	if err != nil || opts.Offline {
		return rep, err
	}
	if err := src.serverPass(ctx, &rep); err != nil {
		return VerifyReport{}, err
	}
	return rep, nil
}

// ErrNoAttributionHistory reports a dispatcher without the public
// attribution routes (API 1.11): it cannot answer dated lookups.
var ErrNoAttributionHistory = errors.New("client: verify: the dispatcher does not offer the attribution history (GET /attribution/candidates, API 1.11)")

// The dispatcher's documented per-client rate limit of the attribution
// routes (docs/verification.md#http-api), which Verify paces itself to.
const (
	DefaultVerifyRequestRate  = 10.0 // requests per second
	DefaultVerifyRequestBurst = 40
)

// defaultRetryAfter is the wait after a 429 without a usable Retry-After.
const defaultRetryAfter = time.Second

// RateLimitedError reports a verification that the dispatcher's rate limit
// held back until its context ended. The groups it names were not checked.
type RateLimitedError struct {
	// Throttled counts the requests the dispatcher answered 429.
	Throttled int
	// UncheckedGroups is how many groups remain without a verdict (at least
	// this many when Partial is set: the lookups had not reached every
	// packet), and UncheckedPackets how many packets they hold.
	UncheckedGroups  int
	UncheckedPackets int
	Partial          bool
	// Err is the context's error.
	Err error
}

func (e *RateLimitedError) Error() string {
	why := "the verification was paced to the dispatcher's rate limit"
	if e.Throttled > 0 {
		why = fmt.Sprintf("the dispatcher rate-limited the verification (%d requests answered 429 rate_limited)", e.Throttled)
	}
	least := ""
	if e.Partial {
		least = "at least "
	}
	return fmt.Sprintf("client: verify: %s until the context ended (%v); %s%d groups (%d packets) remain unchecked",
		why, e.Err, least, e.UncheckedGroups, e.UncheckedPackets)
}

func (e *RateLimitedError) Unwrap() error { return e.Err }

// errPaced marks a context that ended while a request waited for the rate
// limit; verifyOffline turns it into a *RateLimitedError.
type errPaced struct {
	throttled int
	err       error
}

func (e *errPaced) Error() string {
	return fmt.Sprintf("client: verify: rate limited until the context ended: %v", e.err)
}

func (e *errPaced) Unwrap() error { return e.err }

// pacer is a token bucket shared by the requests of one Verify: rate
// tokens per second up to burst, one per request. A 429 empties it and
// holds every request until the Retry-After has passed. A rate of zero or
// below disables it, but not the waits after a 429.
type pacer struct {
	mu        sync.Mutex
	rate      float64
	burst     float64
	tokens    float64
	last      time.Time
	hold      time.Time // no request before this, after a 429
	throttled int
	now       func() time.Time
}

func newPacer(rate float64, burst int, now func() time.Time) *pacer {
	return &pacer{rate: rate, burst: float64(burst), tokens: float64(burst), last: now(), now: now}
}

// wait blocks until a request may be sent, or ctx ends.
func (p *pacer) wait(ctx context.Context) error {
	for {
		p.mu.Lock()
		now := p.now()
		var delay time.Duration
		if now.Before(p.hold) {
			delay = p.hold.Sub(now)
		} else if p.rate > 0 {
			p.tokens = min(p.burst, p.tokens+now.Sub(p.last).Seconds()*p.rate)
			p.last = now
			if p.tokens >= 1 {
				p.tokens--
				p.mu.Unlock()
				return nil
			}
			delay = time.Duration((1 - p.tokens) / p.rate * float64(time.Second))
		} else {
			p.mu.Unlock()
			return nil
		}
		throttled := p.throttled
		p.mu.Unlock()
		if err := sleepCtx(ctx, max(delay, time.Millisecond)); err != nil {
			return &errPaced{throttled: throttled, err: err}
		}
	}
}

// limited records a 429: no request until after retryAfter.
func (p *pacer) limited(retryAfter time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.throttled++
	now := p.now()
	if until := now.Add(retryAfter); until.After(p.hold) {
		p.hold = until
	}
	p.tokens, p.last = 0, now
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// clientSource answers lookups from the dispatcher's public routes.
type clientSource struct {
	c    *Client
	pace *pacer
}

// paced runs call at the pacer's rate, retrying after the Retry-After while
// the dispatcher answers 429, until ctx ends.
func paced[T any](ctx context.Context, p *pacer, call func() (T, error)) (T, error) {
	for {
		var zero T
		if err := p.wait(ctx); err != nil {
			return zero, err
		}
		v, err := call()
		var httpErr *HTTPError
		if err == nil || !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusTooManyRequests {
			return v, err
		}
		wait := httpErr.RetryAfter
		if wait <= 0 {
			wait = defaultRetryAfter
		}
		p.limited(wait)
	}
}

func (s *clientSource) candidates(ctx context.Context, ip netip.Addr, at time.Time) (EvidenceLookup, error) {
	doc, err := paced(ctx, s.pace, func() (AttributionCandidates, error) {
		return s.c.AttributionCandidates(ctx, ip.String(), at)
	})
	if err != nil {
		var httpErr *HTTPError
		if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound {
			return EvidenceLookup{}, fmt.Errorf("%w: %v", ErrNoAttributionHistory, err)
		}
		return EvidenceLookup{}, err
	}
	out := EvidenceLookup{RetainedFrom: doc.RetainedFrom.UTC(), Truncated: doc.Truncated, Candidates: make([]EvidenceCandidate, 0, len(doc.Candidates))}
	for _, c := range doc.Candidates {
		s := c.Schedule
		out.Candidates = append(out.Candidates, EvidenceCandidate{
			ExecutorID: c.ExecutorID, RunID: c.RunID, ActiveFrom: c.ActiveFrom.UTC(), ActiveTo: c.ActiveTo.UTC(),
			IPSource: c.IPSource, DisclosedThrough: c.DisclosedThrough,
			Schedule: EvidenceSchedule{
				ChainID: s.ChainID, K0: s.K0, T0UnixNs: s.T0UnixNs, EpochSeconds: s.EpochSeconds,
				DisclosureDelayEpochs: s.DisclosureDelayEpochs, ChainLength: s.ChainLength, TagSpec: s.TagSpec,
			},
		})
	}
	return out, nil
}

func (s *clientSource) keys(ctx context.Context, executorID, chain string, from, to int64) ([]EvidenceKey, *int64, error) {
	if to < from {
		return nil, nil, nil
	}
	doc, err := paced(ctx, s.pace, func() (AttributionKeys, error) {
		return s.c.AttributionKeys(ctx, executorID, chain, from, to)
	})
	if err != nil {
		return nil, nil, err
	}
	out := make([]EvidenceKey, len(doc.Keys))
	for i, k := range doc.Keys {
		out[i] = EvidenceKey{Epoch: k.Epoch, Key: k.Key}
	}
	return out, doc.NextEpoch, nil
}

func (s *clientSource) describe() (string, string) {
	return s.c.origin + s.c.basePath, APIVersion
}
