// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"time"
)

// Verify attributes captured packets to Debuglet runs (docs/verification.md).
// It groups the packets by source address and epoch, looks up the runs that
// were active from each address at the time in the dispatcher's public
// attribution history, and checks the tags against the disclosed keys
// offline: packets never leave this process. Groups whose key is not
// disclosed yet are pending. It needs no credential, and it fails only when
// the capture or the dispatcher cannot be read; every group verdict,
// including invalid ones, is part of the report.
//
// An offline verdict rests on the capture's timestamps: a key is used only
// if it was still secret at the capture time plus opts.ClockTolerance.
func (c *Client) Verify(ctx context.Context, packets []CapturedPacket, opts VerifyOptions) (VerifyReport, error) {
	if c == nil || c.http == nil {
		return VerifyReport{}, errors.New("client: Client must be created with New")
	}
	return verifyOffline(ctx, &clientSource{c: c}, packets, opts, time.Now())
}

// ErrNoAttributionHistory reports a dispatcher without the public
// attribution routes (API 1.11): it cannot answer dated lookups.
var ErrNoAttributionHistory = errors.New("client: verify: the dispatcher does not offer the attribution history (GET /attribution/candidates, API 1.11)")

// clientSource answers lookups from the dispatcher's public routes.
type clientSource struct{ c *Client }

// maxRateRetries is how often a rate-limited lookup is retried, waiting
// 1, 2, 4 and 8 seconds.
const maxRateRetries = 4

// retryRateLimited runs call, retrying while the dispatcher answers 429.
func retryRateLimited[T any](ctx context.Context, call func() (T, error)) (T, error) {
	wait := time.Second
	for attempt := 0; ; attempt++ {
		v, err := call()
		var httpErr *HTTPError
		if err == nil || attempt == maxRateRetries || !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusTooManyRequests {
			return v, err
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return v, err
		case <-timer.C:
		}
		wait *= 2
	}
}

func (s *clientSource) candidates(ctx context.Context, ip netip.Addr, at time.Time) (EvidenceLookup, error) {
	doc, err := retryRateLimited(ctx, func() (AttributionCandidates, error) {
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
	doc, err := retryRateLimited(ctx, func() (AttributionKeys, error) {
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
