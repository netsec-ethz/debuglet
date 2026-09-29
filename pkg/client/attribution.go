// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

type (
	AttributionCandidates = wire.AttributionCandidates
	AttributionCandidate  = wire.AttributionCandidate
	AttributionSchedule   = wire.AttributionSchedule
	AttributionKeys       = wire.AttributionKeys
	AttributionKey        = wire.AttributionKey
)

// Tag specification versions of an AttributionSchedule: a legacy chain is
// unsupported under tag spec v1.
const (
	TagSpecVersionLegacy = wire.TagSpecVersionLegacy
	TagSpecVersionV1     = wire.TagSpecVersionV1
)

const (
	routeAttributionCandidates = "attribution/candidates"
	routeAttributionKeys       = "attribution/keys"

	// Limits of the attribution routes (docs/verification.md).
	maxAttributionCandidates = 32
	maxAttributionKeyPage    = 1024
)

// AttributionCandidates lists the runs that were active from ip within one
// epoch of at, with the schedule of each run's chain. It needs no credential
// and names runs and executors only, never accounts. An empty answer for a
// time before RetainedFrom is no evidence either way. This optional API 1.11
// route is absent on older dispatchers, which answer 404.
func (c *Client) AttributionCandidates(ctx context.Context, ip string, at time.Time) (AttributionCandidates, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return AttributionCandidates{}, errors.New("client: attribution lookup needs an IP address")
	}
	if at.IsZero() {
		return AttributionCandidates{}, errors.New("client: attribution lookup needs a time")
	}
	query := url.Values{"ip": {addr.String()}, "at": {at.UTC().Format(time.RFC3339Nano)}}
	data, err := c.do(ctx, http.MethodGet, routeAttributionCandidates, query, nil, http.StatusOK)
	if err != nil {
		return AttributionCandidates{}, err
	}
	var doc AttributionCandidates
	if err := c.decode(http.MethodGet, routeAttributionCandidates, data, &doc); err != nil {
		return AttributionCandidates{}, err
	}
	valid := doc.Candidates != nil && len(doc.Candidates) <= maxAttributionCandidates && !doc.RetainedFrom.IsZero()
	for _, candidate := range doc.Candidates {
		s := candidate.Schedule
		valid = valid && isCanonicalUUID(candidate.RunID) && !isNilUUID(candidate.RunID) &&
			strings.TrimSpace(candidate.ExecutorID) != "" && !candidate.ActiveTo.Before(candidate.ActiveFrom) &&
			(candidate.IPSource == "observed" || candidate.IPSource == "advertised") &&
			s.ChainID != "" && len(s.K0) > 0 && s.EpochSeconds >= 0 && s.DisclosureDelayEpochs >= 0 && s.ChainLength >= 0 &&
			s.TagSpec >= 0 && candidate.DisclosedThrough >= 0 && candidate.DisclosedThroughAtNs >= 0 &&
			candidate.NextDisclosureAtNs >= 0 && (candidate.DisclosedThrough == 0) == (candidate.DisclosedThroughAtNs == 0)
	}
	if !valid {
		return AttributionCandidates{}, c.protocolErr(http.MethodGet, routeAttributionCandidates, "inconsistent attribution candidates")
	}
	return doc, nil
}

// AttributionKeys returns one page of the disclosed keys of a chain, from
// fromEpoch towards toEpoch, spanning at most 1024 epochs; NextEpoch names
// the fromEpoch of the next page while keys beyond this one exist. A toEpoch
// of zero sets no bound.
// Undisclosed epochs are absent, and the caller checks every key against the
// chain's K0 itself. It needs no credential. This optional API 1.11 route is
// absent on older dispatchers, which answer 404.
func (c *Client) AttributionKeys(ctx context.Context, executorID, chainID string, fromEpoch, toEpoch int64) (AttributionKeys, error) {
	if strings.TrimSpace(executorID) == "" || strings.TrimSpace(chainID) == "" {
		return AttributionKeys{}, errors.New("client: attribution keys need an executor and a chain")
	}
	if fromEpoch < 0 || toEpoch < 0 || (toEpoch != 0 && toEpoch < fromEpoch) {
		return AttributionKeys{}, errors.New("client: invalid attribution key epoch range")
	}
	query := url.Values{"executor_id": {executorID}, "chain_id": {chainID}, "from_epoch": {strconv.FormatInt(fromEpoch, 10)}}
	last := fromEpoch + maxAttributionKeyPage - 1
	if toEpoch != 0 {
		query.Set("to_epoch", strconv.FormatInt(toEpoch, 10))
		last = min(last, toEpoch)
	}
	data, err := c.do(ctx, http.MethodGet, routeAttributionKeys, query, nil, http.StatusOK)
	if err != nil {
		return AttributionKeys{}, err
	}
	var doc AttributionKeys
	if err := c.decode(http.MethodGet, routeAttributionKeys, data, &doc); err != nil {
		return AttributionKeys{}, err
	}
	valid := doc.ExecutorID == executorID && doc.ChainID == chainID && doc.Keys != nil
	previous := fromEpoch - 1
	for _, key := range doc.Keys {
		valid = valid && key.Epoch > previous && key.Epoch <= last && len(key.Key) > 0
		previous = key.Epoch
	}
	if doc.NextEpoch != nil {
		valid = valid && *doc.NextEpoch == last+1
	}
	if !valid {
		return AttributionKeys{}, c.protocolErr(http.MethodGet, routeAttributionKeys, "inconsistent attribution key page")
	}
	return doc, nil
}
