// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"net/netip"
	"slices"
	"sort"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	"github.com/netsec-ethz/debuglet/pkg/tagspec"
	pb "github.com/netsec-ethz/debuglet/protocol"

	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// Server-assisted verification (docs/verification.md, method server). The
// packets of one source address in one epoch of one chain form a group. A
// group whose key is on record is checked here against the disclosed key
// (method offline). Before disclosure, the dispatcher asks the executor,
// which still holds the key, whether one candidate run reproduces every tag
// (method server). The executor never returns tags or keys, and every
// question spends one unit of a budget per executor, chain and epoch that all
// requesters share. The budget is spent durably before the question is
// relayed, so neither a crash nor a lost answer refunds it.

// Limits of server-assisted verification (docs/verification.md#limits).
const (
	// VerifyBudget is R, the executor queries per executor, chain and epoch.
	VerifyBudget = 16
	// MaxVerifyPackets bounds the packets of one request.
	MaxVerifyPackets = 256
	// MaxVerifyGroups bounds the groups one request forms.
	MaxVerifyGroups = 16
	// maxVerifyRuns is the most candidate runs one lookup may name.
	maxVerifyRuns = 32
	// maxVerifyDerivation bounds the hash steps from a recorded key down to
	// the epoch a group needs.
	maxVerifyDerivation = 1 << 20
	// verifyRelayTimeout bounds one executor query.
	verifyRelayTimeout = 5 * time.Second
	// verifyDisclosureGrace is how long after its due time a key that is not
	// on record still counts as about to be disclosed, as in the client.
	verifyDisclosureGrace = 2 * time.Minute
	// verifyNoRunWindow groups the packets of an address without a run.
	verifyNoRunWindow = time.Second
)

// Group verdicts, methods and the reasons this file adds to the client's.
const (
	VerifyVerified    = "verified"
	VerifyInvalid     = "invalid"
	VerifyPending     = "pending"
	VerifyMissing     = "missing"
	VerifyUnsupported = "unsupported"

	VerifyMethodOffline = "offline"
	VerifyMethodServer  = "server"

	// VerifyBudgetExhausted: every query of the epoch has been spent.
	VerifyBudgetExhausted = "budget_exhausted"
	// VerifyExecutorUnavailable: the executor did not answer.
	VerifyExecutorUnavailable = "executor_unavailable"
)

// ErrTooManyVerifyGroups reports a request whose packets form more than
// MaxVerifyGroups groups.
var ErrTooManyVerifyGroups = errors.New("the packets form more than 16 groups (one per source address and epoch)")

// VerifyPacket is one packet of a verification request.
type VerifyPacket struct {
	Data       []byte
	CapturedAt time.Time
}

// VerifyGroupResult is the verdict of one group. Packets are indices into the
// request. Budget is set for a group that has a chain.
type VerifyGroupResult struct {
	Source, ChainID, ExecutorID, RunID string
	Epoch                              int64
	Verdict, Reason, Method            string
	Packets                            []int
	Budget                             *VerifyBudgetState
}

// VerifyBudgetState is the budget of one executor, chain and epoch.
type VerifyBudgetState struct {
	Limit, Remaining int64
	ResetsAt         time.Time
}

// tagVerifier is the executor query of a bound control client.
type tagVerifier interface {
	VerifyTags(context.Context, *pb.VerifyTagsRequest, ...grpc.CallOption) (*pb.VerifyTagsResponse, error)
}

// verifyChain is a candidate chain with the runs it names.
type verifyChain struct {
	row  database.ListAttributionCandidatesRow
	runs []string
}

func (c verifyChain) epochOf(at time.Time) int64 {
	d, i := at.UnixNano()-c.row.T0Ns, c.row.IntervalNs
	e := d / i
	if d%i != 0 && d < 0 {
		e--
	}
	return e
}

func (c verifyChain) epochStart(e int64) time.Time {
	return time.Unix(0, c.row.T0Ns+e*c.row.IntervalNs)
}

// usableInterval is an epoch length the arithmetic here can work with.
func usableInterval(ns int64) bool {
	return ns >= int64(time.Second) && ns <= int64(1<<20)*int64(time.Second)
}

// VerifyAttribution forms the groups of packets and decides each of them.
func (d *Dispatcher) VerifyAttribution(ctx context.Context, packets []VerifyPacket) ([]VerifyGroupResult, error) {
	var out []VerifyGroupResult
	unsupported := map[[2]string][]int{}
	bySource := map[netip.Addr][]int{}
	for i, p := range packets {
		if _, err := tagspec.HashInput(p.Data); err != nil {
			reason := tagspec.UnsupportedMalformed
			var u *tagspec.UnsupportedError
			if errors.As(err, &u) {
				reason = u.Reason
			}
			key := [2]string{"", reason}
			if len(p.Data) >= 20 && p.Data[0]>>4 == 4 {
				key[0] = netip.AddrFrom4([4]byte(p.Data[12:16])).String()
			}
			unsupported[key] = append(unsupported[key], i)
			continue
		}
		addr := netip.AddrFrom4([4]byte(p.Data[12:16]))
		bySource[addr] = append(bySource[addr], i)
	}
	keys := make([][2]string, 0, len(unsupported))
	for key := range unsupported {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b [2]string) int { return bytes.Compare([]byte(a[0]+"\x00"+a[1]), []byte(b[0]+"\x00"+b[1])) })
	for _, key := range keys {
		out = append(out, VerifyGroupResult{Source: key[0], Verdict: VerifyUnsupported, Reason: key[1], Packets: unsupported[key]})
	}
	if len(out) > MaxVerifyGroups {
		return nil, ErrTooManyVerifyGroups
	}
	sources := make([]netip.Addr, 0, len(bySource))
	for addr := range bySource {
		sources = append(sources, addr)
	}
	slices.SortFunc(sources, netip.Addr.Compare)

	// Form the groups as the client does: a lookup at the first packet of a
	// source covers the packets up to the end of the current epoch of every
	// run it names, or a second when it names none. A window is split per
	// candidate chain, in which it lies within one epoch.
	type chainGroup struct {
		chain   verifyChain
		epoch   int64
		packets []int
	}
	var groups []chainGroup
	formed := len(out)
	for _, addr := range sources {
		idx := bySource[addr]
		sort.SliceStable(idx, func(x, y int) bool { return packets[idx[x]].CapturedAt.Before(packets[idx[y]].CapturedAt) })
		for len(idx) > 0 {
			if formed >= MaxVerifyGroups {
				return nil, ErrTooManyVerifyGroups
			}
			at := packets[idx[0]].CapturedAt
			retainedFrom, rows, err := d.verifyCandidates(ctx, addr.String(), at)
			if err != nil {
				return nil, err
			}
			end := at.Add(verifyNoRunWindow)
			var chains []verifyChain
			for _, row := range rows {
				if !usableInterval(row.IntervalNs) {
					continue
				}
				c := verifyChain{row: row}
				if ce := c.epochStart(c.epochOf(at) + 1); ce.Before(end) || len(chains) == 0 {
					end = ce
				}
				k := slices.IndexFunc(chains, func(o verifyChain) bool {
					return o.row.ExecutorID == row.ExecutorID && o.row.ChainID == row.ChainID
				})
				if k < 0 {
					chains = append(chains, c)
					k = len(chains) - 1
				}
				chains[k].runs = append(chains[k].runs, row.Uuid.String())
			}
			n := max(sort.Search(len(idx), func(k int) bool { return !packets[idx[k]].CapturedAt.Before(end) }), 1)
			window := slices.Clone(idx[:n])
			idx = idx[n:]
			base := VerifyGroupResult{Source: addr.String(), Packets: window}
			switch {
			case len(rows) > maxVerifyRuns:
				base.Verdict, base.Reason = VerifyUnsupported, "too_many_candidates"
			case len(rows) == 0 && at.Before(retainedFrom):
				base.Verdict, base.Reason = VerifyMissing, "not_retained"
			case len(rows) == 0:
				base.Verdict, base.Reason, base.Method = VerifyInvalid, "no_run", VerifyMethodOffline
			case len(chains) == 0:
				base.Verdict, base.Reason = VerifyUnsupported, "schedule"
			}
			if base.Verdict != "" {
				out = append(out, base)
				formed++
				continue
			}
			for _, c := range chains {
				groups = append(groups, chainGroup{chain: c, epoch: c.epochOf(at), packets: window})
				formed++
			}
			if formed > MaxVerifyGroups {
				return nil, ErrTooManyVerifyGroups
			}
		}
	}
	for _, g := range groups {
		out = append(out, d.verifyGroup(ctx, g.chain, g.epoch, g.packets, packets))
	}
	return out, nil
}

// verifyCandidates is the dated lookup of GET /attribution/candidates.
func (d *Dispatcher) verifyCandidates(ctx context.Context, ip string, at time.Time) (time.Time, []database.ListAttributionCandidatesRow, error) {
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return time.Time{}, nil, err
	}
	defer tx.Rollback()
	q := database.New(tx)
	retainedFrom, err := q.GetAttributionRetention(ctx)
	if err != nil {
		return time.Time{}, nil, err
	}
	rows, err := q.ListAttributionCandidates(ctx, database.ListAttributionCandidatesParams{SourceIp: ip, AtNs: at.UnixNano(), MaxRows: maxVerifyRuns + 1})
	if err != nil {
		return time.Time{}, nil, err
	}
	return time.Unix(0, retainedFrom), rows, tx.Commit()
}

// verifyGroup decides one group of one chain at one epoch.
func (d *Dispatcher) verifyGroup(ctx context.Context, c verifyChain, epoch int64, indices []int, packets []VerifyPacket) VerifyGroupResult {
	row := c.row
	source := netip.AddrFrom4([4]byte(packets[indices[0]].Data[12:16])).String()
	out := VerifyGroupResult{Source: source, ChainID: row.ChainID, ExecutorID: row.ExecutorID, Epoch: epoch, Packets: indices}
	due := c.epochStart(epoch + row.DelayEpochs)
	budget := &VerifyBudgetState{Limit: VerifyBudget, Remaining: VerifyBudget, ResetsAt: due.UTC()}
	switch {
	case row.TagSpec != tagspec.Version:
		out.Verdict, out.Reason = VerifyUnsupported, "tag_spec"
		return out
	case row.DelayEpochs < tagspec.MinDisclosureDelay:
		out.Verdict, out.Reason = VerifyUnsupported, "disclosure_delay"
		return out
	case epoch < 1 || (row.ChainLength > 0 && epoch >= row.ChainLength):
		out.Verdict, out.Reason = VerifyUnsupported, "no_signing_key"
		return out
	}
	out.Budget = budget
	q := database.New(d.db)
	budgetKey := database.GetAttributionVerifyBudgetParams{ExecutorID: row.ExecutorID, ChainID: row.ChainID, Epoch: epoch}
	if used, err := q.GetAttributionVerifyBudget(ctx, budgetKey); err == nil {
		budget.Remaining = max(VerifyBudget-used, 0)
	}

	// A key on record answers without the executor and spends nothing.
	if key, ok, err := d.recordedEpochKey(ctx, row.ExecutorID, row.ChainID, epoch); err != nil {
		out.Verdict, out.Reason = VerifyPending, VerifyExecutorUnavailable
		d.logger.Warn("Failed to read a disclosed key for verification", zap.String("executorID", row.ExecutorID), zap.Error(err))
		return out
	} else if ok {
		out.Method = VerifyMethodOffline
		out.Verdict, out.Reason, out.RunID = matchRuns(key, c.runs, indices, packets)
		return out
	}
	now := d.now()
	if !now.Before(due) {
		// The executor no longer answers for a disclosable epoch.
		if now.Before(due.Add(verifyDisclosureGrace)) {
			out.Verdict, out.Reason = VerifyPending, "not_disclosed"
		} else {
			out.Verdict, out.Reason = VerifyMissing, "keys_missing"
		}
		return out
	}
	d.mu.RLock()
	entry := d.executors[row.ExecutorID]
	var owner *rpc.SessionOwner
	if !d.closed && entry != nil && entry.owner.Available() && bytes.Equal(entry.TeslaAnchorKey, row.Anchor) {
		owner = entry.owner
	}
	d.mu.RUnlock()
	if owner == nil {
		// Nothing is asked, so nothing is spent.
		out.Verdict, out.Reason = VerifyPending, VerifyExecutorUnavailable
		return out
	}
	used, err := d.spendVerifyBudget(ctx, row.ExecutorID, row.ChainID, epoch, now)
	if errors.Is(err, sql.ErrNoRows) {
		budget.Remaining = 0
		out.Verdict, out.Reason = VerifyPending, VerifyBudgetExhausted
		return out
	}
	if err != nil {
		out.Verdict, out.Reason = VerifyPending, VerifyExecutorUnavailable
		d.logger.Warn("Failed to spend a verification query", zap.String("executorID", row.ExecutorID), zap.Error(err))
		return out
	}
	budget.Remaining = max(VerifyBudget-used, 0)
	out.Verdict, out.Reason, out.RunID = d.relayVerify(ctx, owner, row.Anchor, epoch, c.runs, indices, packets)
	if out.Verdict != VerifyPending {
		out.Method = VerifyMethodServer
	}
	return out
}

// spendVerifyBudget counts one query of the epoch, in its own transaction,
// and returns the queries used. It returns sql.ErrNoRows when the budget is
// exhausted. Counts of epochs already due for disclosure are dropped first.
func (d *Dispatcher) spendVerifyBudget(ctx context.Context, executorID, chainID string, epoch int64, now time.Time) (int64, error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	q := database.New(tx)
	if _, err := q.PruneAttributionVerifyBudget(ctx, now.UnixNano()); err != nil {
		return 0, err
	}
	used, err := q.SpendAttributionVerifyBudget(ctx, database.SpendAttributionVerifyBudgetParams{
		ExecutorID: executorID, ChainID: chainID, Epoch: epoch,
	})
	if err != nil {
		return 0, err
	}
	return used, tx.Commit()
}

// recordedEpochKey derives the key of an epoch from the lowest key on record
// at or above it. Recorded keys were checked against their chain when they
// were stored.
func (d *Dispatcher) recordedEpochKey(ctx context.Context, executorID, chainID string, epoch int64) ([]byte, bool, error) {
	row, err := database.New(d.db).NextAttributionKey(ctx, database.NextAttributionKeyParams{ExecutorID: executorID, ChainID: chainID, Epoch: epoch})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if row.Epoch-epoch > maxVerifyDerivation {
		return nil, false, nil
	}
	key := bytes.Clone(row.Key)
	for e := row.Epoch; e > epoch; e-- {
		sum := sha256.Sum256(key)
		key = sum[:]
	}
	return key, true, nil
}

// matchRuns decides a group against a disclosed key with the executor's
// rule: the one run that reproduces every tag is verified; none is a
// mismatch; several are ambiguous.
func matchRuns(key []byte, runs []string, indices []int, packets []VerifyPacket) (verdict, reason, run string) {
	var matched []string
	for _, candidate := range runs {
		ak, err := tagspec.DeriveAK(key, []byte(candidate))
		if err != nil {
			continue
		}
		all := true
		for _, i := range indices {
			in, _ := tagspec.HashInput(packets[i].Data)
			id, _ := tagspec.PacketID(packets[i].Data)
			if tag, err := tagspec.ComputeTag(ak, in); err != nil || tag != id {
				all = false
				break
			}
		}
		if all {
			matched = append(matched, candidate)
		}
	}
	switch len(matched) {
	case 0:
		return VerifyInvalid, "tag_mismatch", ""
	case 1:
		return VerifyVerified, "", matched[0]
	}
	return VerifyUnsupported, "ambiguous", ""
}

// executorReasons are the reasons an executor may give for unsupported.
var executorReasons = map[string]bool{
	"unknown_chain": true, "epoch_unavailable": true, "attribution_unavailable": true, "too_many": true, "malformed": true,
}

// relayVerify asks the executor about one group over its control session,
// the way confirmRunRetirement inspects retained work.
func (d *Dispatcher) relayVerify(ctx context.Context, owner *rpc.SessionOwner, anchor []byte, epoch int64, runs []string, indices []int, packets []VerifyPacket) (verdict, reason, run string) {
	call, cancel := context.WithTimeout(ctx, verifyRelayTimeout)
	defer cancel()
	mutation, err := owner.AdmitMutation(call)
	if err != nil {
		return VerifyPending, VerifyExecutorUnavailable, ""
	}
	defer mutation.Finish()
	client, available := d.Bidi.GetClientFor(owner)
	verifier, supported := client.(tagVerifier)
	if !available || !supported {
		return VerifyPending, VerifyExecutorUnavailable, ""
	}
	req := &pb.VerifyTagsRequest{ChainAnchor: anchor, Epoch: epoch, CandidateRunIds: runs}
	binding := owner.Binding()
	req.ControlBinding = &pb.ControlBinding{DispatcherIncarnation: binding.Incarnation, SessionId: binding.SessionID}
	for _, i := range indices {
		req.Packets = append(req.Packets, packets[i].Data)
	}
	reply, err := verifier.VerifyTags(mutation.Context(), req, grpc.MaxCallRecvMsgSize(4096))
	if err != nil || reply == nil {
		d.logger.Info("An executor did not answer a verification query; the query stays spent",
			zap.String("executorID", owner.ExecutorID()), zap.Error(err))
		return VerifyPending, VerifyExecutorUnavailable, ""
	}
	switch reply.GetVerdict() {
	case "matched":
		if slices.Contains(runs, reply.GetRunId()) {
			return VerifyVerified, "", reply.GetRunId()
		}
	case "unmatched":
		return VerifyInvalid, "tag_mismatch", ""
	case "ambiguous":
		return VerifyUnsupported, "ambiguous", ""
	case "unsupported":
		if executorReasons[reply.GetReason()] {
			return VerifyUnsupported, reply.GetReason(), ""
		}
	}
	d.logger.Warn("An executor answered a verification query outside the protocol", zap.String("executorID", owner.ExecutorID()))
	return VerifyPending, VerifyExecutorUnavailable, ""
}
