// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"crypto/hmac"
	"time"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
	"github.com/netsec-ethz/debuglet/internal/executor/transport/rpc"
	"github.com/netsec-ethz/debuglet/internal/ids"
	"github.com/netsec-ethz/debuglet/pkg/tagspec"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Bounds of one pre-disclosure verification query (docs/verification.md).
const (
	maxVerifyCandidates = 32
	maxVerifyPackets    = 256
	// minVerifyPacket is an IPv4 header without options; a captured packet
	// carries at most the tag input, tesla.MaxTagInput bytes.
	minVerifyPacket = 20
)

// Verdicts and reasons of VerifyTagsResponse.
const (
	verifyMatched     = "matched"
	verifyUnmatched   = "unmatched"
	verifyAmbiguous   = "ambiguous"
	verifyUnsupported = "unsupported"

	verifyUnknownChain           = "unknown_chain"
	verifyEpochUnavailable       = "epoch_unavailable"
	verifyAttributionUnavailable = "attribution_unavailable"
	verifyTooMany                = "too_many"
	verifyMalformed              = "malformed"
)

// OnVerifyTags answers whether exactly one candidate run reproduces the tag of
// every packet of one group, under a key this executor has not disclosed yet.
// The answer is one verdict for the whole group: it never carries tags, keys
// or per-packet results, and neither does the log. Duplicate candidate IDs are
// malformed, so ambiguous means two distinct runs reproduce every tag.
func (e *Executor) OnVerifyTags(ctx context.Context, binding controlsession.Binding, req *pb.VerifyTagsRequest) (*pb.VerifyTagsResponse, error) {
	if err := e.checkExecutionLease(ctx, binding); err != nil {
		return nil, err
	}
	if err := rpc.CheckPayloadBinding(req.GetControlBinding(), binding); err != nil {
		return nil, err
	}
	resp, err := e.verifyTags(req, time.Now())
	if err != nil {
		return nil, err
	}
	e.logger.Info("Answered tag verification query", zap.Int("candidates", len(req.GetCandidateRunIds())),
		zap.Int("packets", len(req.GetPackets())), zap.String("verdict", resp.Verdict), zap.String("reason", resp.Reason))
	if resp.RunId != "" {
		e.logger.Debug("Private tag verification diagnostic", zap.String("debugletID", resp.RunId))
	}
	return resp, nil
}

func verifyRefused(reason string) *pb.VerifyTagsResponse {
	return &pb.VerifyTagsResponse{Verdict: verifyUnsupported, Reason: reason}
}

// verifyTags decides the verdict at now. A group whose bytes tag spec v1
// assigns no tag is malformed rather than unmatched.
func (e *Executor) verifyTags(req *pb.VerifyTagsRequest, now time.Time) (*pb.VerifyTagsResponse, error) {
	candidates, packets := req.GetCandidateRunIds(), req.GetPackets()
	if len(candidates) > maxVerifyCandidates || len(packets) > maxVerifyPackets {
		return verifyRefused(verifyTooMany), nil
	}
	if len(candidates) == 0 || len(packets) == 0 {
		return verifyRefused(verifyMalformed), nil
	}
	seen := make(map[string]struct{}, len(candidates))
	for _, id := range candidates {
		if _, ok := ids.ParseCanonical(id); !ok {
			return verifyRefused(verifyMalformed), nil
		}
		if _, dup := seen[id]; dup {
			return verifyRefused(verifyMalformed), nil
		}
		seen[id] = struct{}{}
	}
	inputs, tags := make([][]byte, len(packets)), make([]uint16, len(packets))
	for i, packet := range packets {
		if len(packet) < minVerifyPacket || len(packet) > tesla.MaxTagInput {
			return verifyRefused(verifyMalformed), nil
		}
		in, err := tesla.HashInput(packet)
		if err != nil {
			return verifyRefused(verifyMalformed), nil
		}
		inputs[i] = in
		tags[i], _ = tagspec.PacketID(packet)
	}

	ks := e.teslaSchedule
	if ks == nil || !hmac.Equal(req.GetChainAnchor(), ks.Anchor()) {
		return verifyRefused(verifyUnknownChain), nil
	}
	// On an untrusted clock the epoch a verifier derived from capture time may
	// not be the epoch whose key tagged the packets, so a yes would be an
	// unfounded attribution. These are the clock_unready and clock_drift
	// conditions of Attribution, read directly because chain_exhausted takes
	// precedence there while the last epochs are still undisclosed.
	if drift := ks.Drift(now); ks.Config().ClockUnready || drift > ks.MaxDrift() || -drift > ks.MaxDrift() {
		return verifyRefused(verifyAttributionUnavailable), nil
	}
	epoch := req.GetEpoch()
	if epoch < 1 || epoch >= ks.ChainLength() {
		return verifyRefused(verifyEpochUnavailable), nil
	}
	// A disclosable key lets anyone verify offline; answering would spend the
	// caller's budget for nothing.
	if disclosed, _, ok := ks.DisclosedKey(now); ok && disclosed >= epoch {
		return verifyRefused(verifyEpochUnavailable), nil
	}
	key, err := ks.KeyAtEpoch(epoch)
	if err != nil {
		return verifyRefused(verifyEpochUnavailable), nil
	}

	matches, matched := 0, ""
	for _, id := range candidates {
		ak, err := tesla.DeriveAK(key, []byte(id))
		if err != nil {
			return nil, status.Error(codes.Internal, "tag verification failed")
		}
		if reproducesTags(ak, inputs, tags) {
			matches, matched = matches+1, id
		}
	}
	switch matches {
	case 0:
		return &pb.VerifyTagsResponse{Verdict: verifyUnmatched}, nil
	case 1:
		return &pb.VerifyTagsResponse{Verdict: verifyMatched, RunId: matched}, nil
	default:
		return &pb.VerifyTagsResponse{Verdict: verifyAmbiguous}, nil
	}
}

// reproducesTags reports whether ak yields the carried tag of every packet.
func reproducesTags(ak []byte, inputs [][]byte, tags []uint16) bool {
	for i, in := range inputs {
		tag, err := tesla.ComputeTag(ak, in)
		if err != nil || tag != tags[i] {
			return false
		}
	}
	return true
}
