// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger"
	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	verifyRunA        = "6c1f9a52-0d3e-4b7a-9f21-3e5d8c7b1a01"
	verifyRunB        = "6c1f9a52-0d3e-4b7a-9f21-3e5d8c7b1a02"
	verifyEpochLength = 10 * time.Minute
	verifyChainLength = 8
)

// verifySchedule starts the fixture chain back before now: one and a half
// epochs back is epoch 1, whose key is not yet disclosable with d = 2. Every
// call uses the same seed, so every schedule has the same anchor and keys.
func verifySchedule(t *testing.T, back time.Duration, unready bool, clock tesla.Clock) *tesla.KeySchedule {
	t.Helper()
	ks, err := tesla.NewKeySchedule(tesla.Config{Seed: []byte("verify fixture"), ChainLength: verifyChainLength,
		EpochLength: verifyEpochLength, DisclosureDelay: 2, Epoch: time.Now().Add(-back), ClockUnready: unready, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

// verifyPacket is a 48-byte IPv4/UDP packet; payload varies its hashed bytes.
func verifyPacket(payload byte) []byte {
	p := make([]byte, 48)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8], p[9] = 64, 17
	copy(p[12:16], []byte{192, 0, 2, 1})
	copy(p[16:20], []byte{198, 51, 100, 7})
	binary.BigEndian.PutUint16(p[20:22], 40000)
	binary.BigEndian.PutUint16(p[22:24], 33434)
	binary.BigEndian.PutUint16(p[24:26], uint16(len(p)-20))
	for i := 28; i < len(p); i++ {
		p[i] = payload + byte(i)
	}
	return p
}

// taggedPackets returns the bytes the pure-Go tagger produced for run during
// the schedule's current epoch.
func taggedPackets(t *testing.T, ks *tesla.KeySchedule, run string, n int) [][]byte {
	t.Helper()
	tg := tagger.New(ks, []byte(run))
	key, _ := ks.KeyAtEpoch(1)
	out := make([][]byte, n)
	for i := range out {
		p, err := tg.TagPacket(verifyPacket(byte(i)))
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := tesla.VerifyTag(key, 1, []byte(run), p, tagger.ReadIPID(p)); err != nil || !ok {
			t.Fatalf("fixture packet %d is not tagged for epoch 1: %v", i, err)
		}
		out[i] = p
	}
	return out
}

func verifyRequest(ks *tesla.KeySchedule, epoch int64, candidates []string, packets [][]byte) *pb.VerifyTagsRequest {
	return &pb.VerifyTagsRequest{ControlBinding: operationWireBinding(), ChainAnchor: ks.Anchor(), Epoch: epoch,
		CandidateRunIds: candidates, Packets: packets}
}

// assertNoSecrets checks that a response is one verdict and never carries a
// chain key, a measurement key or a per-packet result.
func assertNoSecrets(t *testing.T, ks *tesla.KeySchedule, req *pb.VerifyTagsRequest, resp *pb.VerifyTagsResponse) {
	t.Helper()
	wire, err := proto.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	for epoch := int64(0); epoch <= verifyChainLength; epoch++ {
		key, _ := ks.KeyAtEpoch(epoch)
		secrets := [][]byte{key[:8]}
		for _, id := range req.GetCandidateRunIds() {
			if ak, err := tesla.DeriveAK(key, []byte(id)); err == nil {
				secrets = append(secrets, ak[:8])
			}
		}
		for _, secret := range secrets {
			if bytes.Contains(wire, secret) {
				t.Fatalf("response carries key material of epoch %d", epoch)
			}
		}
	}
	// Exactly the three declared fields: no unknown field smuggles a tag.
	if len(resp.ProtoReflect().GetUnknown()) != 0 || len(wire) > 2+len(resp.Verdict)+2+len(resp.RunId)+2+len(resp.Reason) {
		t.Fatalf("response carries more than a verdict: %d bytes", len(wire))
	}
	if resp.RunId != "" && !strings.Contains(strings.Join(req.GetCandidateRunIds(), " "), resp.RunId) {
		t.Fatalf("response names a run that was not a candidate: %s", resp.RunId)
	}
}

// collidingRun finds a canonical run ID other than run whose measurement key
// reproduces the tag of packet at epoch 1, which a 16-bit tag makes cheap.
func collidingRun(t *testing.T, ks *tesla.KeySchedule, run string, packet []byte) string {
	t.Helper()
	key, _ := ks.KeyAtEpoch(1)
	tag := tagger.ReadIPID(packet)
	for i := 0; i < 1<<22; i++ {
		id := uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprint(i))).String()
		if ok, err := tesla.VerifyTag(key, 1, []byte(id), packet, tag); err == nil && ok && id != run {
			return id
		}
	}
	t.Fatal("no colliding run ID found")
	return ""
}

func TestVerifyTagsVerdicts(t *testing.T) {
	e, _ := newExecutorRPCFixture(t, newOperationPeer(), nil)
	core, logs := observer.New(zapcore.DebugLevel)
	e.logger = zap.New(core)
	ks := verifySchedule(t, verifyEpochLength*3/2, false, nil)
	e.teslaSchedule = ks
	packets := taggedPackets(t, ks, verifyRunA, 4)
	altered := make([][]byte, len(packets))
	for i, p := range packets {
		altered[i] = bytes.Clone(p)
	}
	altered[2][40] ^= 0x01 // UDP payload, inside the hashed 48 bytes.
	colliding := collidingRun(t, ks, verifyRunA, packets[0])
	wrongAnchor := verifyRequest(ks, 1, []string{verifyRunA}, packets)
	wrongAnchor.ChainAnchor = bytes.Repeat([]byte{7}, 32)
	many := make([]string, maxVerifyCandidates+1)
	for i := range many {
		many[i] = uuid.NewSHA1(uuid.NameSpaceURL, []byte(fmt.Sprint(i))).String()
	}
	ipv6 := bytes.Clone(packets[0])
	ipv6[0] = 0x60
	fragment := bytes.Clone(packets[0])
	fragment[6] |= 0x20

	for _, tc := range []struct {
		name    string
		req     *pb.VerifyTagsRequest
		verdict string
		reason  string
		run     string
	}{
		{"matched", verifyRequest(ks, 1, []string{verifyRunB, verifyRunA}, packets), verifyMatched, "", verifyRunA},
		{"other_run", verifyRequest(ks, 1, []string{verifyRunB}, packets), verifyUnmatched, "", ""},
		{"altered_packet", verifyRequest(ks, 1, []string{verifyRunA, verifyRunB}, altered), verifyUnmatched, "", ""},
		{"wrong_epoch", verifyRequest(ks, 2, []string{verifyRunA}, packets), verifyUnmatched, "", ""},
		{"ambiguous", verifyRequest(ks, 1, []string{verifyRunA, colliding}, packets[:1]), verifyAmbiguous, "", ""},
		{"collision_needs_every_packet", verifyRequest(ks, 1, []string{verifyRunA, colliding}, packets), verifyMatched, "", verifyRunA},
		{"epoch_zero", verifyRequest(ks, 0, []string{verifyRunA}, packets), verifyUnsupported, verifyEpochUnavailable, ""},
		{"negative_epoch", verifyRequest(ks, -1, []string{verifyRunA}, packets), verifyUnsupported, verifyEpochUnavailable, ""},
		{"exhausted_epoch", verifyRequest(ks, verifyChainLength, []string{verifyRunA}, packets), verifyUnsupported, verifyEpochUnavailable, ""},
		{"wrong_anchor", wrongAnchor, verifyUnsupported, verifyUnknownChain, ""},
		{"too_many_candidates", verifyRequest(ks, 1, many, packets), verifyUnsupported, verifyTooMany, ""},
		{"too_many_packets", verifyRequest(ks, 1, []string{verifyRunA}, make([][]byte, maxVerifyPackets+1)), verifyUnsupported, verifyTooMany, ""},
		{"short_packet", verifyRequest(ks, 1, []string{verifyRunA}, [][]byte{packets[0][:19]}), verifyUnsupported, verifyMalformed, ""},
		{"long_packet", verifyRequest(ks, 1, []string{verifyRunA}, [][]byte{make([]byte, 65)}), verifyUnsupported, verifyMalformed, ""},
		{"truncated_below_total_length", verifyRequest(ks, 1, []string{verifyRunA}, [][]byte{packets[0][:40]}), verifyUnsupported, verifyMalformed, ""},
		{"ipv6", verifyRequest(ks, 1, []string{verifyRunA}, [][]byte{ipv6}), verifyUnsupported, verifyMalformed, ""},
		{"fragment", verifyRequest(ks, 1, []string{verifyRunA}, [][]byte{fragment}), verifyUnsupported, verifyMalformed, ""},
		{"no_packets", verifyRequest(ks, 1, []string{verifyRunA}, nil), verifyUnsupported, verifyMalformed, ""},
		{"no_candidates", verifyRequest(ks, 1, nil, packets), verifyUnsupported, verifyMalformed, ""},
		{"duplicate_candidates", verifyRequest(ks, 1, []string{verifyRunA, verifyRunA}, packets), verifyUnsupported, verifyMalformed, ""},
		{"uppercase_candidate", verifyRequest(ks, 1, []string{strings.ToUpper(verifyRunA)}, packets), verifyUnsupported, verifyMalformed, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), operationTestBound)
			defer cancel()
			logs.TakeAll()
			resp, err := e.OnVerifyTags(ctx, operationBinding(), tc.req)
			if err != nil {
				t.Fatal(err)
			}
			if resp.Verdict != tc.verdict || resp.Reason != tc.reason || resp.RunId != tc.run {
				t.Fatalf("got %+v, want verdict=%s reason=%s run=%s", resp, tc.verdict, tc.reason, tc.run)
			}
			assertNoSecrets(t, ks, tc.req, resp)
			info := logs.FilterLevelExact(zapcore.InfoLevel).All()
			if len(info) != 1 {
				t.Fatalf("%d Info lines, want one", len(info))
			}
			fields := info[0].ContextMap()
			if fields["verdict"] != tc.verdict || fields["candidates"] != int64(len(tc.req.CandidateRunIds)) || fields["packets"] != int64(len(tc.req.Packets)) {
				t.Fatalf("Info line fields %v", fields)
			}
			for _, field := range info[0].Context {
				for _, id := range tc.req.CandidateRunIds {
					if field.String != "" && strings.Contains(field.String, id) {
						t.Fatalf("Info line names a run: %v", fields)
					}
				}
			}
		})
	}
}

// Keys the executor would already disclose, and keys signed under an
// untrusted clock, are never the subject of an answer.
func TestVerifyTagsRefusesDisclosableEpochAndUntrustedClock(t *testing.T) {
	e, _ := newExecutorRPCFixture(t, newOperationPeer(), nil)
	packets := taggedPackets(t, verifySchedule(t, verifyEpochLength*3/2, false, nil), verifyRunA, 2)
	for _, tc := range []struct {
		name   string
		ks     *tesla.KeySchedule
		epoch  int64
		reason string
	}{
		// Epoch 4 of 8: k_2 is disclosable with d = 2, k_3 is not.
		{"disclosable", verifySchedule(t, verifyEpochLength*9/2, false, nil), 2, verifyEpochUnavailable},
		{"earlier_than_disclosed", verifySchedule(t, verifyEpochLength*9/2, false, nil), 1, verifyEpochUnavailable},
		{"not_yet_disclosed", verifySchedule(t, verifyEpochLength*9/2, false, nil), 3, ""},
		{"clock_drift", verifySchedule(t, verifyEpochLength*3/2, false, aheadClock(30*time.Second)), 1, verifyAttributionUnavailable},
		{"clock_unready", verifySchedule(t, verifyEpochLength*3/2, true, nil), 1, verifyAttributionUnavailable},
		// The last undisclosed epochs of an exhausted chain still need a trusted clock.
		{"exhausted_with_drift", verifySchedule(t, verifyEpochLength*17/2, false, aheadClock(30*time.Second)), verifyChainLength - 1, verifyAttributionUnavailable},
		{"exhausted_last_epoch", verifySchedule(t, verifyEpochLength*17/2, false, nil), verifyChainLength - 1, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e.teslaSchedule = tc.ks
			ctx, cancel := context.WithTimeout(context.Background(), operationTestBound)
			defer cancel()
			req := verifyRequest(tc.ks, tc.epoch, []string{verifyRunA}, packets)
			resp, err := e.OnVerifyTags(ctx, operationBinding(), req)
			if err != nil {
				t.Fatal(err)
			}
			if tc.reason == "" {
				if resp.Verdict != verifyUnmatched {
					t.Fatalf("answerable epoch: %+v", resp)
				}
			} else if resp.Verdict != verifyUnsupported || resp.Reason != tc.reason {
				t.Fatalf("got %+v, want unsupported %s", resp, tc.reason)
			}
			assertNoSecrets(t, tc.ks, req, resp)
		})
	}
}

// The request names the admitted session, as for retained-run inspection.
func TestVerifyTagsBinding(t *testing.T) {
	e, _ := newExecutorRPCFixture(t, newOperationPeer(), nil)
	ks := verifySchedule(t, verifyEpochLength*3/2, false, nil)
	e.teslaSchedule = ks
	packets := taggedPackets(t, ks, verifyRunA, 1)
	ctx, cancel := context.WithTimeout(context.Background(), operationTestBound)
	defer cancel()
	other := verifyRequest(ks, 1, []string{verifyRunA}, packets)
	other.ControlBinding = &pb.ControlBinding{DispatcherIncarnation: operationBinding().Incarnation, SessionId: "0f3b31ce-2d0b-4d5f-9df3-5a2d9b1c6a11"}
	missing := verifyRequest(ks, 1, []string{verifyRunA}, packets)
	missing.ControlBinding = nil
	for _, tc := range []struct {
		name string
		req  *pb.VerifyTagsRequest
		code codes.Code
	}{
		{"another_session", other, codes.PermissionDenied},
		{"missing_binding", missing, codes.InvalidArgument},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := e.OnVerifyTags(ctx, operationBinding(), tc.req)
			if status.Code(err) != tc.code || resp != nil {
				t.Fatalf("status=%v response=%+v, want %v", status.Code(err), resp, tc.code)
			}
		})
	}
	// A session other than the one the fixture holds is refused before any check.
	if _, err := e.OnVerifyTags(ctx, controlsession.Binding{Incarnation: other.ControlBinding.DispatcherIncarnation, SessionID: other.ControlBinding.SessionId}, other); err == nil {
		t.Fatal("verification answered without the held session")
	}
}
