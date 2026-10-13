// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"testing"
	"time"

	experimentwire "github.com/netsec-ethz/debuglet/pkg/wire/experiment"
)

func testOptions(algorithm string, role int) options {
	return options{Algorithm: algorithm, Role: role, Participants: 5,
		settings: settings{DeadlineMS: 5000, RetryMS: 250, RepairMS: 750, PayloadBytes: 512, UpdateID: "test-update", BlockedFrom: -1, BlockedTo: -1}}
}

// This deterministic message pump tests protocol decisions only. Real socket
// and WASM execution are covered separately by the installed-role acceptance.
func exercise(t *testing.T, algorithm string, blockedFrom, blockedTo int) ([]*delivery, []message) {
	t.Helper()
	nodes := make([]*delivery, 5)
	for role := range nodes {
		o := testOptions(algorithm, role)
		o.BlockedFrom, o.BlockedTo = blockedFrom, blockedTo
		nodes[role] = newDelivery(o, "experiment")
	}
	var sent []message
	for now := time.Duration(0); now < 5*time.Second; now += 10 * time.Millisecond {
		var queue []message
		for _, node := range nodes {
			queue = append(queue, node.tick(now)...)
		}
		for len(queue) != 0 {
			m := queue[0]
			queue = queue[1:]
			if nodes[m.From].blocked(m) {
				continue
			}
			sent = append(sent, m)
			if len(sent) > 10000 {
				t.Fatal("unbounded message exchange")
			}
			replies, err := nodes[m.To].receive(m, now)
			if err != nil {
				t.Fatal(err)
			}
			queue = append(queue, replies...)
		}
	}
	return nodes, sent
}

func TestDeliveryHealthyAndBrokenTree(t *testing.T) {
	for _, tc := range []struct {
		name, algorithm  string
		from, to         int
		complete, repair bool
	}{
		{"healthy direct", "direct", -1, -1, true, false},
		{"healthy relay", "relay", -1, -1, true, false},
		{"direct missing recipient", "direct", 0, 4, false, false},
		{"relay broken first hop", "relay", 0, 1, true, true},
		{"relay broken tree edge", "relay", 1, 3, true, true},
		{"direct unaffected by tree edge", "direct", 1, 3, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nodes, sent := exercise(t, tc.algorithm, tc.from, tc.to)
			if got := nodes[0].completion != nil; got != tc.complete {
				t.Fatalf("completion=%v, missing=%v", got, nodes[0].missing())
			}
			repairs := 0
			for _, m := range sent {
				if m.Kind == "repair" {
					repairs++
				}
			}
			if (repairs > 0) != tc.repair {
				t.Fatalf("repair messages=%d", repairs)
			}
			if tc.complete {
				for role, node := range nodes {
					if !node.verified {
						t.Fatalf("role %d has no verified update", role)
					}
				}
			} else if !reflect.DeepEqual(nodes[0].missing(), []int{4}) || nodes[4].verified {
				t.Fatal("missing recipient was reported incorrectly")
			}
		})
	}
}

func TestMissingACKIsNotMissingDelivery(t *testing.T) {
	for _, algorithm := range []string{"direct", "relay"} {
		nodes, _ := exercise(t, algorithm, 4, 0)
		if !nodes[4].verified || nodes[0].completion != nil || !reflect.DeepEqual(nodes[0].missing(), []int{4}) {
			t.Fatalf("%s: verified=%v, completion=%v, missing=%v", algorithm, nodes[4].verified, nodes[0].completion, nodes[0].missing())
		}
	}
}

func TestDirectFanoutDoesNotWaitForACK(t *testing.T) {
	d := newDelivery(testOptions("direct", 0), "experiment")
	first := d.tick(0)
	if len(first) != 4 {
		t.Fatalf("first wave has %d recipients", len(first))
	}
	if got := d.tick(249 * time.Millisecond); len(got) != 0 {
		t.Fatal("retry fired early")
	}
	if got := d.tick(250 * time.Millisecond); len(got) != 4 {
		t.Fatal("missing ACKs were not retried")
	}
	if got := d.tick(5 * time.Second); len(got) != 0 {
		t.Fatal("send after deadline")
	}
}

func TestVerificationDeduplicationAndFrozenCompletion(t *testing.T) {
	origin := newDelivery(testOptions("relay", 0), "experiment")
	receiver := newDelivery(testOptions("relay", 1), "experiment")
	m := origin.packet("data", 1, 1)
	corrupt := m
	corrupt.Payload = append([]byte(nil), m.Payload...)
	corrupt.Payload[0] ^= 1
	for _, invalid := range []message{corrupt, {Version: 1, Kind: "ack", From: 9, To: 1}, {Version: 1, Kind: "repair", From: 0, To: 1}} {
		if replies, err := receiver.receive(invalid, 0); err == nil || len(replies) != 0 || receiver.verified {
			t.Fatal("invalid message changed delivery state")
		}
	}
	if replies, err := receiver.receive(m, 10*time.Millisecond); err != nil || len(replies) != 1 || !receiver.verified {
		t.Fatalf("verify: %v %v", replies, err)
	}
	if replies, err := receiver.receive(m, 20*time.Millisecond); err != nil || len(replies) != 1 || receiver.duplicates != 1 {
		t.Fatal("duplicate should be acknowledged without reapplying update")
	}
	if len(receiver.pending) != 2 {
		t.Fatal("duplicate changed tree forwarding")
	}
	for role := 1; role < 5; role++ {
		ack := origin.packet("ack", 0, role)
		ack.From = role
		if _, err := origin.receive(ack, time.Duration(role)*time.Millisecond); err != nil {
			t.Fatal(err)
		}
	}
	if origin.completion == nil || *origin.completion != 4*time.Millisecond {
		t.Fatal("incorrect all-ACK duration")
	}
	ack := origin.packet("ack", 0, 4)
	ack.From = 4
	if _, err := origin.receive(ack, time.Second); err != nil {
		t.Fatal(err)
	}
	if *origin.completion != 4*time.Millisecond {
		t.Fatal("duplicate ACK changed completion time")
	}
}

func TestMessageFramingCountsDataACKAndRepair(t *testing.T) {
	d := newDelivery(testOptions("relay", 0), "experiment")
	for _, kind := range []string{"data", "ack", "repair"} {
		m := d.packet(kind, 1, 1)
		frame, err := frameMessage(m)
		if err != nil {
			t.Fatal(err)
		}
		decoded, count, err := readMessage(bytes.NewReader(frame))
		if err != nil || count != len(frame) || !reflect.DeepEqual(m, decoded) {
			t.Fatalf("%s: count=%d len=%d err=%v", kind, count, len(frame), err)
		}
		body, _ := json.Marshal(m)
		if len(frame) != 4+len(body) {
			t.Fatal("framing bytes excluded")
		}
		_, partial, err := readMessage(bytes.NewReader(frame[:len(frame)-1]))
		if err != io.ErrUnexpectedEOF || partial != len(frame)-1 {
			t.Fatalf("partial frame accounting: %d %v", partial, err)
		}
	}
	var oversized [4]byte
	binary.BigEndian.PutUint32(oversized[:], maxMessageBytes+1)
	if _, count, err := readMessage(bytes.NewReader(oversized[:])); err == nil || count != 4 {
		t.Fatal("oversized frame not rejected before reading body")
	}
}

func TestOptionsAndSummaryPreserveUncertainty(t *testing.T) {
	if _, err := parseOptions([]string{"-role=0"}); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{}, {"-role=0", "-participants=9"}, {"-role=0", "-payload-bytes=513"}, {"-role=0", "-blocked-from=1"}, {"-role=0", "-blocked-from=1", "-blocked-to=1"}, {"-role=0", "-retry-ms=10"}} {
		if _, err := parseOptions(args); err == nil {
			t.Fatalf("accepted invalid args %v", args)
		}
	}
	nodes, _ := exercise(t, "direct", 4, 0)
	var output bytes.Buffer
	r := reporter{options: nodes[0].options, writer: &output, experimentID: "experiment", runID: "origin", hash: nodes[0].hash, sentBytes: 123, receivedBytes: 45}
	if err := r.summary(nodes[0], nil); err != nil {
		t.Fatal(err)
	}
	var summary map[string]any
	if err := json.Unmarshal(output.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary["outcome"] != "deadline" || summary["completion_ms"] != nil || summary["sent_bytes"] != float64(123) || summary["received_bytes"] != float64(45) {
		t.Fatalf("summary lost uncertainty/accounting: %s", output.String())
	}
	if !reflect.DeepEqual(summary["missing_ack_roles"], []any{float64(4)}) {
		t.Fatal("summary omitted missing ACK")
	}
}

func TestReadinessRequiresDistinctMatchingParticipants(t *testing.T) {
	o := testOptions("relay", 0)
	group := make([]experimentwire.ExperimentParticipant, 5)
	for role := range group {
		metadata, err := json.Marshal(memberMetadata{Role: role, Endpoint: fmt.Sprintf("127.0.0.1:%d", 20000+role), Algorithm: o.Algorithm, Participants: o.Participants, Config: o.settings})
		if err != nil {
			t.Fatal(err)
		}
		group[role] = experimentwire.ExperimentParticipant{ID: fmt.Sprintf("run-%d", role), ExecutorID: fmt.Sprintf("executor-%d", role), Metadata: metadata}
	}
	endpoints, ownID, err := members(o, "127.0.0.1:20000", group)
	if err != nil || len(endpoints) != 5 || ownID != "run-0" {
		t.Fatalf("valid group: %v %q %v", endpoints, ownID, err)
	}
	for _, kind := range []string{"missing participant", "duplicate executor", "duplicate role", "different fault", "wrong own listener"} {
		t.Run(kind, func(t *testing.T) {
			changed := append([]experimentwire.ExperimentParticipant(nil), group...)
			address := "127.0.0.1:20000"
			switch kind {
			case "missing participant":
				changed = changed[:4]
			case "duplicate executor":
				changed[1].ExecutorID = changed[0].ExecutorID
			case "wrong own listener":
				address = "127.0.0.1:20001"
			default:
				var metadata memberMetadata
				if err := json.Unmarshal(changed[1].Metadata, &metadata); err != nil {
					t.Fatal(err)
				}
				if kind == "duplicate role" {
					metadata.Role = 0
				} else {
					metadata.Config.BlockedFrom, metadata.Config.BlockedTo = 0, 1
				}
				changed[1].Metadata, err = json.Marshal(metadata)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := members(o, address, changed); err == nil {
				t.Fatal("accepted inconsistent readiness membership")
			}
		})
	}
}
