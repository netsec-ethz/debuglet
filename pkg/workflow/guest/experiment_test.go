// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	experimentwire "github.com/netsec-ethz/debuglet/pkg/wire/experiment"
)

func experimentFixture(t *testing.T, self string) *Experiment {
	t.Helper()
	config := experimentConfig{
		Participant: self, Fingerprint: strings.Repeat("a", 64),
		Participants: []string{"a", "b", "c"},
		Channels: []experimentChannel{
			{ID: "request", From: "a", To: "b", Type: "object", ResponseType: "number"},
			{ID: "notice", From: "a", To: "c", Type: "string"},
			{ID: "other", From: "c", To: "b", Type: "boolean"},
		},
	}
	session, err := newExperiment(config)
	if err != nil {
		t.Fatal(err)
	}
	group := experimentGroup(t, session)
	address := "127.0.0.1:2001"
	for i, participant := range []string{"a", "b", "c"} {
		if participant == self {
			address = groupAddress(i)
		}
	}
	if err := session.admit(group, address); err != nil {
		t.Fatal(err)
	}
	return session
}

func groupAddress(index int) string {
	return net.JoinHostPort("127.0.0.1", []string{"2001", "2002", "2003"}[index])
}

func experimentGroup(t *testing.T, session *Experiment) experimentwire.Experiment {
	t.Helper()
	group := experimentwire.Experiment{ID: "group"}
	for i, participant := range []string{"a", "b", "c"} {
		metadata, err := json.Marshal(experimentEndpoint{participant, session.fingerprint, groupAddress(i)})
		if err != nil {
			t.Fatal(err)
		}
		group.Participants = append(group.Participants, experimentwire.ExperimentParticipant{
			ID: "run-" + participant, ExecutorID: "executor-" + participant, Metadata: metadata,
		})
	}
	return group
}

func experimentIncoming(e *Experiment, from, channel, requestID string, sequence uint64, value any) experimentFrame {
	return experimentFrame{
		ExperimentID: e.id, Fingerprint: e.fingerprint,
		From: from, FromRunID: e.peers[from].runID,
		To: e.participant, ToRunID: e.peers[e.participant].runID,
		Channel: channel, RequestID: requestID, Sequence: sequence, Value: value,
	}
}

func queueExperiment(t *testing.T, e *Experiment, frame experimentFrame) {
	t.Helper()
	data, err := experimentEncode(frame)
	if err != nil {
		t.Fatal(err)
	}
	decoded, size, err := experimentRead(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.enqueue(decoded, size); err != nil {
		t.Fatal(err)
	}
}

func TestExperimentMembershipRequiresExactAdmittedProgram(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*experimentwire.Experiment)
	}{
		{"missing", func(g *experimentwire.Experiment) { g.Participants = g.Participants[:2] }},
		{"duplicate run", func(g *experimentwire.Experiment) { g.Participants[1].ID = g.Participants[0].ID }},
		{"empty executor", func(g *experimentwire.Experiment) { g.Participants[1].ExecutorID = "" }},
		{"duplicate participant", func(g *experimentwire.Experiment) { g.Participants[1].Metadata = g.Participants[0].Metadata }},
		{"wrong fingerprint", func(g *experimentwire.Experiment) {
			g.Participants[1].Metadata = bytes.ReplaceAll(g.Participants[1].Metadata, []byte(strings.Repeat("a", 64)), []byte(strings.Repeat("b", 64)))
		}},
		{"invalid endpoint", func(g *experimentwire.Experiment) {
			g.Participants[1].Metadata = bytes.ReplaceAll(g.Participants[1].Metadata, []byte("127.0.0.1:2002"), []byte("127.0.0.1:0"))
		}},
		{"wrong self address", func(g *experimentwire.Experiment) {
			g.Participants[0].Metadata = bytes.ReplaceAll(g.Participants[0].Metadata, []byte("127.0.0.1:2001"), []byte("127.0.0.1:4000"))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := experimentFixture(t, "a")
			group := experimentGroup(t, e)
			test.edit(&group)
			if err := e.admit(group, "127.0.0.1:2001"); err == nil {
				t.Fatal("accepted mismatched membership")
			}
		})
	}
}

func TestExperimentRequestResponseOwnership(t *testing.T) {
	requestID := strings.Repeat("1", 32)
	receiver := experimentFixture(t, "b")
	request := experimentIncoming(receiver, "a", "request", requestID, 1, map[string]any{"url": "https://example.test"})
	queueExperiment(t, receiver, request)
	responseInputs := map[string]any{"destination": "a", "channel": "request", "request_id": requestID}
	if _, _, _, _, err := receiver.operation(responseInputs, true); err == nil {
		t.Fatal("reply allowed before the request was consumed")
	}
	out, err := receiver.Await(map[string]any{"source": "a", "channel": "request"})
	if err != nil || out["ok"] != true || out["request_id"] != requestID || out["source"] != "a" {
		t.Fatalf("request result %#v, %v", out, err)
	}
	if _, _, _, reverse, err := receiver.operation(responseInputs, true); err != nil || !reverse {
		t.Fatalf("reply to consumed request: reverse=%v, err=%v", reverse, err)
	}
	responseInputs["request_id"] = strings.Repeat("2", 32)
	if _, _, _, _, err := receiver.operation(responseInputs, true); err == nil {
		t.Fatal("reply accepted an unrelated request ID")
	}

	sender := experimentFixture(t, "a")
	sender.pending[requestID] = experimentRequest{channel: "request", peer: "b"}
	response := experimentIncoming(sender, "b", "request", requestID, 1, float64(200))
	queueExperiment(t, sender, response)
	response.Sequence++
	if err := sender.enqueue(response, 400); err == nil {
		t.Fatal("queued a duplicate response under a new sequence")
	}
	out, err = sender.Await(map[string]any{"source": "b", "channel": "request", "request_id": requestID})
	if err != nil || out["ok"] != true || out["value"] != float64(200) || len(sender.pending) != 0 {
		t.Fatalf("response result %#v, %v, pending=%#v", out, err, sender.pending)
	}
	if _, err := sender.Await(map[string]any{"source": "b", "channel": "request", "request_id": requestID}); err == nil {
		t.Fatal("consumed response could be awaited again")
	}
	if err := sender.enqueue(response, 400); err == nil {
		t.Fatal("accepted a late response to a consumed request")
	}
}

func TestExperimentAwaitRetainsOtherChannels(t *testing.T) {
	e := experimentFixture(t, "b")
	queueExperiment(t, e, experimentIncoming(e, "c", "other", "", 1, true))
	id := strings.Repeat("1", 32)
	queueExperiment(t, e, experimentIncoming(e, "a", "request", id, 1, map[string]any{"value": float64(1)}))
	out, err := e.Await(map[string]any{"source": "a", "channel": "request"})
	if err != nil || out["ok"] != true || len(e.inbox) != 1 || e.inboxBytes == 0 {
		t.Fatalf("matching request did not preserve unrelated message: %#v %v", out, err)
	}
	out, err = e.Await(map[string]any{"source": "c", "channel": "other"})
	if err != nil || out["value"] != true || len(e.inbox) != 0 || e.inboxBytes != 0 {
		t.Fatalf("buffered message lost: %#v %v", out, err)
	}
}

func TestExperimentRejectsMisdirectedAndUntypedFrames(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*experimentFrame)
	}{
		{"experiment", func(f *experimentFrame) { f.ExperimentID = "other" }},
		{"fingerprint", func(f *experimentFrame) { f.Fingerprint = strings.Repeat("b", 64) }},
		{"sender run", func(f *experimentFrame) { f.FromRunID = "other" }},
		{"recipient run", func(f *experimentFrame) { f.ToRunID = "other" }},
		{"recipient", func(f *experimentFrame) { f.To = "a" }},
		{"type", func(f *experimentFrame) { f.Value = "true" }},
		{"request ID on one-way", func(f *experimentFrame) { f.RequestID = strings.Repeat("1", 32) }},
		{"sequence zero", func(f *experimentFrame) { f.Sequence = 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := experimentFixture(t, "b")
			frame := experimentIncoming(e, "c", "other", "", 1, true)
			test.edit(&frame)
			if err := e.enqueue(frame, 400); err == nil {
				t.Fatal("accepted invalid frame")
			}
			if len(e.inbox) != 0 || len(e.received) != 0 {
				t.Fatal("invalid frame changed the inbox or replay window")
			}
		})
	}
}

func TestExperimentInboxAndSequenceBounds(t *testing.T) {
	e := experimentFixture(t, "b")
	frame := experimentIncoming(e, "c", "other", "", 1, true)
	for i := 0; i < experimentInboxLimit/experimentFrameLimit; i++ {
		frame.Sequence = uint64(i + 1)
		if err := e.enqueue(frame, experimentFrameLimit); err != nil {
			t.Fatal(err)
		}
	}
	frame.Sequence++
	if err := e.enqueue(frame, 1); err == nil {
		t.Fatal("accepted message above inbox byte limit")
	}
	if e.inboxBytes != experimentInboxLimit {
		t.Fatal("overflow changed inbox accounting")
	}
	var sequence experimentSequence
	for _, n := range []uint64{2, 1, 65, 64} {
		var err error
		sequence, err = sequence.accept(n)
		if err != nil {
			t.Fatalf("sequence %d: %v", n, err)
		}
	}
	for _, n := range []uint64{0, 1, 2, 64, 65} {
		if _, err := sequence.accept(n); err == nil {
			t.Fatalf("accepted stale or duplicate sequence %d", n)
		}
	}
}

func TestExperimentFrameRoundTripAndBounds(t *testing.T) {
	e := experimentFixture(t, "b")
	frame := experimentIncoming(e, "c", "other", "", 1, true)
	packet, err := experimentEncode(frame)
	if err != nil {
		t.Fatal(err)
	}
	got, size, err := experimentRead(bytes.NewReader(packet))
	if err != nil || size != len(packet)-4 || !reflect.DeepEqual(got, frame) {
		t.Fatalf("round trip: %#v %d %v", got, size, err)
	}
	for _, test := range [][]byte{packet[:3], packet[:len(packet)-1], {0, 0, 0, 0}, {0, 0, 32, 1}} {
		if _, _, err := experimentRead(bytes.NewReader(test)); err == nil {
			t.Fatalf("accepted incomplete or oversized frame %v", test[:min(len(test), 4)])
		}
	}
	frame.Value = strings.Repeat("x", experimentFrameLimit)
	if _, err := experimentEncode(frame); err == nil {
		t.Fatal("encoded oversized message")
	}
	var decoded experimentEndpoint
	for _, text := range []string{`{"address":"x","unexpected":true}`, `{} {}`} {
		if err := experimentDecode([]byte(text), &decoded); err == nil {
			t.Fatalf("accepted invalid metadata %s", text)
		}
	}
}

func TestExperimentFramingOverTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	e := experimentFixture(t, "b")
	frame := experimentIncoming(e, "c", "other", "", 1, true)
	packet, err := experimentEncode(frame)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			done <- err
			return
		}
		got, size, err := experimentRead(conn)
		if err == nil {
			err = e.enqueue(got, size)
		}
		done <- err
	}()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// Split the length header as well as the payload across writes.
	for _, part := range [][]byte{packet[:2], packet[2:5], packet[5:]} {
		if err := experimentWrite(conn, part); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	out, err := e.Await(map[string]any{"source": "c", "channel": "other"})
	if err != nil || out["ok"] != true || out["value"] != true {
		t.Fatalf("TCP result %#v, %v", out, err)
	}
}

func TestExperimentFramingReadDeadline(t *testing.T) {
	reader, writer := net.Pipe()
	defer reader.Close()
	defer writer.Close()
	if err := reader.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	wrote := make(chan error, 1)
	go func() {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], 10)
		_, err := writer.Write(header[:])
		wrote <- err
	}()
	if _, _, err := experimentRead(reader); err == nil {
		t.Fatal("partial peer frame did not hit its read deadline")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("expected timeout, got %v", err)
	}
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
}

type noProgressWriter struct{}

func (noProgressWriter) Write([]byte) (int, error) { return 0, nil }

func TestExperimentWriteRejectsNoProgress(t *testing.T) {
	if err := experimentWrite(noProgressWriter{}, []byte("message")); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("write result: %v", err)
	}
}
