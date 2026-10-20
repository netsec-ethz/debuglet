// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
	experimentwire "github.com/netsec-ethz/debuglet/pkg/wire/experiment"
)

const (
	experimentFrameLimit   = 8 * 1024
	experimentInboxLimit   = 64 * 1024
	experimentPendingLimit = 128
)

type experimentConfig struct {
	Participant  string              `json:"participant"`
	Fingerprint  string              `json:"fingerprint"`
	Participants []string            `json:"participants"`
	Channels     []experimentChannel `json:"channels"`
}

type experimentChannel struct {
	ID           string `json:"id"`
	From         string `json:"from"`
	To           string `json:"to"`
	Type         string `json:"type"`
	ResponseType string `json:"response_type,omitempty"`
}

type experimentEndpoint struct {
	Participant string `json:"participant"`
	Fingerprint string `json:"fingerprint"`
	Address     string `json:"address"`
}

type experimentPeer struct {
	runID, executorID, address string
}

type experimentFrame struct {
	ExperimentID string `json:"experiment_id"`
	Fingerprint  string `json:"fingerprint"`
	From         string `json:"from"`
	FromRunID    string `json:"from_run_id"`
	To           string `json:"to"`
	ToRunID      string `json:"to_run_id"`
	Channel      string `json:"channel"`
	RequestID    string `json:"request_id"`
	Sequence     uint64 `json:"sequence"`
	Value        any    `json:"value"`
}

type experimentMessage struct {
	frame experimentFrame
	size  int
}

type experimentRequest struct {
	channel, peer string
	ready         bool
}

type experimentSequence struct {
	highest, seen uint64
}

// Experiment exchanges bounded plaintext messages directly between admitted
// participants. Readiness metadata identifies expected peers but does not
// authenticate their sockets: use this transport for controlled experiments,
// not confidential data. Calls are sequential; there is no background receiver.
type Experiment struct {
	id, participant, fingerprint string
	peers                        map[string]experimentPeer
	channels                     map[string]experimentChannel
	sequence                     uint64
	received                     map[string]experimentSequence
	pending, requests            map[string]experimentRequest
	inbox                        []experimentMessage
	inboxBytes                   int
}

// JoinExperiment publishes this run's listener, checks the admitted membership,
// and waits for the group's common start before any workflow action executes.
func JoinExperiment(configJSON string) (*Experiment, error) {
	var config experimentConfig
	if err := experimentDecode([]byte(configJSON), &config); err != nil {
		return nil, fmt.Errorf("experiment configuration: %w", err)
	}
	session, err := newExperiment(config)
	if err != nil {
		return nil, err
	}
	address, err := debuglet.ListenAddr()
	if err != nil {
		return nil, fmt.Errorf("experiment requires a reachable TCP listener: %w", err)
	}
	metadata, err := json.Marshal(experimentEndpoint{config.Participant, config.Fingerprint, address})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	group, err := debuglet.Ready(ctx, metadata)
	if err != nil {
		return nil, fmt.Errorf("experiment readiness: %w", err)
	}
	if err := session.admit(group, address); err != nil {
		return nil, err
	}
	if err := debuglet.WaitStart(ctx, group); err != nil {
		return nil, fmt.Errorf("experiment start: %w", err)
	}
	return session, nil
}

func newExperiment(config experimentConfig) (*Experiment, error) {
	if len(config.Participants) < 2 || len(config.Participants) > 128 || len(config.Channels) > 128 {
		return nil, fmt.Errorf("experiment requires 2–128 participants and at most 128 channels")
	}
	digest, err := hex.DecodeString(config.Fingerprint)
	if err != nil || len(digest) != 32 {
		return nil, fmt.Errorf("experiment fingerprint must be a SHA-256 digest")
	}
	session := &Experiment{
		participant: config.Participant, fingerprint: config.Fingerprint,
		peers: map[string]experimentPeer{}, channels: map[string]experimentChannel{},
		received: map[string]experimentSequence{}, pending: map[string]experimentRequest{},
		requests: map[string]experimentRequest{},
	}
	for _, participant := range config.Participants {
		if participant == "" || len(participant) > 128 {
			return nil, fmt.Errorf("invalid experiment participant")
		}
		if _, exists := session.peers[participant]; exists {
			return nil, fmt.Errorf("duplicate experiment participant %q", participant)
		}
		session.peers[participant] = experimentPeer{}
	}
	if _, exists := session.peers[config.Participant]; !exists {
		return nil, fmt.Errorf("current participant is absent from experiment")
	}
	for _, channel := range config.Channels {
		_, from := session.peers[channel.From]
		_, to := session.peers[channel.To]
		_, duplicate := session.channels[channel.ID]
		if channel.ID == "" || len(channel.ID) > 128 || duplicate || !from || !to ||
			channel.From == channel.To || !experimentType(channel.Type) ||
			(channel.ResponseType != "" && !experimentType(channel.ResponseType)) {
			return nil, fmt.Errorf("invalid experiment channel %q", channel.ID)
		}
		session.channels[channel.ID] = channel
	}
	return session, nil
}

func (e *Experiment) admit(group experimentwire.Experiment, address string) error {
	if group.ID == "" || len(group.Participants) != len(e.peers) {
		return fmt.Errorf("admitted experiment membership does not match the program")
	}
	members, runs, addresses := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, member := range group.Participants {
		var endpoint experimentEndpoint
		if err := experimentDecode(member.Metadata, &endpoint); err != nil {
			return fmt.Errorf("invalid experiment participant metadata: %w", err)
		}
		_, known := e.peers[endpoint.Participant]
		host, port, err := net.SplitHostPort(endpoint.Address)
		if !known || members[endpoint.Participant] || runs[member.ID] || member.ID == "" ||
			member.ExecutorID == "" || addresses[endpoint.Address] ||
			endpoint.Fingerprint != e.fingerprint || err != nil || !networkHost(host) || !networkPort(port) {
			return fmt.Errorf("admitted experiment participant does not match the program")
		}
		if endpoint.Participant == e.participant && endpoint.Address != address {
			return fmt.Errorf("admitted listener does not match this participant")
		}
		members[endpoint.Participant], runs[member.ID], addresses[endpoint.Address] = true, true, true
		e.peers[endpoint.Participant] = experimentPeer{member.ID, member.ExecutorID, endpoint.Address}
	}
	e.id = group.ID
	return nil
}

// Send writes one message with no retry. Success means the frame was written,
// not that the recipient's workflow has consumed it or produced a response.
func (e *Experiment) Send(inputs map[string]any) (map[string]any, error) {
	channel, peer, requestID, response, err := e.operation(inputs, true)
	if err != nil {
		return nil, err
	}
	value, exists := inputs["value"]
	if !exists {
		return nil, fmt.Errorf("missing value")
	}
	kind := channel.Type
	if response {
		kind = channel.ResponseType
	}
	if err := Check(map[string]any{"value": value}, map[string]string{"value": kind}); err != nil {
		return nil, err
	}
	timeout, err := networkTimeout(inputs)
	if err != nil {
		return nil, err
	}
	if !response && channel.ResponseType != "" {
		if len(e.pending) >= experimentPendingLimit {
			return nil, fmt.Errorf("experiment exceeds 128 outstanding requests")
		}
		id := make([]byte, 16)
		if _, err := rand.Read(id); err != nil {
			return nil, fmt.Errorf("generate request ID: %w", err)
		}
		requestID = hex.EncodeToString(id)
	}
	e.sequence++
	frame := experimentFrame{
		ExperimentID: e.id, Fingerprint: e.fingerprint, From: e.participant,
		FromRunID: e.peers[e.participant].runID, To: peer, ToRunID: e.peers[peer].runID,
		Channel: channel.ID, RequestID: requestID, Sequence: e.sequence, Value: value,
	}
	data, err := experimentEncode(frame)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"ok": false, "error": "", "request_id": requestID}
	deadline := time.Now().Add(timeout)
	conn, err := debuglet.DialTimeout("tcp", e.peers[peer].address, timeout)
	if err == nil {
		defer conn.Close()
		err = conn.SetWriteDeadline(deadline)
		if err == nil {
			err = experimentWrite(conn, data)
		}
	}
	if err != nil {
		out["error"] = err.Error()
		return out, nil
	}
	if response {
		delete(e.requests, requestID)
	} else if channel.ResponseType != "" {
		e.pending[requestID] = experimentRequest{channel: channel.ID, peer: peer}
	}
	out["ok"] = true
	return out, nil
}

// Await consumes a matching message or waits until its deadline. Valid messages
// for other channels are buffered within the inbox limit, never discarded.
func (e *Experiment) Await(inputs map[string]any) (map[string]any, error) {
	channel, peer, requestID, response, err := e.operation(inputs, false)
	if err != nil {
		return nil, err
	}
	timeout, err := networkTimeout(inputs)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"ok": false, "error": "", "value": nil, "request_id": "", "source": ""}
	deadline := time.Now().Add(timeout)
	for {
		for i, message := range e.inbox {
			frame := message.frame
			if frame.Channel != channel.ID || frame.From != peer || (response && frame.RequestID != requestID) {
				continue
			}
			e.inbox = append(e.inbox[:i], e.inbox[i+1:]...)
			e.inboxBytes -= message.size
			if response {
				delete(e.pending, requestID)
			} else if channel.ResponseType != "" {
				request := e.requests[frame.RequestID]
				request.ready = true
				e.requests[frame.RequestID] = request
			}
			out["ok"], out["value"], out["request_id"], out["source"] = true, frame.Value, frame.RequestID, frame.From
			return out, nil
		}
		if time.Until(deadline) <= 0 {
			out["error"] = "experiment await timed out"
			return out, nil
		}
		conn, err := debuglet.AcceptTCPTimeout(time.Until(deadline))
		if err == nil {
			err = conn.SetReadDeadline(deadline)
			if err == nil {
				var frame experimentFrame
				var size int
				frame, size, err = experimentRead(conn)
				if err == nil {
					err = e.enqueue(frame, size)
				}
			}
			conn.Close()
		}
		if err != nil {
			out["error"] = err.Error()
			return out, nil
		}
	}
}

func (e *Experiment) operation(inputs map[string]any, send bool) (experimentChannel, string, string, bool, error) {
	var empty experimentChannel
	channelID, err := networkString(inputs, "channel", "")
	if err != nil {
		return empty, "", "", false, err
	}
	channel, exists := e.channels[channelID]
	if !exists || e.id == "" {
		return empty, "", "", false, fmt.Errorf("experiment channel is unavailable")
	}
	selector := "source"
	if send {
		selector = "destination"
	}
	peer, err := networkString(inputs, selector, "")
	if err != nil {
		return empty, "", "", false, err
	}
	from, to := peer, e.participant
	if send {
		from, to = e.participant, peer
	}
	response := from == channel.To && to == channel.From && channel.ResponseType != ""
	if !response && (from != channel.From || to != channel.To) {
		return empty, "", "", false, fmt.Errorf("participant is not an endpoint of this channel direction")
	}
	requestID, err := experimentRequestID(inputs)
	if err != nil {
		return empty, "", "", false, err
	}
	if !response && requestID != "" {
		return empty, "", "", false, fmt.Errorf("forward channel operations must not supply a request_id")
	}
	if response {
		requests := e.pending
		if send {
			requests = e.requests
		}
		request, exists := requests[requestID]
		if requestID == "" || !exists || request.channel != channel.ID || request.peer != peer || (send && !request.ready) {
			return empty, "", "", false, fmt.Errorf("response requires an unconsumed request_id from this channel and peer")
		}
	}
	return channel, peer, requestID, response, nil
}

func (e *Experiment) enqueue(frame experimentFrame, size int) error {
	channel, known := e.channels[frame.Channel]
	peer, member := e.peers[frame.From]
	if !known || !member || frame.From == e.participant || frame.ExperimentID != e.id ||
		frame.Fingerprint != e.fingerprint || frame.FromRunID != peer.runID ||
		frame.To != e.participant || frame.ToRunID != e.peers[e.participant].runID {
		return fmt.Errorf("message does not belong to this experiment participant")
	}
	response := frame.From == channel.To && frame.To == channel.From && channel.ResponseType != ""
	if !response && (frame.From != channel.From || frame.To != channel.To) {
		return fmt.Errorf("message does not match the channel direction")
	}
	kind := channel.Type
	if response {
		kind = channel.ResponseType
	}
	if err := Check(map[string]any{"value": frame.Value}, map[string]string{"value": kind}); err != nil {
		return err
	}
	if size < 1 || size > experimentFrameLimit || e.inboxBytes+size > experimentInboxLimit || len(e.inbox) >= 128 {
		return fmt.Errorf("experiment inbox exceeds 64 KiB or 128 messages")
	}
	sequence, err := e.received[frame.From].accept(frame.Sequence)
	if err != nil {
		return err
	}
	if channel.ResponseType == "" {
		if frame.RequestID != "" {
			return fmt.Errorf("one-way channel message has a request ID")
		}
	} else {
		id, err := hex.DecodeString(frame.RequestID)
		if err != nil || len(id) != 16 {
			return fmt.Errorf("invalid experiment request ID")
		}
		if response {
			request, exists := e.pending[frame.RequestID]
			if !exists || request.channel != channel.ID || request.peer != frame.From || request.ready {
				return fmt.Errorf("unexpected or duplicate experiment response")
			}
			request.ready = true
			e.pending[frame.RequestID] = request
		} else {
			if _, exists := e.requests[frame.RequestID]; exists || len(e.requests) >= experimentPendingLimit {
				return fmt.Errorf("duplicate request or more than 128 pending incoming requests")
			}
			e.requests[frame.RequestID] = experimentRequest{channel: channel.ID, peer: frame.From}
		}
	}
	e.received[frame.From] = sequence
	e.inbox = append(e.inbox, experimentMessage{frame: frame, size: size})
	e.inboxBytes += size
	return nil
}

// A fixed window admits limited connection reordering without an unbounded
// replay table. Frames older than the latest 64 sequence numbers are rejected.
func (s experimentSequence) accept(sequence uint64) (experimentSequence, error) {
	if sequence == 0 {
		return s, fmt.Errorf("invalid experiment message sequence")
	}
	if sequence > s.highest {
		delta := sequence - s.highest
		s.seen = s.seen<<delta | 1
		s.highest = sequence
		return s, nil
	}
	delta := s.highest - sequence
	if delta >= 64 || s.seen&(uint64(1)<<delta) != 0 {
		return s, fmt.Errorf("duplicate or stale experiment message")
	}
	s.seen |= uint64(1) << delta
	return s, nil
}

func experimentRequestID(inputs map[string]any) (string, error) {
	value, exists := inputs["request_id"]
	if !exists {
		return "", nil
	}
	id, ok := value.(string)
	if !ok || len(id) > 32 {
		return "", fmt.Errorf("request_id must be a string of at most 32 characters")
	}
	return id, nil
}

func experimentType(kind string) bool {
	switch kind {
	case "any", "string", "number", "boolean", "object", "numbers", "strings":
		return true
	default:
		return false
	}
}

func experimentEncode(frame experimentFrame) ([]byte, error) {
	data, err := json.Marshal(frame)
	if err != nil {
		return nil, err
	}
	if len(data) > experimentFrameLimit {
		return nil, fmt.Errorf("experiment message exceeds the 8 KiB frame limit")
	}
	packet := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(packet, uint32(len(data)))
	copy(packet[4:], data)
	return packet, nil
}

func experimentWrite(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if n < 0 || n > len(data) {
			return fmt.Errorf("invalid message write count")
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func experimentRead(reader io.Reader) (experimentFrame, int, error) {
	var frame experimentFrame
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return frame, 0, err
	}
	size := int(binary.BigEndian.Uint32(header[:]))
	if size < 1 || size > experimentFrameLimit {
		return frame, 0, fmt.Errorf("experiment message exceeds the 8 KiB frame limit")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(reader, data); err != nil {
		return frame, 0, err
	}
	err := experimentDecode(data, &frame)
	return frame, size, err
}

func experimentDecode(data []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("expected one JSON value")
	}
	return nil
}
