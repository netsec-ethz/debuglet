// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// delivery compares direct fan-out with peer-assisted delivery of one update.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
	experimentwire "github.com/netsec-ethz/debuglet/pkg/wire/experiment"
)

const maxMessageBytes = 2048

type memberMetadata struct {
	Role         int      `json:"role"`
	Endpoint     string   `json:"endpoint"`
	Algorithm    string   `json:"algorithm"`
	Participants int      `json:"participants"`
	Config       settings `json:"config"`
}

type reporter struct {
	options
	writer                                                  io.Writer
	experimentID, runID, hash                               string
	started                                                 time.Time
	sentBytes, receivedBytes, sendErrors, simulatedFailures int
}

func (r *reporter) emit(fields map[string]any) error {
	fields["schema"], fields["algorithm"], fields["role"], fields["participants"] = schema, r.Algorithm, r.Role, r.Participants
	fields["experiment_id"], fields["run_id"], fields["update_sha256"] = r.experimentID, r.runID, r.hash
	return json.NewEncoder(r.writer).Encode(fields)
}

func (r *reporter) elapsed() time.Duration {
	if r.started.IsZero() {
		return 0
	}
	return time.Since(r.started)
}

func milliseconds(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func (r *reporter) event(event string, fields map[string]any) error {
	if fields == nil {
		fields = map[string]any{}
	}
	fields["type"], fields["event"], fields["elapsed_ms"] = "event", event, milliseconds(r.elapsed())
	return r.emit(fields)
}

func (r *reporter) summary(d *delivery, failure error) error {
	fields := map[string]any{"type": "summary", "config": r.settings,
		"outcome": "error", "verified": false, "completion_ms": nil,
		"finished_ms": milliseconds(r.elapsed()), "sent_bytes": r.sentBytes,
		"received_bytes": r.receivedBytes, "send_errors": r.sendErrors,
		"simulated_failures": r.simulatedFailures, "duplicates": 0}
	if d != nil {
		fields["verified"], fields["duplicates"] = d.verified, d.duplicates
		fields["outcome"] = "deadline"
		if (d.Role != 0 && d.verified) || d.completion != nil {
			fields["outcome"] = "complete"
		}
		if d.completion != nil {
			fields["completion_ms"] = milliseconds(*d.completion)
		}
		if d.Role == 0 {
			acked := []int{}
			for role := 1; role < d.Participants; role++ {
				if d.acked[role] {
					acked = append(acked, role)
				}
			}
			fields["acked_roles"], fields["missing_ack_roles"] = acked, d.missing()
		}
	}
	if failure != nil {
		fields["outcome"], fields["error"] = "error", failure.Error()
	}
	return r.emit(fields)
}

func parseOptions(args []string) (options, error) {
	var o options
	f := flag.NewFlagSet("delivery", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&o.Algorithm, "algorithm", "direct", "direct or relay")
	f.IntVar(&o.Role, "role", -1, "participant role; origin is zero")
	f.IntVar(&o.Participants, "participants", 5, "group size")
	f.IntVar(&o.DeadlineMS, "deadline-ms", 5000, "local delivery window")
	f.IntVar(&o.RetryMS, "retry-ms", 250, "data retransmission interval")
	f.IntVar(&o.RepairMS, "repair-ms", 750, "first peer repair request")
	f.IntVar(&o.PayloadBytes, "payload-bytes", 512, "update payload bytes")
	f.StringVar(&o.UpdateID, "update-id", "demo-1", "update identity")
	f.IntVar(&o.BlockedFrom, "blocked-from", -1, "simulated connection failure source role")
	f.IntVar(&o.BlockedTo, "blocked-to", -1, "simulated connection failure destination role")
	if err := f.Parse(args); err != nil {
		return o, err
	}
	if f.NArg() != 0 {
		return o, errors.New("unexpected positional arguments")
	}
	return o, o.validate()
}

func main() {
	// Debuglet passes the submitted WASI argv verbatim, without an argv[0]
	// program name. The first element is already an application argument.
	o, err := parseOptions(os.Args)
	r := &reporter{options: o, writer: os.Stdout}
	var d *delivery
	if err == nil {
		d, err = run(r)
	}
	if summaryErr := r.summary(d, err); summaryErr != nil {
		fmt.Fprintln(os.Stderr, summaryErr)
		os.Exit(1)
	}
	if err != nil || d == nil || !d.verified || (d.Role == 0 && d.completion == nil) {
		os.Exit(1)
	}
}

func run(r *reporter) (*delivery, error) {
	address, err := debuglet.ListenAddr()
	if err != nil {
		return nil, err
	}
	metadata, err := json.Marshal(memberMetadata{Role: r.Role, Endpoint: address, Algorithm: r.Algorithm, Participants: r.Participants, Config: r.settings})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	experiment, err := debuglet.Ready(ctx, metadata)
	if err != nil {
		return nil, err
	}
	r.experimentID = experiment.ID
	endpoints, self, err := members(r.options, address, experiment.Participants)
	if err != nil {
		return nil, err
	}
	r.runID = self
	d := newDelivery(r.options, experiment.ID)
	r.hash = d.hash
	if err := r.event("ready", map[string]any{"config": r.settings}); err != nil {
		return d, err
	}
	if err := debuglet.WaitStart(ctx, experiment); err != nil {
		return d, err
	}
	r.started = time.Now()
	if err := r.event("start", nil); err != nil {
		return d, err
	}
	end := r.started.Add(time.Duration(r.DeadlineMS) * time.Millisecond)
	for time.Now().Before(end) {
		for _, packet := range d.tick(r.elapsed()) {
			if !time.Now().Before(end) {
				break
			}
			if err := send(r, d, endpoints, packet, end); err != nil {
				return d, err
			}
		}
		remaining := time.Until(end)
		if remaining <= 0 {
			break
		}
		conn, err := debuglet.AcceptTCPTimeout(min(20*time.Millisecond, remaining))
		if errors.Is(err, debuglet.ErrTimeout) {
			continue
		}
		if err != nil {
			return d, fmt.Errorf("accept: %w", err)
		}
		if err := conn.SetReadDeadline(minTime(end, time.Now().Add(250*time.Millisecond))); err != nil {
			conn.Close()
			return d, err
		}
		packet, n, readErr := readMessage(conn)
		conn.Close()
		r.receivedBytes += n
		if readErr != nil {
			if err := r.event("invalid_message", map[string]any{"bytes": n}); err != nil {
				return d, err
			}
			continue
		}
		wasVerified := d.verified
		wasAcked := packet.From >= 0 && packet.From < len(d.acked) && d.acked[packet.From]
		responses, err := d.receive(packet, r.elapsed())
		if err != nil {
			if err := r.event("invalid_message", map[string]any{"bytes": n}); err != nil {
				return d, err
			}
			continue
		}
		fields := map[string]any{"peer_role": packet.From, "message_kind": packet.Kind, "bytes": n}
		if err := r.event("receive", fields); err != nil {
			return d, err
		}
		if !wasVerified && d.verified {
			if err := r.event("verified", nil); err != nil {
				return d, err
			}
		}
		if packet.Kind == "ack" && r.Role == 0 && !wasAcked {
			if err := r.event("acknowledged", map[string]any{"peer_role": packet.From}); err != nil {
				return d, err
			}
		}
		if packet.Kind == "repair" {
			if err := r.event("repair", map[string]any{"peer_role": packet.Recipient}); err != nil {
				return d, err
			}
		}
		for _, response := range responses {
			if !time.Now().Before(end) {
				break
			}
			if err := send(r, d, endpoints, response, end); err != nil {
				return d, err
			}
		}
	}
	return d, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func send(r *reporter, d *delivery, endpoints []string, packet message, end time.Time) error {
	fields := map[string]any{"peer_role": packet.To, "message_kind": packet.Kind, "bytes": 0}
	if d.blocked(packet) {
		r.simulatedFailures++
		return r.event("simulated_failure", fields)
	}
	frame, err := frameMessage(packet)
	if err != nil {
		return err
	}
	conn, err := debuglet.DialTimeout("tcp", endpoints[packet.To], min(time.Second, time.Until(end)))
	n := 0
	if err == nil {
		err = conn.SetWriteDeadline(minTime(end, time.Now().Add(250*time.Millisecond)))
		if err == nil {
			n, err = conn.Write(frame)
			if err == nil && n != len(frame) {
				err = io.ErrShortWrite
			}
		}
		conn.Close()
	}
	r.sentBytes += n
	fields["bytes"] = n
	if err != nil {
		r.sendErrors++
		return r.event("send_error", fields)
	}
	return r.event("send", fields)
}

func frameMessage(m message) ([]byte, error) {
	body, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	if len(body) > maxMessageBytes {
		return nil, errors.New("message exceeds framing limit")
	}
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame, uint32(len(body)))
	copy(frame[4:], body)
	return frame, nil
}

func readMessage(reader io.Reader) (message, int, error) {
	var m message
	var header [4]byte
	n, err := io.ReadFull(reader, header[:])
	if err != nil {
		return m, n, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > maxMessageBytes {
		return m, n, errors.New("invalid message length")
	}
	body := make([]byte, length)
	count, err := io.ReadFull(reader, body)
	n += count
	if err != nil {
		return m, n, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&m); err != nil {
		return m, n, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return m, n, errors.New("extra message content")
	}
	return m, n, nil
}

func members(o options, ownAddress string, participants []experimentwire.ExperimentParticipant) ([]string, string, error) {
	if len(participants) != o.Participants {
		return nil, "", errors.New("unexpected group size")
	}
	endpoints := make([]string, o.Participants)
	seenEndpoints, seenExecutors, seenRuns := map[string]bool{}, map[string]bool{}, map[string]bool{}
	self := ""
	for _, participant := range participants {
		var m memberMetadata
		if err := json.Unmarshal(participant.Metadata, &m); err != nil {
			return nil, "", err
		}
		if m.Role < 0 || m.Role >= o.Participants || endpoints[m.Role] != "" || m.Algorithm != o.Algorithm || m.Participants != o.Participants || m.Config != o.settings {
			return nil, "", errors.New("participants disagree on roles or experiment settings")
		}
		host, port, err := net.SplitHostPort(m.Endpoint)
		if err != nil {
			return nil, "", errors.New("invalid participant listener")
		}
		ip, ipErr := netip.ParseAddr(host)
		portNumber, portErr := strconv.Atoi(port)
		if ipErr != nil || ip.IsUnspecified() || ip.IsMulticast() || portErr != nil || portNumber < 1 || portNumber > 65535 {
			return nil, "", errors.New("need a numeric reachable listener address")
		}
		endpoint := net.JoinHostPort(ip.String(), strconv.Itoa(portNumber))
		if participant.ID == "" || participant.ExecutorID == "" || seenEndpoints[endpoint] || seenExecutors[participant.ExecutorID] || seenRuns[participant.ID] {
			return nil, "", errors.New("participants need distinct listeners, executors and runs")
		}
		seenEndpoints[endpoint], seenExecutors[participant.ExecutorID], seenRuns[participant.ID] = true, true, true
		endpoints[m.Role] = m.Endpoint
		if m.Role == o.Role {
			if m.Endpoint != ownAddress {
				return nil, "", errors.New("own listener does not match assigned role")
			}
			self = participant.ID
		}
	}
	if self == "" {
		return nil, "", errors.New("own role is absent from group")
	}
	return endpoints, self, nil
}
