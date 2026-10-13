// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const schema = "debuglet.delivery.v1"

type settings struct {
	DeadlineMS   int    `json:"deadline_ms"`
	RetryMS      int    `json:"retry_ms"`
	RepairMS     int    `json:"repair_ms"`
	PayloadBytes int    `json:"payload_bytes"`
	UpdateID     string `json:"update_id"`
	BlockedFrom  int    `json:"blocked_from"`
	BlockedTo    int    `json:"blocked_to"`
}

type options struct {
	Algorithm    string
	Role         int
	Participants int
	settings
}

func (o options) validate() error {
	if o.Algorithm != "direct" && o.Algorithm != "relay" {
		return errors.New("algorithm must be direct or relay")
	}
	if o.Participants < 2 || o.Participants > 8 || o.Role < 0 || o.Role >= o.Participants {
		return errors.New("need 2–8 participants and a role in that group")
	}
	if o.DeadlineMS < 1000 || o.DeadlineMS > 15000 || o.RetryMS < 100 || o.RetryMS > 2000 || o.RepairMS < o.RetryMS || o.RepairMS >= o.DeadlineMS {
		return errors.New("deadline must be 1000–15000 ms, retry 100–2000 ms, and retry <= repair < deadline")
	}
	if o.PayloadBytes < 1 || o.PayloadBytes > 512 || len(o.UpdateID) < 1 || len(o.UpdateID) > 64 {
		return errors.New("payload must be 1–512 bytes and update ID 1–64 characters")
	}
	if o.BlockedFrom != -1 || o.BlockedTo != -1 {
		if o.BlockedFrom < 0 || o.BlockedFrom >= o.Participants || o.BlockedTo < 0 || o.BlockedTo >= o.Participants || o.BlockedFrom == o.BlockedTo {
			return errors.New("simulated failure requires two distinct participant roles, or both -1")
		}
	}
	return nil
}

type message struct {
	Version      int    `json:"version"`
	ExperimentID string `json:"experiment_id"`
	UpdateID     string `json:"update_id"`
	Kind         string `json:"kind"`
	From         int    `json:"from"`
	To           int    `json:"to"`
	Recipient    int    `json:"recipient"`
	SHA256       string `json:"sha256"`
	Payload      []byte `json:"payload,omitempty"`
}

type pendingSend struct{ next time.Duration }

// delivery is deliberately a small application protocol, independent of its
// TCP framing. It does not predict network outcomes or create receive events.
type delivery struct {
	options
	experimentID string
	payload      []byte
	hash         string
	verified     bool
	acked        []bool
	pending      map[int]pendingSend
	nextRepair   time.Duration
	repairRound  int
	completion   *time.Duration
	duplicates   int
}

func newDelivery(o options, experimentID string) *delivery {
	payload := make([]byte, o.PayloadBytes)
	for i := range payload {
		payload[i] = byte((i*31 + 17) % 251)
	}
	sum := sha256.Sum256(payload)
	d := &delivery{options: o, experimentID: experimentID, payload: payload,
		hash: hex.EncodeToString(sum[:]), verified: o.Role == 0,
		acked: make([]bool, o.Participants), pending: make(map[int]pendingSend),
		nextRepair: time.Duration(o.RepairMS) * time.Millisecond}
	if o.Role == 0 {
		for role := 1; role < o.Participants; role++ {
			if o.Algorithm == "direct" || (role-1)/2 == 0 {
				d.pending[role] = pendingSend{}
			}
		}
	}
	return d
}

func (d *delivery) packet(kind string, to, recipient int) message {
	m := message{Version: 1, ExperimentID: d.experimentID, UpdateID: d.UpdateID,
		Kind: kind, From: d.Role, To: to, Recipient: recipient, SHA256: d.hash}
	if kind == "data" {
		m.Payload = d.payload
	}
	return m
}

func (d *delivery) tick(now time.Duration) []message {
	if now >= time.Duration(d.DeadlineMS)*time.Millisecond || d.completion != nil {
		return nil
	}
	var outgoing []message
	// Do not wait for one peer's ACK before sending to the next peer.
	for role := 1; role < d.Participants; role++ {
		if pending, ok := d.pending[role]; ok && now >= pending.next {
			outgoing = append(outgoing, d.packet("data", role, role))
			d.pending[role] = pendingSend{next: now + time.Duration(d.RetryMS)*time.Millisecond}
		}
	}
	if d.Role == 0 && d.Algorithm == "relay" && now >= d.nextRepair {
		for missing := 1; missing < d.Participants; missing++ {
			if d.acked[missing] {
				continue
			}
			var helpers []int
			for role := 1; role < d.Participants; role++ {
				if role != missing && d.acked[role] {
					helpers = append(helpers, role)
				}
			}
			if len(helpers) != 0 {
				outgoing = append(outgoing, d.packet("repair", helpers[d.repairRound%len(helpers)], missing))
			}
		}
		d.repairRound++
		d.nextRepair = now + time.Duration(d.RetryMS)*time.Millisecond
	}
	return outgoing
}

func (d *delivery) receive(m message, now time.Duration) ([]message, error) {
	if m.Version != 1 || m.ExperimentID != d.experimentID || m.UpdateID != d.UpdateID || m.SHA256 != d.hash || m.From < 0 || m.From >= d.Participants || m.From == d.Role || m.To != d.Role {
		return nil, errors.New("message does not match this experiment, update or recipient")
	}
	if now >= time.Duration(d.DeadlineMS)*time.Millisecond {
		return nil, errors.New("message arrived after the local deadline")
	}
	switch m.Kind {
	case "data":
		if d.Role == 0 || m.Recipient != d.Role || len(m.Payload) != d.PayloadBytes {
			return nil, errors.New("invalid update recipient or payload length")
		}
		sum := sha256.Sum256(m.Payload)
		if hex.EncodeToString(sum[:]) != d.hash {
			return nil, errors.New("update hash mismatch")
		}
		if d.verified {
			d.duplicates++
		} else {
			d.verified = true
			if d.Algorithm == "relay" {
				for child := 1; child < d.Participants; child++ {
					if (child-1)/2 == d.Role {
						d.pending[child] = pendingSend{}
					}
				}
			}
		}
		acks := []message{d.packet("ack", 0, d.Role)}
		if m.From != 0 {
			acks = append(acks, d.packet("ack", m.From, d.Role))
		}
		return acks, nil
	case "ack":
		if len(m.Payload) != 0 || m.Recipient != m.From {
			return nil, errors.New("invalid acknowledgement")
		}
		delete(d.pending, m.From)
		if d.Role == 0 {
			d.acked[m.From] = true
			if d.completion == nil && len(d.missing()) == 0 {
				elapsed := now
				d.completion = &elapsed
			}
		}
	case "repair":
		if d.Algorithm != "relay" || m.From != 0 || len(m.Payload) != 0 || m.Recipient < 1 || m.Recipient >= d.Participants || m.Recipient == d.Role || !d.verified {
			return nil, errors.New("invalid repair instruction")
		}
		// A repeated instruction may repair a lost origin ACK even if this
		// helper received its own ACK for an earlier send.
		if _, waiting := d.pending[m.Recipient]; !waiting {
			d.pending[m.Recipient] = pendingSend{}
		}
	default:
		return nil, fmt.Errorf("unknown message kind")
	}
	return nil, nil
}

func (d *delivery) missing() []int {
	roles := []int{}
	for role := 1; role < d.Participants; role++ {
		if !d.acked[role] {
			roles = append(roles, role)
		}
	}
	return roles
}

func (d *delivery) blocked(m message) bool { return m.From == d.BlockedFrom && m.To == d.BlockedTo }
