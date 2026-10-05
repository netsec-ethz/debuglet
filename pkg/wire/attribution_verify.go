// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"time"
)

// Server-assisted verification (docs/verification.md): POST
// /attribution/verify and GET /attribution/receipt-keys.

// AttributionVerifyPacket is one captured packet: the first min(64, Total
// Length) bytes of the IPv4 packet and the time the caller says it was
// captured.
type AttributionVerifyPacket struct {
	Data       []byte    `json:"data"`
	CapturedAt time.Time `json:"captured_at"`
}

// AttributionVerifyRequest is the body of POST /attribution/verify.
type AttributionVerifyRequest struct {
	Packets []AttributionVerifyPacket `json:"packets"`
}

// AttributionVerifyBudget is the executor query budget of one chain epoch,
// shared by every requester. ResetsAt is when the epoch's key is due for
// disclosure; from then on the group is checked against the disclosed key.
type AttributionVerifyBudget struct {
	Limit     int64     `json:"limit"`
	Remaining int64     `json:"remaining"`
	ResetsAt  time.Time `json:"resets_at"`
}

// AttributionVerifyGroup is the verdict of one packet group: the packets of
// one source address in one epoch of one chain. Packets are indices into the
// request's packets. Budget is set for a group that has a chain.
type AttributionVerifyGroup struct {
	Source     string                   `json:"source"`
	Epoch      int64                    `json:"epoch"`
	ChainID    string                   `json:"chain_id"`
	ExecutorID string                   `json:"executor_id"`
	RunID      string                   `json:"run_id"`
	Verdict    string                   `json:"verdict"`
	Reason     string                   `json:"reason"`
	Method     string                   `json:"method"`
	Packets    []int                    `json:"packets"`
	Budget     *AttributionVerifyBudget `json:"budget,omitempty"`
}

// AttributionReceipt is a detached Ed25519 signature by the key KeyID over
// Payload, the canonical JSON of an AttributionReceiptPayload.
type AttributionReceipt struct {
	KeyID     string `json:"key_id"`
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

// AttributionVerifyResponse answers POST /attribution/verify.
type AttributionVerifyResponse struct {
	Groups  []AttributionVerifyGroup `json:"groups"`
	Receipt AttributionReceipt       `json:"receipt"`
}

// AttributionReceiptPayload is what a receipt signs. QueryAt is the
// dispatcher's clock when it answered; the callers' capture times enter only
// through PacketsDigest, so a receipt shows what was asked and answered when,
// not when a packet was observed. Its fields are in the order of their JSON
// names, which CanonicalReceiptPayload relies on.
type AttributionReceiptPayload struct {
	APIVersion    string                    `json:"api_version"`
	Dispatcher    string                    `json:"dispatcher"`
	Groups        []AttributionReceiptGroup `json:"groups"`
	PacketsDigest string                    `json:"packets_digest"`
	QueryAt       string                    `json:"query_at"`
}

// AttributionReceiptGroup is one group verdict as a receipt records it.
type AttributionReceiptGroup struct {
	ChainID    string `json:"chain_id"`
	Epoch      int64  `json:"epoch"`
	ExecutorID string `json:"executor_id"`
	Method     string `json:"method"`
	Packets    []int  `json:"packets"`
	Reason     string `json:"reason"`
	RunID      string `json:"run_id"`
	Source     string `json:"source"`
	Verdict    string `json:"verdict"`
}

// CanonicalReceiptPayload encodes a payload as canonical JSON: keys sorted,
// no whitespace, no HTML escaping.
func CanonicalReceiptPayload(p AttributionReceiptPayload) ([]byte, error) {
	if p.Groups == nil {
		p.Groups = []AttributionReceiptGroup{}
	}
	for i := range p.Groups {
		if p.Groups[i].Packets == nil {
			p.Groups[i].Packets = []int{}
		}
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// PacketsDigest is "sha256:" and the hex SHA-256 over the big-endian uint16
// length, the data and the int64 captured_at in Unix nanoseconds of every
// packet in order: the digest of an evidence bundle's packets.
func PacketsDigest(packets []AttributionVerifyPacket) string {
	h := sha256.New()
	var buf [8]byte
	for _, p := range packets {
		binary.BigEndian.PutUint16(buf[:2], uint16(len(p.Data)))
		h.Write(buf[:2])
		h.Write(p.Data)
		binary.BigEndian.PutUint64(buf[:], uint64(p.CapturedAt.UnixNano()))
		h.Write(buf[:])
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// AttributionReceiptKey is one key that verifies receipts, valid for receipts
// whose query_at is at or after ValidFrom and, when ValidTo is set, before it.
type AttributionReceiptKey struct {
	KeyID     string     `json:"key_id"`
	PublicKey []byte     `json:"public_key"`
	ValidFrom time.Time  `json:"valid_from"`
	ValidTo   *time.Time `json:"valid_to"`
}

// AttributionReceiptKeys answers GET /attribution/receipt-keys.
type AttributionReceiptKeys struct {
	Keys []AttributionReceiptKey `json:"keys"`
}
