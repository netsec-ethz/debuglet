// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package debuglet

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/netsec-ethz/debuglet/internal/guestio"
)

type SCIONPath = guestio.SCIONPath
type SCIONInterface = guestio.SCIONInterface
type SCIONExchange = guestio.SCIONExchange
type SCIONDatagram = guestio.SCIONDatagram

const SCIONMaxPayload = guestio.SCIONMaxPayload

// ListSCIONPaths discovers currently usable outbound paths to a literal SCION
// UDP address (IA,IP:port). A same-AS destination has the explicit "local" path.
// Timeout zero uses the run lifetime. Requires SCION protocol permission.
func ListSCIONPaths(address string, timeout time.Duration) ([]SCIONPath, error) {
	r, err := scionCall(guestio.SCIONPaths, invokeSCIONPaths, guestio.SCIONRequest{Address: address, TimeoutNS: int64(timeout)})
	if r.Paths == nil && err == nil {
		r.Paths = []SCIONPath{}
	}
	return r.Paths, err
}

// SelectSCIONPath pins a discovered identity, never a list index. An unavailable
// identity is an error and never silently falls back to another path.
func SelectSCIONPath(address, pathID string, timeout time.Duration) (SCIONPath, error) {
	r, err := scionCall(guestio.SCIONSelectPath, invokeSCIONSelectPath, guestio.SCIONRequest{Address: address, PathID: pathID, TimeoutNS: int64(timeout)})
	if err == nil && r.Path == nil {
		err = fmt.Errorf("debuglet: missing SCION path result")
	}
	if err != nil {
		return SCIONPath{}, err
	}
	return *r.Path, nil
}

// ExchangeSCION sends one datagram over the exact discovered path and receives
// one reply on that same connected socket. PathID identifies the outbound path;
// it makes no claim about the return path. The caller must correlate payloads
// when retrying after timeouts; a delayed earlier reply can still arrive.
// The entire received payload is accounted; Data is capped at maxBytes and
// Truncated and Size preserve that distinction. No TESLA tags are added.
func ExchangeSCION(address, pathID string, payload []byte, maxBytes int, timeout time.Duration) (SCIONExchange, error) {
	r, err := scionCall(guestio.SCIONExchangeFunction, invokeSCIONExchange, guestio.SCIONRequest{Address: address, PathID: pathID, Payload: payload, MaxBytes: maxBytes, TimeoutNS: int64(timeout)})
	if err == nil && r.Exchange == nil {
		err = fmt.Errorf("debuglet: missing SCION exchange result")
	}
	if r.Exchange == nil {
		return SCIONExchange{}, err
	}
	return *r.Exchange, err
}

// SCIONListenerAddress returns the run's admitted SCION listener endpoint.
func SCIONListenerAddress() (string, error) {
	r, err := scionCall(guestio.SCIONListenerAddressFunction, invokeSCIONListenerAddress, guestio.SCIONRequest{})
	return r.Address, err
}

// ReceiveSCION reads one admitted datagram from the run's SCION listener.
// maxBytes is 1..SCIONMaxPayload. A timeout is an ordinary recoverable error.
func ReceiveSCION(maxBytes int, timeout time.Duration) (SCIONDatagram, error) {
	r, err := scionCall(guestio.SCIONReceive, invokeSCIONReceive, guestio.SCIONRequest{MaxBytes: maxBytes, TimeoutNS: int64(timeout)})
	if err == nil && r.Datagram == nil {
		err = fmt.Errorf("debuglet: missing SCION receive result")
	}
	if err != nil {
		return SCIONDatagram{}, err
	}
	return *r.Datagram, nil
}

// ReplySCION replies only to the exact sender of the most recent successful
// ReceiveSCION. It cannot open a connection to an arbitrary destination.
func ReplySCION(sender string, payload []byte, timeout time.Duration) (int, error) {
	r, err := scionCall(guestio.SCIONReply, invokeSCIONReply, guestio.SCIONRequest{Address: sender, Payload: payload, TimeoutNS: int64(timeout)})
	return r.Bytes, err
}

func scionCall(operation string, invoke func([]byte) ([]byte, error), req guestio.SCIONRequest) (guestio.SCIONResponse, error) {
	var result guestio.SCIONResponse
	if req.TimeoutNS < 0 || len(req.Payload) > SCIONMaxPayload || len(req.Address) > 256 || len(req.PathID) > 256 {
		return result, fmt.Errorf("debuglet: invalid SCION bounds")
	}
	if operation == guestio.SCIONReceive || operation == guestio.SCIONExchangeFunction {
		if req.MaxBytes < 1 || req.MaxBytes > SCIONMaxPayload {
			return result, fmt.Errorf("debuglet: invalid SCION receive size")
		}
	}
	if operation != guestio.SCIONReceive && operation != guestio.SCIONListenerAddressFunction && req.Address == "" {
		return result, fmt.Errorf("debuglet: SCION address is required")
	}
	if (operation == guestio.SCIONSelectPath || operation == guestio.SCIONExchangeFunction) && req.PathID == "" {
		return result, fmt.Errorf("debuglet: an exact SCION path ID is required")
	}
	data, err := json.Marshal(req)
	if err != nil {
		return result, err
	}
	data, err = invoke(data)
	if len(data) > 0 {
		if decodeErr := json.Unmarshal(data, &result); decodeErr != nil {
			return result, decodeErr
		}
	}
	if err != nil && result.Error != "" {
		err = fmt.Errorf("%s: %w", result.Error, err)
	}
	return result, err
}
