// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

func TestSCIONDiscoveryAndPinPreserveStableIdentity(t *testing.T) {
	in := map[string]any{"address": "1-ff00:0:110,192.0.2.1:4000", "path_id": "path-b", "timeout_ms": float64(1500)}
	path := debuglet.SCIONPath{ID: "path-b", Source: "1-ff00:0:111", Destination: "1-ff00:0:110", HopCount: 2, MTU: 1400, ExpiresMS: 1234, Interfaces: []debuglet.SCIONInterface{{IA: "1-ff00:0:111", ID: 5}}}
	out, err := scionPaths(in, func(address string, timeout time.Duration) ([]debuglet.SCIONPath, error) {
		if address != in["address"] || timeout != 1500*time.Millisecond {
			t.Fatal(address, timeout)
		}
		return []debuglet.SCIONPath{path}, nil
	})
	if err != nil || out["ok"] != true {
		t.Fatal(out, err)
	}
	if !reflect.DeepEqual(out["paths"], []any{scionPathObject(path)}) {
		t.Fatal(out)
	}
	out, err = scionSelectPath(in, func(address, id string, timeout time.Duration) (debuglet.SCIONPath, error) {
		if id != "path-b" {
			t.Fatal("selected by index instead of stable id")
		}
		return debuglet.SCIONPath{}, errors.New("selected path disappeared")
	})
	if err != nil || out["ok"] != false || out["path_id"] != "" || out["error"] != "selected path disappeared" {
		t.Fatal(out, err)
	}
}

func TestSCIONExchangeRecordsActualPathAndFailure(t *testing.T) {
	in := map[string]any{"address": "1-ff00:0:110,192.0.2.1:4000", "path_id": "path-a", "payload": "/wA=", "encoding": "base64"}
	out, err := scionUDPExchange(in, func(address, id string, payload []byte, maxBytes int, timeout time.Duration) (debuglet.SCIONExchange, error) {
		if id != "path-a" || !reflect.DeepEqual(payload, []byte{255, 0}) || maxBytes != 4096 {
			t.Fatal(id, payload, maxBytes)
		}
		return debuglet.SCIONExchange{PathID: "path-a", Sender: address, DurationMS: 2}, errors.New("receive timed out")
	})
	if err != nil || out["ok"] != false || out["complete"] != false || out["path_id"] != "path-a" || out["error"] != "receive timed out" {
		t.Fatal(out, err)
	}
	out, err = scionUDPExchange(in, func(string, string, []byte, int, time.Duration) (debuglet.SCIONExchange, error) {
		return debuglet.SCIONExchange{PathID: "path-a", Data: []byte{255}, Size: 2, Truncated: true}, nil
	})
	if err != nil || out["ok"] != false || out["truncated"] != true || out["response_base64"] != "/w==" || out["received_bytes"] != float64(2) {
		t.Fatal(out, err)
	}
}

func TestSCIONReceiveReplyPreserveBytes(t *testing.T) {
	const sender = "1-ff00:0:111,192.0.2.2:1234"
	out, err := scionReceive(map[string]any{"encoding": "base64"}, func(int, time.Duration) (debuglet.SCIONDatagram, error) {
		return debuglet.SCIONDatagram{Data: []byte{255, 0}, Size: 2, Sender: sender, ReceivedAtMS: 1234}, nil
	})
	if err != nil || out["ok"] != true || out["payload"] != "/wA=" || out["received_at_ms"] != float64(1234) {
		t.Fatal(out, err)
	}
	out, err = scionReply(map[string]any{"sender": out["sender"], "payload": out["payload_base64"], "encoding": "base64"}, func(address string, payload []byte, timeout time.Duration) (int, error) {
		if address != sender || !reflect.DeepEqual(payload, []byte{255, 0}) {
			t.Fatal(address, payload)
		}
		return len(payload), nil
	})
	if err != nil || out["ok"] != true || out["bytes_sent"] != float64(2) {
		t.Fatal(out, err)
	}
}

func TestSCIONDynamicBoundsBeforeIO(t *testing.T) {
	for _, invalid := range []map[string]any{{"path_id": ""}, {"max_bytes": float64(4097)}, {"timeout_ms": float64(0)}, {"encoding": "base64", "payload": "!!"}} {
		in := map[string]any{"address": "1-ff00:0:110,192.0.2.1:4000", "path_id": "path-a"}
		for k, v := range invalid {
			in[k] = v
		}
		_, err := scionUDPExchange(in, func(string, string, []byte, int, time.Duration) (debuglet.SCIONExchange, error) {
			t.Fatal("invalid input reached IO")
			return debuglet.SCIONExchange{}, nil
		})
		if err == nil {
			t.Fatal("accepted", invalid)
		}
	}
}
