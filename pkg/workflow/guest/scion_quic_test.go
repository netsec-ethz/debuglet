// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

func TestSCIONQUICRequiresExpectedPinAndPreservesFailure(t *testing.T) {
	in := map[string]any{"address": "1-ff00:0:111,192.0.2.1:4000", "path_id": "path-a", "certificate_sha256": strings.Repeat("a", 64), "payload": "/wA=", "encoding": "base64"}
	out, err := scionQUICExchange(in, func(address, path, pin string, payload []byte, timeout time.Duration) (debuglet.SCIONQUICExchange, error) {
		if address != in["address"] || path != "path-a" || pin != in["certificate_sha256"] || !reflect.DeepEqual(payload, []byte{255, 0}) || timeout != 5*time.Second {
			t.Fatal(address, path, pin, payload, timeout)
		}
		return debuglet.SCIONQUICExchange{PathID: path, Sender: address, Verified: true, HandshakeMS: 1.5, DurationMS: 3.5}, errors.New("stream receive timed out")
	})
	if err != nil || out["ok"] != false || out["error"] != "stream receive timed out" || out["path_id"] != "path-a" || out["verified"] != true || out["duration_ms"] != 3.5 {
		t.Fatal(out, err)
	}
	out, err = scionQUICExchange(in, func(string, string, string, []byte, time.Duration) (debuglet.SCIONQUICExchange, error) {
		return debuglet.SCIONQUICExchange{Data: []byte{255, 0}, PathID: "path-a", Verified: true}, nil
	})
	if err != nil || out["ok"] != true || out["response_base64"] != "/wA=" {
		t.Fatal(out, err)
	}
	in["timeout_ms"] = float64(10001)
	if _, err := scionQUICExchange(in, func(string, string, string, []byte, time.Duration) (debuglet.SCIONQUICExchange, error) {
		t.Fatal("oversized timeout reached IO")
		return debuglet.SCIONQUICExchange{}, nil
	}); err == nil {
		t.Fatal("accepted timeout over 10 seconds")
	}
	delete(in, "timeout_ms")
	for _, pin := range []string{"", "sha256:abcd", strings.Repeat("G", 64), strings.Repeat("A", 64), strings.Repeat("0", 62)} {
		in["certificate_sha256"] = pin
		_, err := scionQUICExchange(in, func(string, string, string, []byte, time.Duration) (debuglet.SCIONQUICExchange, error) {
			t.Fatal("invalid pin reached IO")
			return debuglet.SCIONQUICExchange{}, nil
		})
		if err == nil {
			t.Fatal("accepted pin", pin)
		}
	}
}

func TestSCIONQUICEchoStartReportsTrustedResult(t *testing.T) {
	pin := strings.Repeat("b", 64)
	out, err := scionQUICEchoStart(map[string]any{}, func(timeout time.Duration) (debuglet.SCIONQUICListener, error) {
		if timeout != 2*time.Second {
			t.Fatal(timeout)
		}
		return debuglet.SCIONQUICListener{Address: "1-ff00:0:111,192.0.2.1:4000", CertificateSHA256: pin}, nil
	})
	if err != nil || out["ok"] != true || out["certificate_sha256"] != pin {
		t.Fatal(out, err)
	}
}
