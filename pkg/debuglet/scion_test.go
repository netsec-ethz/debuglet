// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package debuglet

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/guestio"
)

func TestSCIONValidationDoesNotInvokeHost(t *testing.T) {
	for _, req := range []guestio.SCIONRequest{
		{Address: "1-ff00:0:110,192.0.2.1:1234", PathID: "id", MaxBytes: 1, TimeoutNS: -1},
		{Address: "1-ff00:0:110,192.0.2.1:1234", PathID: "id", MaxBytes: SCIONMaxPayload + 1},
		{Address: "1-ff00:0:110,192.0.2.1:1234", PathID: "", MaxBytes: 1},
		{Address: "1-ff00:0:110,192.0.2.1:1234", PathID: "id", MaxBytes: 1, Payload: make([]byte, SCIONMaxPayload+1)},
	} {
		_, err := scionCall(guestio.SCIONExchangeFunction, func([]byte) ([]byte, error) { t.Fatal("invalid request reached host"); return nil, nil }, req)
		if err == nil {
			t.Fatalf("accepted %+v", req)
		}
	}
}

func TestSCIONResponsePreservesPartialEvidenceAndSafeReason(t *testing.T) {
	timeout := errors.New("timeout")
	r, err := scionCall(guestio.SCIONExchangeFunction, func([]byte) ([]byte, error) {
		return []byte(`{"exchange":{"path_id":"sent-path","sender":"peer","duration_ms":5}}`), timeout
	}, guestio.SCIONRequest{Address: "peer", PathID: "sent-path", MaxBytes: 8, TimeoutNS: int64(time.Second)})
	if !errors.Is(err, timeout) || r.Exchange == nil || r.Exchange.PathID != "sent-path" {
		t.Fatalf("partial evidence lost: %+v %v", r, err)
	}
	r, err = scionCall(guestio.SCIONSelectPath, func([]byte) ([]byte, error) {
		return []byte(`{"error":"SCION path is unavailable or expired; discover paths again"}`), ErrIO
	}, guestio.SCIONRequest{Address: "peer", PathID: "gone"})
	if err == nil || !strings.Contains(err.Error(), "discover paths again") || r.Path != nil {
		t.Fatalf("path reason lost: %+v %v", r, err)
	}
}

func TestSCIONQUICRequiresExplicitCertificatePin(t *testing.T) {
	for _, pin := range []string{"", "not-a-pin", strings.Repeat("a", 62), strings.Repeat("g", 64)} {
		_, err := scionCall(guestio.SCIONQUICExchangeFunction, func([]byte) ([]byte, error) { t.Fatal("invalid pin reached host"); return nil, nil }, guestio.SCIONRequest{Address: "peer", PathID: "path", CertificateSHA256: pin})
		if err == nil {
			t.Fatalf("accepted pin %q", pin)
		}
	}
}

func TestSCIONQUICRejectsTimeoutBeyondBound(t *testing.T) {
	_, err := scionCall(guestio.SCIONQUICExchangeFunction, func([]byte) ([]byte, error) { t.Fatal("excessive timeout reached host"); return nil, nil }, guestio.SCIONRequest{Address: "peer", PathID: "path", CertificateSHA256: strings.Repeat("a", 64), TimeoutNS: int64(11 * time.Second)})
	if err == nil {
		t.Fatal("accepted timeout beyond 10 seconds")
	}
}
