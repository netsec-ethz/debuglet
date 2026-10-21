// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

func TestExchangeInvalidInputsDoNotDial(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, patch := range []map[string]any{
			{"target": "example.test:0"}, {"target": "https://example.test/"}, {"target": "bad host:443"},
			{"payload": 1}, {"payload": strings.Repeat("x", debuglet.MaxIOBytes+1)},
			{"encoding": "hex"}, {"encoding": "base64", "payload": "!!"},
			{"encoding": "base64", "payload": "AB=="}, // Nonzero unused padding bits.
			{"max_bytes": float64(0)}, {"max_bytes": float64(debuglet.MaxIOBytes + 1)},
			{"timeout_ms": float64(0)}, {"timeout_ms": 1.5},
		} {
			inputs := map[string]any{"target": "example.test:53"}
			for key, value := range patch {
				inputs[key] = value
			}
			if out, err := networkExchange(inputs, stream); err == nil || out != nil {
				t.Fatalf("stream=%v inputs=%v returned %v, %v", stream, inputs, out, err)
			}
		}
	}
	for _, patch := range []map[string]any{{"read_until": "forever"}, {"delimiter": ""}, {"delimiter": 0}, {"delimiter": "long", "max_bytes": float64(2)}} {
		inputs := map[string]any{"target": "example.test:53"}
		for key, value := range patch {
			inputs[key] = value
		}
		if _, err := TCPExchange(inputs); err == nil {
			t.Fatalf("accepted %v", inputs)
		}
	}
	if _, err := networkExchangeConfig(map[string]any{"target": "example.test:53", "max_bytes": float64(debuglet.MaxIOBytes)}, false); err == nil {
		t.Fatal("UDP must reserve a byte to detect oversize responses")
	}
}

func TestExchangePayloadBytes(t *testing.T) {
	want := []byte{0, 255, '\n', 128}
	got, err := networkPayload(map[string]any{"payload": base64.StdEncoding.EncodeToString(want), "encoding": "base64"})
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("payload=%v, %v", got, err)
	}
	got, err = networkPayload(map[string]any{"payload": "  line\n"})
	if err != nil || string(got) != "  line\n" {
		t.Fatalf("text whitespace changed: %q, %v", got, err)
	}
	got, err = networkPayload(map[string]any{})
	if err != nil || len(got) != 0 {
		t.Fatalf("empty payload=%v, %v", got, err)
	}
}

func TestExchangeFraming(t *testing.T) {
	for name, tc := range map[string]struct {
		mode, wire, delimiter, want string
		limit                       int
		complete, truncated         bool
		wantErr                     error
	}{
		"delimiter":              {"delimiter", "hello\r\nnext", "\r\n", "hello\r\n", 20, true, false, nil},
		"delimiter at limit":     {"delimiter", "ok\nmore", "\n", "ok\n", 3, true, false, nil},
		"delimiter beyond limit": {"delimiter", "ok\r\n", "\r\n", "ok\r", 3, false, true, nil},
		"missing delimiter":      {"delimiter", "hello", "\n", "hello", 20, false, false, io.ErrUnexpectedEOF},
		"exact bytes":            {"bytes", "hello extra", "", "hello", 5, true, false, nil},
		"short bytes":            {"bytes", "hi", "", "hi", 5, false, false, io.ErrUnexpectedEOF},
		"EOF":                    {"eof", "hi", "", "hi", 5, true, false, nil},
		"EOF at limit":           {"eof", "hello", "", "hello", 5, true, false, nil},
		"EOF too large":          {"eof", "hello!", "", "hello", 5, false, true, nil},
		"empty EOF":              {"eof", "", "", "", 5, true, false, nil},
	} {
		t.Run(name, func(t *testing.T) {
			// One-byte reads also exercise delimiters split across packets.
			reader := io.LimitReader(strings.NewReader(tc.wire), int64(len(tc.wire)))
			got, complete, truncated, err := networkReadExchange(oneByteReader{reader}, exchangeConfig{readUntil: tc.mode, limit: tc.limit, delimiter: []byte(tc.delimiter)})
			if string(got) != tc.want || complete != tc.complete || truncated != tc.truncated {
				t.Fatalf("got %q complete=%v truncated=%v error=%v", got, complete, truncated, err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) || tc.wantErr == nil && !tc.truncated && err != nil || tc.truncated && err == nil {
				t.Fatalf("error=%v, expected %v (truncated=%v)", err, tc.wantErr, tc.truncated)
			}
		})
	}
}

type oneByteReader struct{ io.Reader }

func (r oneByteReader) Read(buf []byte) (int, error) { return r.Reader.Read(buf[:min(1, len(buf))]) }

type finalRead struct{ err error }

func (r finalRead) Read(buf []byte) (int, error) { return copy(buf, "ok\n"), r.err }

func TestExchangeProcessesFinalBytesBeforeEOF(t *testing.T) {
	got, complete, truncated, err := networkReadExchange(finalRead{io.EOF}, exchangeConfig{readUntil: "delimiter", limit: 8, delimiter: []byte("\n")})
	if string(got) != "ok\n" || !complete || truncated || err != nil {
		t.Fatalf("%q %v %v %v", got, complete, truncated, err)
	}
	got, complete, _, err = networkReadExchange(finalRead{debuglet.ErrTimeout}, exchangeConfig{readUntil: "bytes", limit: 8})
	if string(got) != "ok\n" || complete || !errors.Is(err, debuglet.ErrTimeout) {
		t.Fatalf("partial timeout: %q %v %v", got, complete, err)
	}
}
