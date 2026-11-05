// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
)

func TestBytePayloadExactBytes(t *testing.T) {
	for name, tc := range map[string]struct {
		value, encoding string
		size            float64
		want            []byte
	}{
		"empty":       {"", "text", -1, nil},
		"zero":        {"ff00", "hex", 0, nil},
		"binary":      {"00fF80", "hex", -1, []byte{0, 255, 128}},
		"base64":      {"AP+A", "base64", -1, []byte{0, 255, 128}},
		"whitespace":  {" \x00\n ", "text", -1, []byte{' ', 0, '\n', ' '}},
		"UTF-8 bytes": {"é☀", "text", -1, []byte("é☀")},
		"repeat":      {"00ff", "hex", 5, []byte{0, 255, 0, 255, 0}},
		"byte trim":   {"é", "text", 1, []byte{0xc3}},
		"limit":       {"ff", "hex", 8192, bytes.Repeat([]byte{255}, 8192)},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := Pure("byte_payload", map[string]any{"value": tc.value, "encoding": tc.encoding, "size_bytes": tc.size})
			if err != nil {
				t.Fatal(err)
			}
			if out["base64"] != base64.StdEncoding.EncodeToString(tc.want) || out["hex"] != hex.EncodeToString(tc.want) || out["bytes"] != float64(len(tc.want)) {
				t.Fatalf("got %v, want %x", out, tc.want)
			}
			// Output is a legal JSON workflow value even for non-UTF-8 bytes.
			if err := Check(out, map[string]string{"base64": "string", "hex": "string", "bytes": "number"}); err != nil {
				t.Fatal(err)
			}
			for _, encoding := range []string{"hex", "base64"} {
				wire, err := networkPayload(map[string]any{"payload": out[encoding], "encoding": encoding})
				if err != nil || !bytes.Equal(wire, tc.want) {
					t.Fatalf("%s transport payload changed bytes: %x %v", encoding, wire, err)
				}
			}
		})
	}
}

func TestBytePayloadRejectsInvalidAndOversizedInputs(t *testing.T) {
	for _, in := range []map[string]any{
		{"value": "", "size_bytes": float64(1)}, {"size_bytes": float64(-2)}, {"size_bytes": 1.5},
		{"size_bytes": math.NaN()}, {"size_bytes": math.Inf(1)}, {"size_bytes": float64(8193)},
		{"value": "f", "encoding": "hex"}, {"value": "ff 00", "encoding": "hex"},
		{"value": "AB==", "encoding": "base64"}, {"value": "AA", "encoding": "base64"},
		{"value": "00", "encoding": "binary"}, {"value": true},
		{"value": strings.Repeat("é", 4097)},
		{"value": strings.Repeat("ff", 8193), "encoding": "hex"},
		{"value": base64.StdEncoding.EncodeToString(make([]byte, 8193)), "encoding": "base64"},
	} {
		if _, err := Pure("byte_payload", in); err == nil {
			t.Fatalf("accepted invalid input %#v", in)
		}
	}
}

func TestHTTPBinaryBodyPreservedOnWire(t *testing.T) {
	want := []byte{0, 255, 128, '\n', 0xc3, 0xa9}
	for _, encoding := range []string{"hex", "base64"} {
		value := hex.EncodeToString(want)
		if encoding == "base64" {
			value = base64.StdEncoding.EncodeToString(want)
		}
		req, _, err := networkHTTPRequest(map[string]any{"url": "http://example.test/bytes", "method": "POST", "body": value, "encoding": encoding})
		if err != nil {
			t.Fatal(err)
		}
		var wire bytes.Buffer
		if err := req.Write(&wire); err != nil {
			t.Fatal(err)
		}
		parsed, err := http.ReadRequest(bufio.NewReader(&wire))
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(parsed.Body)
		if err != nil || !bytes.Equal(body, want) || parsed.ContentLength != int64(len(want)) {
			t.Fatalf("%s body=%x length=%d err=%v", encoding, body, parsed.ContentLength, err)
		}
	}
	for _, in := range []map[string]any{
		{"encoding": "hex", "body": "not hex"},
		{"encoding": "base64", "body": "AB=="},
		{"encoding": "hex", "body": strings.Repeat("ff", networkBodyLimit+1)},
	} {
		in["url"] = "http://example.test/"
		if _, _, err := networkHTTPRequest(in); err == nil {
			t.Fatal("invalid HTTP bytes accepted")
		}
	}
}

func TestTCPBinaryDelimiter(t *testing.T) {
	in := map[string]any{"target": "example.test:1234", "payload": "00ff", "encoding": "hex", "delimiter": "00ff", "delimiter_encoding": "hex"}
	c, err := networkExchangeConfig(in, true)
	if err != nil {
		t.Fatal(err)
	}
	got, complete, truncated, err := networkReadExchange(oneByteReader{bytes.NewReader([]byte{3, 0, 255, 4})}, c)
	if err != nil || !complete || truncated || !bytes.Equal(got, []byte{3, 0, 255}) {
		t.Fatalf("binary delimiter: %x %v %v %v", got, complete, truncated, err)
	}
	in["delimiter"] = "0"
	if _, err := networkExchangeConfig(in, true); err == nil {
		t.Fatal("accepted incomplete delimiter byte")
	}
}
