// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestHTTPRequestPreservesBodyAndHeaders(t *testing.T) {
	for _, body := range []string{"", "  text\n", `{"message":"Grüezi ☀"}`} {
		t.Run(body, func(t *testing.T) {
			req, _, err := networkHTTPRequest(map[string]any{
				"url": "http://example.test:8080/echo?kind=json", "method": "POST", "body": body,
				"headers": map[string]any{"content-type": "application/json", "X-Experiment": "sample"},
			})
			if err != nil {
				t.Fatal(err)
			}
			var wire bytes.Buffer
			if err = req.Write(&wire); err != nil {
				t.Fatal(err)
			}
			if strings.Count(strings.ToLower(wire.String()), "\r\ncontent-length:") != 1 {
				t.Fatal("request did not contain exactly one generated Content-Length")
			}
			parsed, err := http.ReadRequest(bufio.NewReader(&wire))
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(parsed.Body)
			if err != nil || string(got) != body || parsed.ContentLength != int64(len(body)) {
				t.Fatalf("body=%q length=%d error=%v", got, parsed.ContentLength, err)
			}
			if parsed.Method != "POST" || parsed.RequestURI != "/echo?kind=json" || parsed.Host != "example.test:8080" || len(parsed.TransferEncoding) != 0 {
				t.Fatalf("unexpected request: %#v", parsed)
			}
			if parsed.Header.Get("Content-Type") != "application/json" || parsed.Header.Get("X-Experiment") != "sample" || parsed.Header.Get("Accept-Encoding") != "identity" || !parsed.Close {
				t.Fatalf("headers = %#v, close=%v", parsed.Header, parsed.Close)
			}
		})
	}
}

func TestHTTPRequestRejectsInvalidAndManagedHeaders(t *testing.T) {
	cases := map[string]map[string]any{
		"body type":             {"body": map[string]any{}},
		"body limit":            {"body": strings.Repeat("x", networkBodyLimit+1)},
		"header type":           {"headers": "x=y"},
		"header value type":     {"headers": map[string]any{"X-Test": []any{"a", "b"}}},
		"header name":           {"headers": map[string]any{"X Test": "x"}},
		"header injection":      {"headers": map[string]any{"X-Test": "x\r\nHost: other.test"}},
		"header null":           {"headers": map[string]any{"X-Test": "x\x00y"}},
		"header case collision": {"headers": map[string]any{"X-Test": "a", "x-test": "b"}},
		"header limit":          {"headers": map[string]any{"X-Test": strings.Repeat("x", networkBodyLimit)}},
	}
	for _, name := range []string{"Host", "Content-Length", "Transfer-Encoding", "Connection", "Proxy-Connection", "Keep-Alive", "TE", "Trailer", "Upgrade", "Expect", "Accept-Encoding"} {
		cases[name] = map[string]any{"headers": map[string]any{name: "override"}}
	}
	for name, inputs := range cases {
		t.Run(name, func(t *testing.T) {
			inputs["url"] = "http://example.test/"
			if request, _, err := networkHTTPRequest(inputs); err == nil || request != nil {
				t.Fatalf("invalid request accepted: %v %v", request, err)
			}
		})
	}
}

func TestHTTPResponseHeadersRemainStructured(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	wire := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nX-Measurement: sample\r\n\r\nok"
	status, body, headers, err := networkReadHTTP(strings.NewReader(wire), req)
	if err != nil || status != 200 || body != "ok" {
		t.Fatalf("response status=%d body=%q error=%v", status, body, err)
	}
	if !reflect.DeepEqual(headers["set-cookie"], []any{"a=1", "b=2"}) || !reflect.DeepEqual(headers["x-measurement"], []any{"sample"}) {
		t.Fatalf("headers = %#v", headers)
	}
	wire = "HTTP/1.1 200 OK\r\nX-Large: " + strings.Repeat("x", networkBodyLimit) + "\r\nContent-Length: 2\r\n\r\nok"
	status, body, headers, err = networkReadHTTP(strings.NewReader(wire), req)
	if err == nil || status != 200 || body != "" || len(headers) != 0 {
		t.Fatalf("oversized headers accepted: status=%d body=%q headers=%d error=%v", status, body, len(headers), err)
	}
}

func TestHTTPHeaderCountAndBodyBoundaries(t *testing.T) {
	request, _, err := networkHTTPRequest(map[string]any{"url": "http://example.test/", "body": strings.Repeat("x", networkBodyLimit)})
	if err != nil || request.ContentLength != networkBodyLimit {
		t.Fatalf("body at limit was rejected: %v", err)
	}
	for _, count := range []int{64, 65} {
		headers := map[string]any{}
		var wire strings.Builder
		wire.WriteString("HTTP/1.1 200 OK\r\n")
		for i := 0; i < count; i++ {
			name := fmt.Sprintf("X-Value-%d", i)
			headers[name] = "v"
			fmt.Fprintf(&wire, "%s: v\r\n", name)
		}
		wire.WriteString("\r\nok")
		_, _, requestErr := networkHTTPRequest(map[string]any{"url": "http://example.test/", "headers": headers})
		_, _, _, responseErr := networkReadHTTP(strings.NewReader(wire.String()), request)
		wantError := count > 64
		if (requestErr != nil) != wantError || (responseErr != nil) != wantError {
			t.Fatalf("%d headers: request=%v response=%v", count, requestErr, responseErr)
		}
	}
}
