package client

import (
	"errors"
	"strings"
	"testing"
)

func TestConnectionMetadata(t *testing.T) {
	const valid = `{"schema_version":1,"mode":"local-test","grpc_address":"127.0.0.1:9001","yamux_address":"[::1]:9000"}`
	for _, tc := range []struct {
		name   string
		status int
		body   string
		ok     bool
	}{
		{"valid", 200, valid, true},
		{"missing", 200, `{}`, false},
		{"null", 200, `null`, false},
		{"future schema", 200, strings.Replace(valid, `:1,`, `:2,`, 1), false},
		{"other mode", 200, strings.Replace(valid, "local-test", "remote", 1), false},
		{"hostname", 200, strings.Replace(valid, "127.0.0.1", "localhost", 1), false},
		{"remote", 200, strings.Replace(valid, "127.0.0.1", "192.0.2.1", 1), false},
		{"missing port", 200, strings.Replace(valid, ":9001", "", 1), false},
		{"zero port", 200, strings.Replace(valid, ":9001", ":0", 1), false},
		{"large port", 200, strings.Replace(valid, ":9001", ":65536", 1), false},
		{"trailing JSON", 200, valid + `{}`, false},
		{"old server", 404, `{"message":"Not Found"}`, false},
		{"unexpected success", 201, valid, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeServer(t, "/api")
			f.handle("GET /connection", jsonHandler(tc.status, tc.body))
			info, err := f.client(t, Options{}).Connection(testContext(t))
			if (err == nil) != tc.ok {
				t.Fatalf("metadata: %+v %v", info, err)
			}
			if got := f.requests()[0]; got.Method != "GET" || got.Path != "/api/connection" {
				t.Fatalf("unexpected route: %s %s", got.Method, got.Path)
			}
			if tc.ok && (info.GRPCAddress != "127.0.0.1:9001" || info.YamuxAddress != "[::1]:9000") {
				t.Fatalf("changed listeners: %+v", info)
			}
			if tc.status != 200 {
				var status *HTTPError
				if !errors.As(err, &status) || status.StatusCode != tc.status || status.Path != "/api/connection" {
					t.Fatalf("lost HTTP identity: %v", err)
				}
			}
		})
	}
}
