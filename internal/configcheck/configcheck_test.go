package configcheck

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type sample struct {
	Server struct {
		BindHost string `toml:"bind_host"`
		Port     int    `toml:"port"`
	} `toml:"server"`
	Logging struct {
		LogLevel string `toml:"log_level"`
	} `toml:"logging"`
	Limit int64 `toml:"limit"`
}

// TestDecodeRejectsUnsupportedKeys names the key a configuration file got
// wrong, whether it is a table, a key inside one, or a top-level key.
func TestDecodeRejectsUnsupportedKeys(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"table", "[metrics]\nport = 1\n", `unsupported configuration key "metrics"`},
		{"key in a table", "[server]\nbind_hosts = 'a'\n", `unsupported configuration key "server.bind_hosts"`},
		{"top-level key", "limits = 1\n", `unsupported configuration key "limits"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var target sample
			_, err := Decode([]byte(tc.body), &target)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("error %v, want %q", err, tc.want)
			}
		})
	}
}

// TestDecodeReportsMalformedValues keeps a type error attached to its key.
func TestDecodeReportsMalformedValues(t *testing.T) {
	var target sample
	_, err := Decode([]byte("[server]\nport = 'nine'\n"), &target)
	if err == nil || !strings.Contains(err.Error(), "Port") {
		t.Fatalf("malformed value: %v", err)
	}
	if _, err := Decode([]byte("[server\n"), &target); err == nil {
		t.Fatal("malformed document accepted")
	}
}

// TestDocumentSet separates a key a file omits from one it sets, including an
// explicit zero, which is what keeps a default from hiding an invalid value.
func TestDocumentSet(t *testing.T) {
	var target sample
	document, err := Decode([]byte("[server]\nport = 0\n[Logging]\nLog_Level = 'debug'\n"), &target)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, path := range [][]string{{"server"}, {"server", "port"}, {"logging", "log_level"}} {
		if !document.Set(path...) {
			t.Errorf("%v reported as omitted", path)
		}
	}
	for _, path := range [][]string{{"limit"}, {"server", "bind_host"}, {"server", "port", "deeper"}, {}} {
		if document.Set(path...) {
			t.Errorf("%v reported as set", path)
		}
	}
	if target.Server.Port != 0 || target.Logging.LogLevel != "debug" {
		t.Fatalf("decoded %+v", target)
	}
}

func TestPortAndEndpoint(t *testing.T) {
	for _, port := range []int{0, 1, 65535} {
		if err := Port("server.port", port); err != nil {
			t.Errorf("port %d: %v", port, err)
		}
	}
	for _, port := range []int{-1, 65536} {
		if err := Port("server.port", port); err == nil || !strings.Contains(err.Error(), "server.port") {
			t.Errorf("port %d: %v", port, err)
		}
	}
	for _, endpoint := range []string{"127.0.0.1:1", "localhost:9000", "[::1]:9001", "example.org:443"} {
		if err := Endpoint("dispatcher.addr", endpoint); err != nil {
			t.Errorf("endpoint %q: %v", endpoint, err)
		}
	}
	for _, endpoint := range []string{"", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:70000", "127.0.0.1:http", ":1"} {
		if err := Endpoint("dispatcher.addr", endpoint); err == nil || !strings.Contains(err.Error(), "dispatcher.addr") {
			t.Errorf("endpoint %q: %v", endpoint, err)
		}
	}
}

func TestHost(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "localhost", "example.org", "example.org.", "a-b.example"} {
		if err := Host("server.bind_host", host); err != nil {
			t.Errorf("host %q: %v", host, err)
		}
	}
	for _, host := range []string{"", "not a host", "-example.org", "example-.org", "exam/ple", strings.Repeat("a", 64) + ".org"} {
		if err := Host("server.bind_host", host); err == nil || !strings.Contains(err.Error(), "server.bind_host") {
			t.Errorf("host %q: %v", host, err)
		}
	}
}

// TestOriginHidesCredentials keeps a password an operator put in an origin out
// of the reported error.
func TestOriginHidesCredentials(t *testing.T) {
	for _, origin := range []string{"https://example.org", "http://127.0.0.1:9000"} {
		if err := Origin("cors.allowed_origins[0]", origin); err != nil {
			t.Errorf("origin %q: %v", origin, err)
		}
	}
	for _, origin := range []string{"", "example.org", "ftp://example.org", "https://example.org/app",
		"https://example.org?q=1", "https://example.org#top", "https://example.org:0"} {
		if err := Origin("cors.allowed_origins[0]", origin); err == nil || !strings.Contains(err.Error(), "cors.allowed_origins[0]") {
			t.Errorf("origin %q: %v", origin, err)
		}
	}
	err := Origin("cors.allowed_origins[0]", "https://operator:hunter2@example.org")
	if err == nil {
		t.Fatal("origin with credentials accepted")
	}
	if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "operator") {
		t.Fatalf("error repeats credentials: %v", err)
	}
	if err := Origin("cors.allowed_origins[0]", "https://%zz"); err == nil || strings.Contains(err.Error(), "%zz") {
		t.Fatalf("unparsable origin: %v", err)
	}
}

func TestPathAndFile(t *testing.T) {
	if err := Path("database.path", ".data/dispatcher.db"); err != nil {
		t.Errorf("path: %v", err)
	}
	for _, value := range []string{"", "   ", "a\x00b"} {
		if err := Path("database.path", value); err == nil || !strings.Contains(err.Error(), "database.path") {
			t.Errorf("path %q: %v", value, err)
		}
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "cert")
	if err := os.WriteFile(file, []byte("fixture material; no TLS handshake claimed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := File("tls.cert_file", file); err != nil {
		t.Errorf("file: %v", err)
	}
	for _, value := range []string{filepath.Join(dir, "absent"), dir} {
		if err := File("tls.cert_file", value); err == nil || !strings.Contains(err.Error(), "tls.cert_file") {
			t.Errorf("file %q: %v", value, err)
		}
	}
}

// TestIntervalBoundaries rejects a value that would wrap into a short or
// negative duration instead of the long one the operator asked for.
func TestIntervalBoundaries(t *testing.T) {
	if err := Seconds("tesla.delay", int64(math.MaxInt64/int64(time.Second))); err != nil {
		t.Errorf("largest convertible value: %v", err)
	}
	if err := Seconds("tesla.delay", math.MaxInt64); err == nil || !strings.Contains(err.Error(), "tesla.delay must be at most") {
		t.Errorf("overflow: %v", err)
	}
	if err := Seconds("tesla.delay", -1); err == nil || !strings.Contains(err.Error(), "must not be negative") {
		t.Errorf("negative: %v", err)
	}
	if err := Milliseconds("scheduler.scheduler_granularity_ms", int64(math.MaxInt64/int64(time.Millisecond))); err != nil {
		t.Errorf("largest convertible value: %v", err)
	}
	if err := Milliseconds("scheduler.scheduler_granularity_ms", math.MaxInt64); err == nil {
		t.Error("millisecond overflow accepted")
	}
}

func TestLogLevelAndLabel(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error", "dpanic", "panic", "fatal", "INFO"} {
		if err := LogLevel("logging.log_level", level); err != nil {
			t.Errorf("level %q: %v", level, err)
		}
	}
	for _, level := range []string{"", "chatty", "trace"} {
		if err := LogLevel("logging.log_level", level); err == nil || !strings.Contains(err.Error(), "logging.log_level") {
			t.Errorf("level %q: %v", level, err)
		}
	}
	if err := Label("identity.executor_id", "local-executor", 128); err != nil {
		t.Errorf("label: %v", err)
	}
	for _, value := range []string{"", "local executor", "local\texecutor", strings.Repeat("a", 129)} {
		if err := Label("identity.executor_id", value, 128); err == nil || !strings.Contains(err.Error(), "identity.executor_id") {
			t.Errorf("label %q: %v", value, err)
		}
	}
}
