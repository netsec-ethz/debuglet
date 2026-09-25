// Package configcheck holds the checks both daemons apply to their
// configuration file before they open storage, bind listeners or acquire a
// packet counter. Every error names the configuration key that is wrong, so an
// operator can correct the file without reading a stack trace.
package configcheck

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
	"go.uber.org/zap/zapcore"
)

// Document records which keys a configuration file actually sets. Daemons use
// it to keep a documented default for an omitted key while still rejecting an
// explicit value that is out of range.
type Document struct {
	keys map[string]any
}

// Decode fills target from a TOML configuration file and reports which keys the
// file set. Keys the daemon does not support are rejected instead of ignored:
// a misspelled key otherwise looks like a setting that silently does nothing.
func Decode(data []byte, target any) (Document, error) {
	decoder := toml.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return Document{}, describe(err)
	}
	var keys map[string]any
	if err := toml.Unmarshal(data, &keys); err != nil {
		return Document{}, describe(err)
	}
	return Document{keys: keys}, nil
}

// describe turns a decoding failure into a message that names the key.
func describe(err error) error {
	var missing *toml.StrictMissingError
	if errors.As(err, &missing) && len(missing.Errors) > 0 {
		return fmt.Errorf("unsupported configuration key %q", strings.Join(missing.Errors[0].Key(), "."))
	}
	var decode *toml.DecodeError
	if errors.As(err, &decode) {
		if key := decode.Key(); len(key) > 0 {
			return fmt.Errorf("%s: %w", strings.Join(key, "."), decode)
		}
	}
	return fmt.Errorf("read configuration: %w", err)
}

// Set reports whether the configuration file contains the given key. Table and
// key names are matched the same way the decoder matches them to fields.
func (d Document) Set(path ...string) bool {
	table := d.keys
	for i, name := range path {
		value, ok := lookup(table, name)
		if !ok {
			return false
		}
		if i == len(path)-1 {
			return true
		}
		if table, ok = value.(map[string]any); !ok {
			return false
		}
	}
	return false
}

func lookup(table map[string]any, name string) (any, bool) {
	if value, ok := table[name]; ok {
		return value, true
	}
	for key, value := range table {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return nil, false
}

// Port accepts the documented listener range. Zero is kept: it asks the
// operating system for an unused port, which readiness then reports.
func Port(field string, port int) error {
	if port < 0 || port > 65535 {
		return fmt.Errorf("%s must be between 0 and 65535, got %d", field, port)
	}
	return nil
}

// Endpoint checks an address a daemon connects to, written as "host:port".
func Endpoint(field, endpoint string) error {
	if endpoint == "" {
		return fmt.Errorf("%s is required", field)
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return fmt.Errorf("%s must be a host:port address, got %q", field, endpoint)
	}
	if err := Host(field, host); err != nil {
		return err
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return fmt.Errorf("%s must use a port between 1 and 65535, got %q", field, port)
	}
	return nil
}

// Host checks an IP address literal or a DNS name.
func Host(field, host string) error {
	if host == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	if !dnsName(host) {
		return fmt.Errorf("%s must be an IP address or a DNS name, got %q", field, host)
	}
	return nil
}

func dnsName(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			letter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
			if !letter && (c < '0' || c > '9') && c != '-' && c != '_' {
				return false
			}
		}
	}
	return true
}

// Origin checks a browser origin: a scheme, a host and an optional port, with
// no path, query, fragment or credentials.
func Origin(field, origin string) error {
	parsed, err := url.Parse(origin)
	if err != nil {
		// The unparsed value is not repeated: it may carry credentials.
		return fmt.Errorf("%s must be an origin such as https://example.org", field)
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" ||
		parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%s must be scheme://host[:port] without a path, got %q", field, withoutCredentials(parsed))
	}
	if port := parsed.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return fmt.Errorf("%s must use a port between 1 and 65535, got %q", field, port)
		}
	}
	return Host(field, parsed.Hostname())
}

// withoutCredentials keeps a password in the file out of a reported origin.
func withoutCredentials(parsed *url.URL) string {
	if parsed.User == nil {
		return parsed.String()
	}
	redacted := *parsed
	redacted.User = url.User("redacted")
	return redacted.String()
}

// Path checks a filesystem path the daemon opens or creates.
func Path(field, path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%s is required", field)
	}
	if strings.ContainsRune(path, 0) {
		return fmt.Errorf("%s must not contain a null character", field)
	}
	return nil
}

// File checks a path that must already hold a regular file, such as a
// certificate the daemon reads at startup.
func File(field, path string) error {
	if err := Path(field, path); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular file, got %q", field, path)
	}
	return nil
}

// Seconds checks a configured number of seconds, keeping it inside the range
// that still converts to a time.Duration instead of wrapping into a short or
// negative interval.
func Seconds(field string, value int64) error {
	return interval(field, value, int64(time.Second), "seconds")
}

// Milliseconds is Seconds for a field documented in milliseconds.
func Milliseconds(field string, value int64) error {
	return interval(field, value, int64(time.Millisecond), "milliseconds")
}

func interval(field string, value, unit int64, name string) error {
	if value < 0 {
		return fmt.Errorf("%s must not be negative, got %d", field, value)
	}
	if limit := math.MaxInt64 / unit; value > limit {
		return fmt.Errorf("%s must be at most %d %s, got %d", field, limit, name, value)
	}
	return nil
}

// LogLevel checks a level name the logging subsystem accepts, so that a
// misspelled level fails instead of quietly falling back to info.
func LogLevel(field, level string) error {
	if level == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	var parsed zapcore.Level
	if err := parsed.UnmarshalText([]byte(level)); err != nil {
		return fmt.Errorf("%s must be debug, info, warn, error, dpanic, panic or fatal, got %q", field, level)
	}
	return nil
}

// Label checks a short printable identifier such as an executor name.
func Label(field, value string, maximum int) error {
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	if len(value) > maximum {
		return fmt.Errorf("%s must be at most %d characters, got %d", field, maximum, len(value))
	}
	for _, r := range value {
		if r <= ' ' || r == 0x7f {
			return fmt.Errorf("%s must not contain spaces or control characters, got %q", field, value)
		}
	}
	return nil
}
