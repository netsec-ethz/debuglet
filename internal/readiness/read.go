package readiness

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"unicode/utf8"
)

// MaxRecordSize bounds the bytes Read accepts from one readiness file.
const MaxRecordSize = 4 << 10

// Read reads one published readiness record and checks it against the process
// that was supposed to publish it. The record is evidence that the daemon
// reached its own ready point: an existing process, or a service manager that
// merely created one, proves nothing on its own.
//
// An empty executorID expects a dispatcher record: exactly schema_version, pid,
// http_addr and grpc_addr, with both addresses on 127.0.0.1 and a port from 1
// to 65535. A nonempty executorID expects an executor record: exactly
// schema_version, pid and executor_id, carrying that identity. Any other or
// repeated field, a null value, trailing data, a schema version other than 1 or
// a PID other than pid refuses the record.
//
// A missing record is reported as os.ErrNotExist so a caller can keep waiting
// for it. The path must name a regular file of at most MaxRecordSize bytes; a
// symlink, FIFO or device is refused without being opened.
func Read(path string, pid int, executorID string) (Record, error) {
	data, err := readRegular(path, MaxRecordSize)
	if err != nil {
		return Record{}, err
	}
	fields := []string{"schema_version", "pid", "http_addr", "grpc_addr"}
	if executorID != "" {
		fields = []string{"schema_version", "pid", "executor_id"}
	}
	if err := exactFields(data, fields); err != nil {
		return Record{}, fmt.Errorf("invalid ready record: %w", err)
	}
	var record Record
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&record); err != nil {
		return record, fmt.Errorf("invalid ready record: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return record, errors.New("trailing ready record data")
	}
	if record.SchemaVersion != 1 || pid <= 0 || record.PID != pid {
		return record, errors.New("ready record schema/PID does not match launched child")
	}
	if executorID == "" {
		if record.ExecutorID != "" {
			return record, errors.New("dispatcher ready record has executor identity")
		}
		if err := loopbackAddress(record.HTTPAddr); err != nil {
			return record, err
		}
		if err := loopbackAddress(record.GRPCAddr); err != nil {
			return record, err
		}
	} else if record.ExecutorID != executorID || record.HTTPAddr != "" || record.GRPCAddr != "" {
		return record, errors.New("executor ready record does not match launched identity")
	}
	return record, nil
}

// loopbackAddress accepts the only spelling a daemon publishes for a listener
// it bound on the loopback interface: 127.0.0.1 with a nonzero port.
func loopbackAddress(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return errors.New("ready address is not host:port")
	}
	p, err := strconv.Atoi(port)
	if host != "127.0.0.1" || err != nil || p < 1 || p > 65535 {
		return errors.New("ready address must be 127.0.0.1 with a port from 1 to 65535")
	}
	return nil
}

// exactFields requires data to be one UTF-8 JSON object that names each of
// fields exactly once, names nothing else and gives none of them a null value.
func exactFields(data []byte, fields []string) error {
	invalid := errors.New("record must be one JSON object with exactly the expected fields")
	if !utf8.Valid(data) {
		return invalid
	}
	want := make(map[string]bool, len(fields))
	for _, field := range fields {
		want[field] = true
	}
	seen := make(map[string]bool, len(fields))
	d := json.NewDecoder(bytes.NewReader(data))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return invalid
	}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || !want[key] || seen[key] {
			return invalid
		}
		seen[key] = true
		var value json.RawMessage
		if err := d.Decode(&value); err != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return invalid
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return invalid
	}
	if len(seen) != len(want) {
		return invalid
	}
	return nil
}

func readRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("%s is not a regular file within the %d-byte limit", filepath.Base(path), limit)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds the %d-byte limit", filepath.Base(path), limit)
	}
	return data, nil
}
