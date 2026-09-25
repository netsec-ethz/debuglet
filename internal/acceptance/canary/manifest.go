package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"

	"github.com/netsec-ethz/debuglet/internal/artifact"
	"github.com/netsec-ethz/debuglet/internal/demo"
)

const manifestSizeLimit = 64 << 10

// LoadManifest validates the complete local input before returning it. Neither
// filenames nor decoder errors (which can quote input) enter its diagnostics.
func LoadManifest(path string) (Manifest, error) {
	f, err := openManifestFile(path)
	if err != nil {
		return Manifest{}, errors.New("cannot open regular local manifest")
	}
	data, readErr := io.ReadAll(io.LimitReader(f, manifestSizeLimit+1))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil || len(data) > manifestSizeLimit {
		return Manifest{}, errors.New("cannot read local manifest within 64 KiB")
	}
	fields, err := strictFields(data, []string{"schema_version", "environment", "operator", "executor_id", "api_base_url", "control", "target", "limits", "deployment_record"}, nil, nil)
	if err != nil {
		return Manifest{}, errors.New("invalid local manifest object")
	}
	for _, nested := range []struct {
		name string
		keys []string
	}{
		{"control", []string{"grpc_addr", "yamux_addr", "protection"}},
		{"target", []string{"host"}},
		{"limits", []string{"execution_ms", "ceiling_bps", "attempt_ms"}},
	} {
		if _, err := strictFields(fields[nested.name], nested.keys, nil, nil); err != nil {
			return Manifest{}, errors.New("invalid local manifest fields")
		}
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return Manifest{}, errors.New("invalid local manifest field types")
	}
	digest := sha256.Sum256(data)
	manifest.SourceSHA256 = hex.EncodeToString(digest[:])
	if err := validateLocalManifest(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// Validate checks values and supplied installation metadata only. Run owns
// re-resolution of the installed files before any subprocess or network action.
func Validate(manifest Manifest, assets demo.Assets) error {
	if err := validateLocalManifest(manifest); err != nil {
		return err
	}
	data, err := json.Marshal(assets.Manifest)
	if err != nil {
		return errors.New("invalid installed candidate metadata")
	}
	if _, err := artifact.DecodeManifest(data); err != nil {
		return errors.New("invalid installed candidate metadata")
	}
	return nil
}

func validateLocalManifest(m Manifest) error {
	if m.SchemaVersion != 1 || m.Environment != "local" {
		return errors.New("manifest requires schema 1 and the local environment")
	}
	if m.APIBaseURL != "" || m.Control.GRPCAddr != "" || m.Control.YamuxAddr != "" || m.Control.Protection != "owned-loopback" || m.DeploymentRecord != "" || m.Target.Host != "127.0.0.1" {
		return errors.New("manifest requires generated owned loopback endpoints")
	}
	if !validOwnerLabel(m.Operator) {
		return errors.New("manifest operator must be a 1-64 character local owner label")
	}
	if !canonicalUUID(m.ExecutorID) {
		return errors.New("manifest executor_id must be a canonical nonzero lowercase UUID")
	}
	if m.Limits.ExecutionMS < 1 || m.Limits.ExecutionMS > 15_000 || m.Limits.CeilingBPS < 64_000 || m.Limits.CeilingBPS > 1_000_000 || m.Limits.AttemptMS < 1 || m.Limits.AttemptMS > 180_000 || m.Limits.AttemptMS-m.Limits.ExecutionMS < 20_000 {
		return errors.New("manifest limits are outside the local execution bounds")
	}
	if !lowerHex(m.SourceSHA256, 64) {
		return errors.New("manifest original-byte SHA256 is missing or invalid")
	}
	return nil
}

func validOwnerLabel(label string) bool {
	if len(label) < 1 || len(label) > 64 {
		return false
	}
	for i := range label {
		c := label[i]
		alphanumeric := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !alphanumeric && (i == 0 || c != ' ' && c != '_' && c != '.' && c != '-') {
			return false
		}
	}
	return true
}

// strictFields uses exact decoded keys, so encoding/json's case-insensitive
// field aliases cannot slip through. Values are bounded by the caller; nested
// objects have their own explicit schema. A key listed in nullable may carry
// null; every other required key may not. No parser diagnostic is returned.
func strictFields(data []byte, required, optional []string, nullable map[string]bool) (map[string]json.RawMessage, error) {
	invalid := errors.New("invalid JSON object")
	if !utf8.Valid(data) {
		return nil, invalid
	}
	allowed := make(map[string]bool, len(required)+len(optional))
	for _, key := range append(append([]string{}, required...), optional...) {
		allowed[key] = true
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil, invalid
	}
	fields := make(map[string]json.RawMessage, len(allowed))
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || !allowed[key] || fields[key] != nil {
			return nil, invalid
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil || !nullable[key] && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, invalid
		}
		fields[key] = value
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return nil, invalid
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return nil, invalid
	}
	for _, key := range required {
		if fields[key] == nil {
			return nil, invalid
		}
	}
	return fields, nil
}
