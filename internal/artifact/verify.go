package artifact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
)

const GuestABI = "debuglet-go-wasi-imports-v1"
const Toolchain = "go1.25.11"
const ManifestPath = "share/debuglet/manifest.json"

var versionPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$`)
var shaPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// PayloadModes returns a fresh map, so callers cannot mutate the contract.
func PayloadModes() map[string]fs.FileMode {
	return map[string]fs.FileMode{
		"bin/dbl": 0755, "bin/debuglet-dispatcher": 0755, "bin/debuglet-executor": 0755,
		"share/debuglet/demo.wasm": 0644, "share/debuglet/hello.wasm": 0644,
		ManifestPath: 0644, "LICENSE": 0644, "README-install.md": 0644,
	}
}

func ValidVersion(version string) bool {
	return len(version) <= 128 && versionPattern.MatchString(version)
}
func ValidSourceSHA(sha string) bool { return shaPattern.MatchString(sha) }

// DecodeManifest is bounded, rejects duplicate and unknown keys, and validates
// metadata before any payload is opened. Hashes provide identity, not signatures.
func DecodeManifest(data []byte) (Manifest, error) {
	m, err := DecodeManifestMetadata(data)
	if err != nil {
		return m, err
	}
	modes := PayloadModes()
	delete(modes, ManifestPath)
	if len(m.Files) != len(modes) {
		return m, errors.New("installation manifest has an unexpected file set")
	}
	for name := range modes {
		f, ok := m.Files[name]
		if !ok || f.Bytes <= 0 || !digestPattern.MatchString(f.SHA256) {
			return m, fmt.Errorf("invalid installation file record: %s", name)
		}
	}
	return m, nil
}

// DecodeManifestMetadata validates metadata with an explicit file object. Build
// records use an empty object until the final payload manifest is assembled.
func DecodeManifestMetadata(data []byte) (Manifest, error) {
	var m Manifest
	if len(data) > 64*1024 {
		return m, errors.New("installation manifest exceeds 64 KiB")
	}
	if err := CheckUniqueJSON(data); err != nil {
		return m, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return m, err
	}
	if len(fields) != 10 {
		return m, errors.New("installation metadata must contain exactly the canonical keys")
	}
	for _, key := range []string{"schema_version", "version", "source_sha", "dirty", "go_version", "goos", "goarch", "guest_abi", "files", "build_pipeline_url"} {
		value, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return m, fmt.Errorf("installation manifest is missing %s", key)
		}
	}
	var fileRecords map[string]map[string]json.RawMessage
	if err := json.Unmarshal(fields["files"], &fileRecords); err != nil || fileRecords == nil {
		return m, errors.New("installation files must be an object")
	}
	for _, record := range fileRecords {
		if len(record) != 2 || record["sha256"] == nil || record["bytes"] == nil || bytes.Equal(bytes.TrimSpace(record["sha256"]), []byte("null")) || bytes.Equal(bytes.TrimSpace(record["bytes"]), []byte("null")) {
			return m, errors.New("installation file record must contain exact sha256 and bytes keys")
		}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return m, fmt.Errorf("decode installation manifest: %w", err)
	}
	if m.SchemaVersion != 1 || !ValidVersion(m.Version) || !ValidSourceSHA(m.SourceSHA) || m.Dirty || m.GoVersion != Toolchain || m.GOOS != "linux" || m.GOARCH != "amd64" || m.GuestABI != GuestABI {
		return m, errors.New("unsupported or incomplete installation identity")
	}
	return m, nil
}

// CheckUniqueJSON rejects duplicate object keys and extra JSON values.
func CheckUniqueJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	if err := uniqueValue(d); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("JSON contains trailing data")
	}
	return nil
}

func uniqueValue(d *json.Decoder) error {
	t, err := d.Token()
	if err != nil {
		return err
	}
	switch t {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := k.(string)
			if !ok {
				return errors.New("non-string object key")
			}
			if seen[key] {
				return errors.New("duplicate object key")
			}
			seen[key] = true
			if err := uniqueValue(d); err != nil {
				return err
			}
		}
		t, err = d.Token()
		if err != nil {
			return err
		}
		if t != json.Delim('}') {
			return errors.New("unclosed object")
		}
	case json.Delim('['):
		for d.More() {
			if err := uniqueValue(d); err != nil {
				return err
			}
		}
		t, err = d.Token()
		if err != nil {
			return err
		}
		if t != json.Delim(']') {
			return errors.New("unclosed array")
		}
	}
	return nil
}

// HashFile reads only a regular file and returns its current exact identity.
func HashFile(path string) (File, error) {
	var result File
	info, err := os.Lstat(path)
	if err != nil {
		return result, err
	}
	if !info.Mode().IsRegular() {
		return result, errors.New("payload must be a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return result, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return result, errors.New("payload changed while opening")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, info.Size()+1))
	if err != nil {
		return result, err
	}
	if n != info.Size() {
		return result, errors.New("payload size changed while hashing")
	}
	return File{SHA256: hex.EncodeToString(h.Sum(nil)), Bytes: n}, nil
}

// Verify requires the complete installed tree, with no additional members or
// symlinks. The selected root itself may be reached via a caller-resolved link.
func Verify(root string) (Manifest, error) {
	var m Manifest
	modes := PayloadModes()
	dirs := map[string]bool{".": true, "bin": true, "share": true, "share/debuglet": true}
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if entry.IsDir() {
			if !dirs[rel] {
				return fmt.Errorf("unexpected installation directory: %s", rel)
			}
			return nil
		}
		mode, ok := modes[rel]
		if !ok {
			return fmt.Errorf("unexpected installation file: %s", rel)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != mode || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return fmt.Errorf("invalid installation file type or mode: %s", rel)
		}
		seen[rel] = true
		return nil
	})
	if err != nil {
		return m, err
	}
	if len(seen) != len(modes) {
		return m, errors.New("installation is missing required files")
	}
	f, err := os.Open(filepath.Join(root, filepath.FromSlash(ManifestPath)))
	if err != nil {
		return m, err
	}
	data, readErr := io.ReadAll(io.LimitReader(f, 64*1024+1))
	closeErr := f.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return m, err
	}
	m, err = DecodeManifest(data)
	if err != nil {
		return m, err
	}
	for name, want := range m.Files {
		got, err := HashFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			return m, fmt.Errorf("verify %s: %w", name, err)
		}
		if got != want {
			return m, fmt.Errorf("installation checksum mismatch: %s", name)
		}
	}
	return m, nil
}
