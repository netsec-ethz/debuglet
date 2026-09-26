// Package connections stores explicitly named dispatcher connections for local
// commands. Saved profiles are not a global dispatcher discovery service.
package connections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/netsec-ethz/debuglet/internal/fsutil"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

type Profile struct {
	Name         string `json:"name"`
	Endpoint     string `json:"endpoint"`
	GRPCAddress  string `json:"grpc_address"`
	YamuxAddress string `json:"yamux_address"`
}

type Config struct {
	SchemaVersion int       `json:"schema_version"`
	Current       string    `json:"current"`
	Dispatchers   []Profile `json:"dispatchers"`
}

func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate client configuration; use --config FILE: %w", err)
	}
	return filepath.Join(dir, "debuglet", "config.json"), nil
}

func configPath(path string) (string, error) {
	if path == "" {
		return DefaultPath()
	}
	return path, nil
}

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

func ValidateName(name string) error {
	if !namePattern.MatchString(name) {
		return errors.New("connection name must be 1–64 letters, digits, dots, underscores or hyphens, starting with a letter or digit")
	}
	return nil
}

func validAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	n, portErr := strconv.Atoi(port)
	return err == nil && portErr == nil && n > 0 && n <= 65535 && ip != nil && ip.IsLoopback()
}

func validateProfile(profile Profile) error {
	if err := ValidateName(profile.Name); err != nil {
		return err
	}
	if _, err := client.New(profile.Endpoint, client.Options{}); err != nil {
		return fmt.Errorf("invalid saved endpoint: %w", err)
	}
	if (profile.GRPCAddress != "" || profile.YamuxAddress != "") && (!validAddress(profile.GRPCAddress) || !validAddress(profile.YamuxAddress)) {
		return errors.New("saved control addresses must both be literal loopback host:port values")
	}
	return nil
}

// Load returns an empty schema-1 configuration when the file does not exist.
func Load(path string) (Config, error) {
	empty := Config{SchemaVersion: 1, Dispatchers: []Profile{}}
	path, err := configPath(path)
	if err != nil {
		return Config{}, err
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return empty, nil
	}
	if err != nil {
		return Config{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return Config{}, errors.New("client configuration must be a regular file no larger than 1 MiB")
	}
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return Config{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return Config{}, errors.New("client configuration must be a regular file no larger than 1 MiB")
	}
	var cfg Config
	dec := json.NewDecoder(io.LimitReader(f, (1<<20)+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, errors.New("invalid client configuration JSON")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("trailing client configuration JSON")
	}
	if cfg.SchemaVersion != 1 {
		return Config{}, errors.New("unsupported client configuration schema")
	}
	seen := make(map[string]bool)
	for _, p := range cfg.Dispatchers {
		if err := validateProfile(p); err != nil {
			return Config{}, err
		}
		if seen[p.Name] {
			return Config{}, errors.New("duplicate saved dispatcher name")
		}
		seen[p.Name] = true
	}
	if cfg.Current != "" && !seen[cfg.Current] {
		return Config{}, errors.New("current dispatcher is not a saved connection")
	}
	if cfg.Dispatchers == nil {
		cfg.Dispatchers = []Profile{}
	}
	return cfg, nil
}

func write(path string, cfg Config) error {
	path, err := configPath(path)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return fsutil.WriteFile(path, append(data, '\n'), 0600)
}

// Save replaces a named profile chosen by the operator and selects it when
// requested, or when there is no current connection yet.
func Save(path string, profile Profile, selectCurrent bool) error {
	if err := validateProfile(profile); err != nil {
		return err
	}
	cfg, err := Load(path)
	if err != nil {
		return err
	}
	found := false
	for i, p := range cfg.Dispatchers {
		if p.Name == profile.Name {
			cfg.Dispatchers[i], found = profile, true
		}
	}
	if !found {
		cfg.Dispatchers = append(cfg.Dispatchers, profile)
	}
	if selectCurrent || cfg.Current == "" {
		cfg.Current = profile.Name
	}
	return write(path, cfg)
}

func Select(path, name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	cfg, err := Load(path)
	if err != nil {
		return err
	}
	for _, p := range cfg.Dispatchers {
		if p.Name == name {
			cfg.Current = name
			return write(path, cfg)
		}
	}
	return fmt.Errorf("no saved dispatcher named %q; use dbl dispatcher list or dbl connect URL", name)
}

func Remove(path, name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	cfg, err := Load(path)
	if err != nil {
		return err
	}
	for i, p := range cfg.Dispatchers {
		if p.Name == name {
			cfg.Dispatchers = append(cfg.Dispatchers[:i], cfg.Dispatchers[i+1:]...)
			if cfg.Current == name {
				cfg.Current = ""
			}
			return write(path, cfg)
		}
	}
	return fmt.Errorf("no saved dispatcher named %q", name)
}

func Resolve(path, name string) (Profile, error) {
	if name != "" {
		if err := ValidateName(name); err != nil {
			return Profile{}, err
		}
	}
	cfg, err := Load(path)
	if err != nil {
		return Profile{}, err
	}
	if name == "" {
		name = cfg.Current
	}
	for _, p := range cfg.Dispatchers {
		if p.Name == name {
			return p, nil
		}
	}
	return Profile{}, errors.New("no matching saved dispatcher; use dbl connect URL or --endpoint URL")
}

// Discover validates the server's announced local control listeners without
// reading or changing saved profiles. The caller chooses the profile name.
func Discover(ctx context.Context, endpoint string) (Profile, error) {
	c, err := client.New(endpoint, client.Options{})
	if err != nil {
		return Profile{}, err
	}
	info, err := c.Connection(ctx)
	if err != nil {
		return Profile{}, fmt.Errorf("dispatcher connection metadata unavailable; use a current local dispatcher with dbl dispatcher up: %w", err)
	}
	return Profile{Endpoint: endpoint, GRPCAddress: info.GRPCAddress, YamuxAddress: info.YamuxAddress}, nil
}
