package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"reflect"
	"strings"

	"github.com/netsec-ethz/debuglet/internal/configcheck"
	dispatcherconfig "github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	executorconfig "github.com/netsec-ethz/debuglet/internal/executor/config"
)

const configUsage = `Usage:
  dbl [--output human|json] config --role dispatcher|executor --file FILE

Validate using the daemon's configuration rules and show nonsecret settings.
Origins are configured, default, or startup (host discovery deferred).
Credential fields are omitted. URL credentials, queries and fragments are removed.
No daemon, database or network connection is opened, and no file is rewritten.
`

type configSetting struct {
	Key    string `json:"key"`
	Value  any    `json:"value"`
	Origin string `json:"origin"`
}

type daemonConfig struct {
	dispatcher *dispatcherconfig.DispatcherConfig
	executor   *executorconfig.ExecutorConfig
	document   configcheck.Document
}

func configCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer) int {
	fs := newCommandFlagSet("config")
	role := fs.String("role", "", "dispatcher or executor")
	file := fs.String("file", "", "daemon TOML file")
	if code, ok := parseCommandFlags(fs, args, configUsage, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() != 0 || (*role != "dispatcher" && *role != "executor") || *file == "" {
		return usageError("dbl config", configUsage, stderr, "supply --role dispatcher|executor and --file FILE")
	}
	cfg, err := readDaemonConfig(*role, *file)
	if err != nil {
		return reportFailure(ctx, "dbl config", stderr, err)
	}
	settings := cfg.settings()
	doc := struct {
		Role     string          `json:"role"`
		Settings []configSetting `json:"settings"`
	}{*role, settings}
	return emitReported(ctx, "dbl config", options.Output, stdout, stderr, doc, func(w io.Writer) error {
		for _, setting := range settings {
			value, err := json.Marshal(setting.Value)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "%s = %s (%s)\n", setting.Key, value, setting.Origin); err != nil {
				return err
			}
		}
		return nil
	})
}

func readDaemonConfig(role, path string) (daemonConfig, error) {
	var cfg daemonConfig
	data, err := readOperatorFile(path)
	if err != nil {
		return cfg, errors.New("cannot read configuration: use a readable regular TOML file no larger than 1 MiB")
	}
	switch role {
	case "dispatcher":
		cfg.dispatcher, cfg.document, err = dispatcherconfig.DecodeConfig(data)
	case "executor":
		cfg.executor, cfg.document, err = executorconfig.DecodeConfig(data)
	default:
		return cfg, errors.New("unknown daemon role")
	}
	if err != nil {
		// Parser and validator diagnostics can quote arbitrary configuration
		// values, including malformed credential URLs. Never print them here.
		return daemonConfig{}, errors.New("configuration is invalid: check TOML syntax, supported keys and required values")
	}
	return cfg, nil
}

func readOperatorFile(path string) ([]byte, error) {
	const limit = 1 << 20
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("expected a regular file no larger than 1 MiB")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if len(data) > limit {
		return nil, errors.New("file exceeds 1 MiB")
	}
	return data, err
}

func (cfg daemonConfig) settings() []configSetting {
	var value any = cfg.dispatcher
	if cfg.executor != nil {
		copy := *cfg.executor
		// These optional switches resolve in PolicyConfig.Spec at startup.
		policy := copy.Network.Policy.Spec()
		copy.Network.Policy.TCP, copy.Network.Policy.TLS = &policy.TCP, &policy.TLS
		copy.Network.Policy.UDP, copy.Network.Policy.ICMP = &policy.UDP, &policy.ICMP
		copy.Network.Policy.SCION, copy.Network.Policy.Inbound = &policy.SCION, &policy.Inbound
		copy.Network.Policy.LocalTargets = &policy.LocalTargets
		value = &copy
	}
	settings := []configSetting{}
	var visit func(reflect.Value, []string)
	visit = func(value reflect.Value, path []string) {
		if value.Kind() == reflect.Pointer {
			value = value.Elem()
		}
		if value.Kind() == reflect.Struct {
			for i := 0; i < value.NumField(); i++ {
				field := value.Type().Field(i)
				name, _, _ := strings.Cut(field.Tag.Get("toml"), ",")
				if name == "" {
					name = strings.ToLower(field.Name)
				}
				visit(value.Field(i), append(append([]string{}, path...), name))
			}
			return
		}
		key := strings.Join(path, ".")
		if strings.HasPrefix(key, "credentials.") || key == "tesla.seed" || key == "tls.key_file" || key == "sui.keystore_path" {
			return
		}
		origin := "default"
		if cfg.document.Set(path...) {
			origin = "configured"
		}
		result := value.Interface()
		switch text := result.(type) {
		case string:
			result = safeConfigText(text)
		case []string:
			redacted := make([]string, len(text))
			for i, item := range text {
				redacted[i] = safeConfigText(item)
			}
			result = redacted
		}
		if key == "network.interface" && cfg.executor != nil && cfg.executor.Network.Interface == "" && cfg.executor.Network.PacketCounter != "fallback" {
			origin, result = "startup", "automatic interface discovery deferred"
		}
		settings = append(settings, configSetting{Key: key, Value: result, Origin: origin})
	}
	visit(reflect.ValueOf(value), nil)
	return settings
}

func safeConfigText(value string) string {
	if !strings.Contains(value, "://") {
		if strings.Contains(value, "@") {
			return "[credential-bearing value omitted]"
		}
		return value
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "[invalid URL omitted]"
	}
	parsed.User, parsed.RawQuery, parsed.Fragment = nil, "", ""
	return parsed.String()
}
