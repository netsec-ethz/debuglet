package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeConfig stores body as a TOML file in a per-test temporary directory and
// returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dispatcher.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// baseSections carries the keys every dispatcher configuration must set.
const baseSections = `
[tls]
disable = true

[database]
path = ".data/dispatcher.db"
`

const commonSections = baseSections + `
[server]
version = "test"
http_port = 9000
grpc_port = 9001
`

// TestSuiDisabledFlag checks that SuiConfig.Disabled is parsed from the
// explicit "disabled" key only: an omitted [sui] section and an explicit
// false both keep enabled semantics, and a true flag round-trips even when
// stale chain fields are still present.
func TestSuiDisabledFlag(t *testing.T) {
	// Deliberately unusable nonempty chain fields. Nothing must read them;
	// the keystore path does not exist.
	stalePath := filepath.Join(t.TempDir(), "does-not-exist", "sui.keystore")
	staleFields := `
network = "testnet"
grpc_endpoint = "fullnode.invalid:443"
graphql_url = "https://graphql.invalid/graphql"
address = "0xdead"
payment_registry_id = "0xregistry"
payment_kit_package = "0xpackage"
keystore_path = "` + stalePath + `"
`

	cases := []struct {
		name     string
		sui      string // the [sui] section, or "" for none
		disabled bool
		want     SuiConfig
	}{
		{
			name:     "sui section omitted",
			sui:      "",
			disabled: false,
			want:     SuiConfig{},
		},
		{
			name:     "disabled false",
			sui:      "[sui]\ndisabled = false\n" + staleFields,
			disabled: false,
		},
		{
			name:     "disabled true with blank chain fields",
			sui:      "[sui]\ndisabled = true\n",
			disabled: true,
			want:     SuiConfig{Disabled: true},
		},
		{
			name:     "disabled true with stale chain fields",
			sui:      "[sui]\ndisabled = true\n" + staleFields,
			disabled: true,
		},
		{
			name:     "disabled key omitted with chain fields",
			sui:      "[sui]\n" + staleFields,
			disabled: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadConfig(writeConfig(t, commonSections+tc.sui))
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			if cfg.Sui.Disabled != tc.disabled {
				t.Fatalf("Sui.Disabled = %v, want %v", cfg.Sui.Disabled, tc.disabled)
			}
			// Unrelated sections still load.
			if cfg.Server.Version != "test" || cfg.Server.HTTPPort != 9000 || cfg.Database.Path != ".data/dispatcher.db" {
				t.Fatalf("unexpected common sections: %+v", cfg)
			}
			if tc.sui == "" || tc.sui == "[sui]\ndisabled = true\n" {
				if cfg.Sui != tc.want {
					t.Fatalf("Sui = %+v, want %+v", cfg.Sui, tc.want)
				}
				return
			}
			// The stale fields round-trip unchanged regardless of the flag;
			// ignoring them in disabled mode is the payment layer's job.
			want := SuiConfig{
				Network:           "testnet",
				GRPCEndpoint:      "fullnode.invalid:443",
				GraphQLURL:        "https://graphql.invalid/graphql",
				Address:           "0xdead",
				PaymentRegistryId: "0xregistry",
				PaymentKitPackage: "0xpackage",
				KeystorePath:      stalePath,
				Disabled:          tc.disabled,
			}
			if cfg.Sui != want {
				t.Fatalf("Sui = %+v, want %+v", cfg.Sui, want)
			}
			if _, err := os.Stat(cfg.Sui.KeystorePath); !os.IsNotExist(err) {
				t.Fatalf("stale keystore path unexpectedly exists: %v", err)
			}
		})
	}
}

// TestSuiDisabledRejectsNonBoolean makes sure a malformed flag is a load
// error rather than silently enabled/disabled.
func TestSuiDisabledRejectsNonBoolean(t *testing.T) {
	_, err := LoadConfig(writeConfig(t, commonSections+"[sui]\ndisabled = \"yes\"\n"))
	if err == nil {
		t.Fatalf("LoadConfig accepted a non-boolean disabled flag")
	}
}

func TestBindHostConfig(t *testing.T) {
	for _, host := range []string{"", "127.0.0.1"} {
		t.Run(host, func(t *testing.T) {
			body := baseSections + "[server]\nhttp_port=0\ngrpc_port=0\n"
			if host != "" {
				body += "bind_host='" + host + "'\n"
			}
			cfg, err := LoadConfig(writeConfig(t, body))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Server.BindHost != host || cfg.Server.HTTPPort != 0 || cfg.Server.GRPCPort != 0 {
				t.Fatalf("server config: %+v", cfg.Server)
			}
		})
	}
}
