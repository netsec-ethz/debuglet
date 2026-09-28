package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeOperatorConfig(t *testing.T, role, extra string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), role+".toml")
	body := "[tls]\ndisable=true\n[database]\npath='unopened.db'\n"
	if role == "executor" {
		body += "[identity]\nexecutor_id='fixture'\n[dispatcher]\naddr='127.0.0.1:9001'\n[resources]\ncapacity=1024\n"
	}
	if err := os.WriteFile(path, []byte(body+extra), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestConfigDefaultsOriginsAndNoWrites(t *testing.T) {
	for _, role := range []string{"dispatcher", "executor"} {
		t.Run(role, func(t *testing.T) {
			path := writeOperatorConfig(t, role, "[logging]\nlog_level='warn'\n")
			before, _ := os.ReadFile(path)
			code, out, errout := runCLI(context.Background(), "--output", outputJSON, "config", "--role", role, "--file", path)
			assertCode(t, code, exitOK, out, errout)
			var doc struct {
				Settings []configSetting `json:"settings"`
			}
			if err := json.Unmarshal([]byte(out), &doc); err != nil {
				t.Fatal(err)
			}
			settings := map[string]configSetting{}
			for _, setting := range doc.Settings {
				settings[setting.Key] = setting
			}
			if got := settings["logging.log_level"]; got.Origin != "configured" || got.Value != "warn" {
				t.Fatalf("configured origin: %+v", got)
			}
			if role == "executor" {
				if got := settings["resources.max_debuglets"]; got.Origin != "default" || got.Value != float64(100) {
					t.Fatalf("default origin: %+v", got)
				}
				if got := settings["network.interface"]; got.Origin != "startup" {
					t.Fatalf("host discovery was not deferred: %+v", got)
				}
				if got := settings["network.policy.tcp"]; got.Origin != "default" || got.Value != true {
					t.Fatalf("policy switch default not resolved: %+v", got)
				}
			} else if got := settings["scheduler.executor_timeout"]; got.Origin != "default" || got.Value != float64(60) {
				t.Fatalf("default origin: %+v", got)
			}
			after, _ := os.ReadFile(path)
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil || string(before) != string(after) || len(entries) != 1 {
				t.Fatal("inspection changed config or created state")
			}
		})
	}
}

func TestConfigSecretsAndInvalidValues(t *testing.T) {
	for _, mode := range []string{outputHuman, outputJSON} {
		for _, tc := range []struct {
			name, role, extra string
			valid             bool
		}{
			{"executor secrets", "executor", "[tesla]\nseed='SECRET-SEED'\n[credentials]\nclient_cert='unused-cert'\nenrollment_token='SECRET-TOKEN'\nclient_key='SECRET-KEY'\n", true},
			{"origin array credentials", "dispatcher", "[cors]\nallowed_origins=['https://SECRET-USER:SECRET-PASS@example.test']\n", false},
			{"URL credentials", "dispatcher", "[sui]\ndisabled=true\ngraphql_url='https://SECRET-USER:SECRET-PASS@example.test/graphql?token=SECRET-QUERY#SECRET-FRAGMENT'\nkeystore_path='SECRET-KEYSTORE'\n", true},
			{"invalid quoted value", "executor", "[logging]\nlog_level='SECRET-INVALID'\n", false},
			{"unknown key", "executor", "[SECRET-UNKNOWN]\nvalue='SECRET-VALUE'\n", false},
			{"invalid syntax", "executor", "[credentials]\nenrollment_token='SECRET-UNTERMINATED\n", false},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				path := writeOperatorConfig(t, tc.role, tc.extra)
				code, out, errout := runCLI(context.Background(), "--output", mode, "config", "--role", tc.role, "--file", path)
				want := exitFailure
				if tc.valid {
					want = exitOK
				}
				assertCode(t, code, want, out, errout)
				if strings.Contains(out+errout, "SECRET-") {
					t.Fatalf("configuration secret appeared in output: %s %s", out, errout)
				}
			})
		}
	}
}
