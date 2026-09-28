package artifact

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func installedFixture(t *testing.T) (string, Manifest) {
	t.Helper()
	return installedComponentFixture(t, "")
}

func installedComponentFixture(t *testing.T, component string) (string, Manifest) {
	t.Helper()
	root := t.TempDir()
	m := Manifest{SchemaVersion: 1, Version: "v0.0.0-dev.123456abcdef", SourceSHA: strings.Repeat("a", 40), GoVersion: Toolchain, GOOS: "linux", GOARCH: "amd64", GuestABI: GuestABI, Files: map[string]File{}}
	if component != "" {
		m.SchemaVersion, m.Component = 2, component
	}
	for name, mode := range PayloadModesFor(component) {
		if name == ManifestPath {
			continue
		}
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fixture "+name), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		f, err := HashFile(path)
		if err != nil {
			t.Fatal(err)
		}
		m.Files[name] = f
	}
	writeManifest(t, root, m)
	return root, m
}
func writeManifest(t *testing.T, root string, m Manifest) {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "share", "debuglet"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(ManifestPath)), data, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, filepath.FromSlash(ManifestPath)), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyInstallation(t *testing.T) {
	t.Run("complete", func(t *testing.T) {
		root, want := installedFixture(t)
		got, err := Verify(root)
		if err != nil || got.SourceSHA != want.SourceSHA {
			t.Fatalf("verify: %+v %v", got, err)
		}
	})
	for _, tc := range []struct {
		name   string
		change func(*testing.T, string, *Manifest)
	}{
		{"missing", func(t *testing.T, r string, m *Manifest) {
			if err := os.Remove(filepath.Join(r, "LICENSE")); err != nil {
				t.Fatal(err)
			}
		}},
		{"extra file", func(t *testing.T, r string, m *Manifest) {
			if err := os.WriteFile(filepath.Join(r, "extra"), nil, 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"extra directory", func(t *testing.T, r string, m *Manifest) {
			if err := os.Mkdir(filepath.Join(r, "extra"), 0700); err != nil {
				t.Fatal(err)
			}
		}},
		{"changed bytes", func(t *testing.T, r string, m *Manifest) {
			if err := os.WriteFile(filepath.Join(r, "LICENSE"), []byte("altered"), 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"changed mode", func(t *testing.T, r string, m *Manifest) {
			if err := os.Chmod(filepath.Join(r, "bin", "dbl"), 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink", func(t *testing.T, r string, m *Manifest) {
			p := filepath.Join(r, "LICENSE")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("README-install.md", p); err != nil {
				t.Fatal(err)
			}
		}},
		{"dirty", func(t *testing.T, r string, m *Manifest) { m.Dirty = true; writeManifest(t, r, *m) }},
		{"foreign architecture", func(t *testing.T, r string, m *Manifest) { m.GOARCH = "arm64"; writeManifest(t, r, *m) }},
		{"extra manifest path", func(t *testing.T, r string, m *Manifest) {
			m.Files["../outside"] = m.Files["LICENSE"]
			writeManifest(t, r, *m)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, m := installedFixture(t)
			tc.change(t, root, &m)
			if _, err := Verify(root); err == nil {
				t.Fatal("invalid installation accepted")
			}
		})
	}
}

func TestVerifyPriorToolchainInstallation(t *testing.T) {
	root, manifest := installedFixture(t)
	manifest.GoVersion = "go1.25.11"
	writeManifest(t, root, manifest)
	if _, err := Verify(root); err != nil {
		t.Fatalf("verify prior installation: %v", err)
	}
	manifest.GoVersion = "go1.24.0"
	writeManifest(t, root, manifest)
	if _, err := Verify(root); err == nil {
		t.Fatal("unsupported compiler accepted")
	}
}

func TestManifestDecoding(t *testing.T) {
	_, m := installedFixture(t)
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"duplicate", []byte(strings.Replace(string(data), `"dirty":false`, `"dirty":false,"dirty":true`, 1))},
		{"case alias override", []byte(strings.Replace(string(data), `"dirty":false`, `"dirty":true,"Dirty":false`, 1))},
		{"nested case alias", []byte(strings.Replace(string(data), `"bytes":`, `"Bytes":`, 1))},
		{"missing dirty", []byte(strings.Replace(string(data), `"dirty":false,`, "", 1))},
		{"null dirty", []byte(strings.Replace(string(data), `"dirty":false`, `"dirty":null`, 1))},
		{"unknown", append([]byte(`{"unknown":1,`), data[1:]...)},
		{"trailing", append(append([]byte{}, data...), []byte(` {}`)...)},
		{"oversized", []byte(strings.Repeat(" ", 64*1024+1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeManifest(tc.data); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
}

func TestVersionPathSafety(t *testing.T) {
	for _, v := range []string{"v1.2.3", "v1.2.3-rc.1", "v0.0.0-dev.abcdef123456"} {
		if !ValidVersion(v) {
			t.Errorf("rejected %q", v)
		}
	}
	for _, v := range []string{"../v1.2.3", "v1.2.3/evil", "v1.2.3\n", "v1.2.3;touch x", "v01.2.3", "v1.2.3-"} {
		if ValidVersion(v) {
			t.Errorf("accepted %q", v)
		}
	}
}

func TestVerifyComponentInstallation(t *testing.T) {
	for _, component := range []string{"cli", "executor", "dispatcher"} {
		t.Run(component, func(t *testing.T) {
			root, want := installedComponentFixture(t, component)
			got, err := Verify(root)
			if err != nil || got.Component != component || got.SourceSHA != want.SourceSHA {
				t.Fatalf("verify: %+v %v", got, err)
			}
			// A valid binary from another role is still an unexpected member.
			extra := "bin/dbl"
			if component == "cli" {
				extra = "bin/debuglet-executor"
			}
			if err := os.WriteFile(filepath.Join(root, extra), []byte("other role"), 0755); err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(root); err == nil {
				t.Fatal("accepted another component's payload")
			}
		})
	}
}

func TestComponentManifestSchema(t *testing.T) {
	_, m := installedComponentFixture(t, "cli")
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, old, replacement string }{
		{"unknown component", `"component":"cli"`, `"component":"other"`},
		{"null component", `"component":"cli"`, `"component":null`},
		{"missing component", `"component":"cli",`, ``},
		{"empty component", `"component":"cli"`, `"component":""`},
		{"legacy schema with component", `"schema_version":2`, `"schema_version":1`},
		{"component case alias", `"component":"cli"`, `"Component":"cli"`},
		{"wrong component file set", `"component":"cli"`, `"component":"executor"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := strings.Replace(string(data), tc.old, tc.replacement, 1)
			if changed == string(data) {
				t.Fatal("fixture mutation had no effect")
			}
			if _, err := DecodeManifest([]byte(changed)); err == nil {
				t.Fatal("accepted invalid component manifest")
			}
		})
	}
}
