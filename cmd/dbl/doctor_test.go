package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/artifact"
	executordb "github.com/netsec-ethz/debuglet/internal/executor/database"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
)

func TestDoctorInstalledPayload(t *testing.T) {
	root := t.TempDir()
	manifest := artifact.Manifest{
		SchemaVersion: 1, Version: "v0.2.0", SourceSHA: strings.Repeat("a", 40),
		GoVersion: artifact.Toolchain, GOOS: "linux", GOARCH: "amd64", GuestABI: artifact.GuestABI,
		Files: map[string]artifact.File{},
	}
	for name, mode := range artifact.PayloadModes() {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if name == artifact.ManifestPath {
			continue
		}
		if err := os.WriteFile(path, []byte(name), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		file, err := artifact.HashFile(path)
		if err != nil {
			t.Fatal(err)
		}
		manifest.Files[name] = file
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, artifact.ManifestPath), data, 0644); err != nil {
		t.Fatal(err)
	}
	if check := payloadCheck(filepath.Join(root, "bin", "dbl")); check.Status != "pass" {
		t.Fatalf("valid payload: %+v", check)
	}
	link := filepath.Join(t.TempDir(), "dbl")
	if err := os.Symlink(filepath.Join(root, "bin", "dbl"), link); err != nil {
		t.Fatal(err)
	}
	if check := payloadCheck(link); check.Status != "pass" {
		t.Fatalf("installed symlink: %+v", check)
	}
	if check := payloadCheck(filepath.Join(root, "bin", "debuglet-executor")); check.Status != "unavailable" {
		t.Fatalf("accepted non-CLI executable: %+v", check)
	}
	if err := os.WriteFile(filepath.Join(root, "bin", "dbl"), []byte("modified"), 0755); err != nil {
		t.Fatal(err)
	}
	if check := payloadCheck(link); check.Status != "unavailable" {
		t.Fatalf("accepted altered installation: %+v", check)
	}
}

func TestDoctorNetworkIsExplicitAndBounded(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusOK, map[string]string{"version": "fixture"})
	})
	fx := newFixture(t, mux)
	for _, network := range []bool{false, true} {
		args := []string{"--endpoint", fx.endpoint(), "--output", outputJSON, "doctor"}
		if network {
			args = append(args, "--connection")
		}
		_, out, errout := runCLI(context.Background(), args...)
		if errout != "" {
			t.Fatalf("unexpected error: %s", errout)
		}
		check := doctorResult(t, out, "dispatcher_connection")
		want, calls := "not_checked", 0
		if network {
			want, calls = "pass", 1
		}
		if check.Status != want || fx.total() != calls {
			t.Fatalf("check=%+v requests=%d", check, fx.total())
		}
	}
	slow := newFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	code, out, errout := runCLI(ctx, "--endpoint", slow.endpoint(), "--output", outputJSON, "doctor", "--connection")
	assertCode(t, code, exitDeadline, out, errout)
	if doctorResult(t, out, "dispatcher_connection").Status != "failure" {
		t.Fatal("unavailable dispatcher passed")
	}
}

func doctorResult(t *testing.T, output, id string) doctorCheck {
	t.Helper()
	var report doctorReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("invalid report: %v: %s", err, output)
	}
	seen := map[string]bool{}
	var found doctorCheck
	for _, check := range report.Checks {
		if seen[check.ID] {
			t.Fatalf("duplicate check ID %s", check.ID)
		}
		seen[check.ID] = true
		if check.ID == id {
			found = check
		}
	}
	if found.ID == "" {
		t.Fatalf("missing check %s: %s", id, output)
	}
	return found
}

func TestDoctorOfflineSchemaDoesNotWrite(t *testing.T) {
	for _, version := range []int64{1, sqlitedb.Latest} {
		dir := t.TempDir()
		path := filepath.Join(dir, "executor.sqlite")
		db, err := sqlitedb.Open(path, sqlitedb.Create())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sqlitedb.Migrate(context.Background(), db, executordb.MigrationFS(), version); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		check := schemaCheck(context.Background(), storagecheck.Executor, path)
		want := "pass"
		if version == 1 {
			want = "failure"
		}
		if check.Status != want {
			t.Fatalf("version=%d: %+v", version, check)
		}
		if version == 1 && !strings.Contains(check.Next, "-upgrade-database") {
			t.Fatalf("missing upgrade guidance: %+v", check)
		}
		after, _ := os.ReadFile(path)
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 1 || !bytes.Equal(before, after) {
			t.Fatal("doctor changed database or created sidecars")
		}
		if err := os.WriteFile(path+"-wal", []byte("active journal"), 0600); err != nil {
			t.Fatal(err)
		}
		if check := schemaCheck(context.Background(), storagecheck.Executor, path); check.Status != "not_checked" {
			t.Fatalf("ignored active WAL: %+v", check)
		}
		link := filepath.Join(t.TempDir(), "current.sqlite")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		if check := schemaCheck(context.Background(), storagecheck.Executor, link); check.Status != "not_checked" {
			t.Fatalf("ignored active WAL behind symlink: %+v", check)
		}
		wal, _ := os.ReadFile(path + "-wal")
		if string(wal) != "active journal" {
			t.Fatal("doctor changed WAL")
		}
	}
}

func TestDoctorConfigErrorsAreRedacted(t *testing.T) {
	path := writeOperatorConfig(t, "executor", "[logging]\nlog_level='SECRET-CONFIG'\n")
	for _, mode := range []string{outputHuman, outputJSON} {
		code, out, errout := runCLI(context.Background(), "--output", mode, "doctor", "--role", "executor", "--file", path)
		assertCode(t, code, exitFailure, out, errout)
		if strings.Contains(out+errout, "SECRET-CONFIG") {
			t.Fatal("configuration secret appeared in report")
		}
		if mode == outputJSON && doctorResult(t, out, "config").Status != "failure" {
			t.Fatal("invalid configuration passed")
		}
	}
}

func TestDoctorLiveSchemaRequiresOfflineSelection(t *testing.T) {
	path := writeOperatorConfig(t, "executor", "[network]\npacket_counter='fallback'\n")
	_, out, _ := runCLI(context.Background(), "--output", outputJSON, "doctor", "--role", "executor", "--file", path)
	if check := doctorResult(t, out, "schema"); check.Status != "not_checked" || !strings.Contains(check.Next, "--offline") {
		t.Fatalf("unexpected schema check: %+v", check)
	}
}

func TestDoctorCertificateRenewalGuidance(t *testing.T) {
	for _, tc := range []struct {
		name, role string
		days       int
		status     string
		renewal    bool
	}{
		{"not due", "executor", 30, "pass", false},
		{"due soon", "executor", 13, "pass", true},
		{"dispatcher", "dispatcher", 13, "pass", true},
		{"expired", "executor", -1, "failure", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert, key := doctorCertificate(t, time.Now().Add(time.Duration(tc.days)*24*time.Hour))
			check := certificateCheck(tc.role, false, cert, key, "")
			if check.Status != tc.status || strings.Contains(check.Detail, "renewal is due") != tc.renewal {
				t.Fatalf("unexpected certificate result: %+v", check)
			}
			if strings.Contains(check.Next, "join --renew") != (tc.renewal && tc.role == "executor") {
				t.Fatalf("incorrect role-specific renewal advice: %+v", check)
			}
			if tc.renewal && !strings.Contains(check.Next, "actual control handshake") {
				t.Fatalf("renewal reminder lost trust-verification limitation: %+v", check)
			}
		})
	}
	cert, key := doctorCertificate(t, time.Now().Add(13*24*time.Hour))
	expiredCA, _ := doctorCertificate(t, time.Now().Add(-time.Hour))
	check := certificateCheck("executor", false, cert, key, expiredCA)
	if check.Status != "failure" || !strings.Contains(check.Detail, "CA bundle") || strings.Contains(check.Next, "join --renew") {
		t.Fatalf("CA failure incorrectly recommends leaf-only renewal: %+v", check)
	}
	if check := certificateCheck("executor", true, cert, key, expiredCA); check.Status != "not_checked" {
		t.Fatalf("disabled TLS checked certificate: %+v", check)
	}
}

func doctorCertificate(t *testing.T, expires time.Time) (string, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-30 * 24 * time.Hour), NotAfter: expires,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	cert, key := filepath.Join(t.TempDir(), "certificate.pem"), filepath.Join(t.TempDir(), "private.pem")
	for path, block := range map[string]*pem.Block{cert: {Type: "CERTIFICATE", Bytes: der}, key: {Type: "PRIVATE KEY", Bytes: keyDER}} {
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return cert, key
}

func TestDoctorReportsIsolationWithoutClaimingRuntimeReadiness(t *testing.T) {
	for _, profile := range []string{"", "trusted", "shared"} {
		t.Run(profile, func(t *testing.T) {
			extra := "[isolation]\nprofile='" + profile + "'\n"
			if profile == "shared" {
				extra += `cgroup_root='/unavailable-doctor-fixture'
node_memory_bytes=536870912
node_cpu_quota_us=100000
node_pids=128
control_memory_reserve_bytes=134217728
control_cpu_reserve_us=25000
compile_memory_bytes=268435456
compile_cpu_quota_us=50000
compile_wall_ms=10000
compile_concurrency=1
run_memory_bytes=268435456
run_cpu_quota_us=50000
run_wall_ms=30000
worker_pids=64
memory_pages=1024
`
			}
			path := writeOperatorConfig(t, "executor", extra)
			_, out, _ := runCLI(context.Background(), "--output", outputJSON, "doctor", "--role", "executor", "--file", path)
			check := doctorResult(t, out, "isolation")
			if check.Status != "not_checked" || check.Next == "" {
				t.Fatalf("configuration was treated as proof of isolation: %+v", check)
			}
			if profile == "shared" && !strings.Contains(check.Detail, "runtime enforcement was not checked") {
				t.Fatalf("shared profile lacks its runtime limitation: %+v", check)
			}
			if profile != "shared" && !strings.Contains(check.Detail, "without hard CPU or process-memory limits") {
				t.Fatalf("trusted profile lacks its isolation limitation: %+v", check)
			}
		})
	}
}
