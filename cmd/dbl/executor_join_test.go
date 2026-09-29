package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/demo/service"
	executorconfig "github.com/netsec-ethz/debuglet/internal/executor/config"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
)

const joinExecutorID = "6e937873-2b32-46c4-aa03-d075fcbac905"

type joinFixture struct {
	server         *httptest.Server
	caFile         string
	tokenFile      string
	executorBinary string
	requests       atomic.Int32
}

func TestExecutorJoinAdoptsManagedServiceWithoutReplacingState(t *testing.T) {
	fixture := newJoinFixture(t, nil)
	root := t.TempDir()
	state := service.StateDirectory(root, storagecheck.Executor, "worker")
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), fixture.args(state), &stdout, &stderr); code != exitOK {
		t.Fatalf("join exit %d: %s", code, stderr.String())
	}
	original := map[string][]byte{}
	for _, name := range []string{"service.toml", "executor.sqlite", "executor.key", "executor.crt", "ca.crt"} {
		data, err := os.ReadFile(filepath.Join(state, name))
		if err != nil {
			t.Fatal(err)
		}
		original[name] = data
	}
	manager := newRecordingManager()
	deps := serviceTestDependencies(t, manager, root)
	deps.lookup = func(string, string) (service.Account, error) { return service.Account{UID: 4242, GID: 4343}, nil }
	install := func(args ...string) int {
		stdout.Reset()
		stderr.Reset()
		return serviceCommandWith(context.Background(), args, globalOptions{Output: outputJSON}, &stdout, &stderr, deps)
	}
	args := []string{"install", "--role", "executor", "--enrolled-state", state, "--start=false"}
	for attempt := 0; attempt < 2; attempt++ {
		if code := install(args...); code != exitOK {
			t.Fatalf("install %d exit %d: %s", attempt, code, stderr.String())
		}
		var report service.Report
		if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if report.ExecutorID != joinExecutorID || !report.Enabled || report.Ready {
			t.Fatalf("unexpected service report: %+v", report)
		}
		if attempt == 1 && len(report.Changed) != 0 {
			t.Fatalf("repeat install changed service: %+v", report)
		}
	}
	record, err := service.ReadRecord(root, storagecheck.Executor, "worker")
	if err != nil || !record.Enrolled || record.ExecutorID != joinExecutorID || record.DispatcherGRPC != "dispatcher.example:9001" {
		t.Fatalf("enrolled record: %+v, %v", record, err)
	}
	unit, err := os.ReadFile(record.UnitPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"User=debuglet\n", "Group=debuglet\n", "NoNewPrivileges=yes\n", "CapabilityBoundingSet=\n", "Restart=always\n", "-config " + filepath.Join(state, "service.toml")} {
		if !strings.Contains(string(unit), expected) {
			t.Errorf("unit missing %q", expected)
		}
	}
	if code := install("install", "--role", "executor", "--start=false"); code != exitFailure || !strings.Contains(stderr.String(), "installation mode differs") {
		t.Fatalf("plain reinstall exit %d: %s", code, stderr.String())
	}
	for name, want := range original {
		got, err := os.ReadFile(filepath.Join(state, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("adoption changed %s: %v", name, err)
		}
	}
	changed := bytes.ReplaceAll(original["service.toml"], []byte(joinExecutorID), []byte("00000000-1111-2222-3333-444444444444"))
	if err := os.WriteFile(record.ConfigPath, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if code := install(args...); code != exitFailure || !strings.Contains(stderr.String(), "changed executor identity") {
		t.Fatalf("changed identity exit %d: %s", code, stderr.String())
	}
	if err := os.WriteFile(record.ConfigPath, original["service.toml"], 0600); err != nil {
		t.Fatal(err)
	}
	deps.lookup = func(string, string) (service.Account, error) { return service.Account{UID: 0, GID: 0}, nil }
	if code := install(args...); code != exitFailure || !strings.Contains(stderr.String(), "unprivileged") {
		t.Fatalf("root account exit %d: %s", code, stderr.String())
	}
}

func newJoinFixture(t *testing.T, alter func(*executorJoinResponse)) *joinFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "enrollment CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	f := &joinFixture{}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}
	f.executorBinary = filepath.Join(filepath.Dir(executable), "debuglet-executor")
	// These command tests run in Go's isolated build directory. Create only
	// this fixture's absent sibling; never overwrite an installed daemon.
	stub, err := os.OpenFile(f.executorBinary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		t.Fatal(err)
	}
	if err := stub.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(f.executorBinary) })
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/api/executor-enrollment" || r.Header.Get("Debuglet-API-Version") != "1.10" {
			t.Errorf("unexpected enrollment request: %s %s version=%s", r.Method, r.URL.Path, r.Header.Get("Debuglet-API-Version"))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var req struct {
			ExecutorID string `json:"executor_id"`
			Token      string `json:"token"`
			CSR        string `json:"csr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if req.ExecutorID != joinExecutorID || req.Token != fixSecret {
			t.Error("wrong identity or token")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		block, _ := pem.Decode([]byte(req.CSR))
		if block == nil {
			t.Error("no CSR")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != joinExecutorID {
			t.Error("invalid CSR")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		leaf, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: csr.Subject, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, ca, csr.PublicKey, key)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		result := executorJoinResponse{ExecutorID: joinExecutorID, CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf})), CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), GRPCAddress: "dispatcher.example:9001", YamuxAddress: "dispatcher.example:9000"}
		if alter != nil {
			alter(&result)
		}
		json.NewEncoder(w).Encode(result)
	}))
	t.Cleanup(f.server.Close)
	f.caFile = filepath.Join(t.TempDir(), "server-ca.pem")
	if err := os.WriteFile(f.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	f.tokenFile = filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(f.tokenFile, []byte(fixSecret+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *joinFixture) args(state string) []string {
	return []string{"executor", "join", "--dispatcher", f.server.URL + "/api/", "--executor", joinExecutorID, "--state-dir", state, "--ca-file", f.caFile, "--token-file", f.tokenFile}
}

func TestExecutorJoinWritesUsablePrivateIdentity(t *testing.T) {
	fixture := newJoinFixture(t, nil)
	state := filepath.Join(t.TempDir(), "executor")
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), fixture.args(state), &stdout, &stderr); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if fixture.requests.Load() != 1 {
		t.Fatalf("requests = %d", fixture.requests.Load())
	}
	if strings.Contains(stdout.String()+stderr.String(), fixSecret) {
		t.Fatal("printed enrollment token")
	}
	if !strings.Contains(stdout.String(), roleShellWord(fixture.executorBinary)+" -config "+roleShellWord(filepath.Join(state, "service.toml"))) {
		t.Fatalf("missing start command: %s", stdout.String())
	}
	for _, name := range []string{"", "executor.key", "executor.crt", "ca.crt", "service.toml", "executor.sqlite"} {
		info, err := os.Stat(filepath.Join(state, name))
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0600)
		if name == "" {
			want = 0700
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s mode %o, want %o", name, info.Mode().Perm(), want)
		}
	}
	data, err := os.ReadFile(filepath.Join(state, "service.toml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, _, err := executorconfig.DecodeConfig(data)
	if err != nil {
		t.Fatalf("unusable config: %v", err)
	}
	if cfg.Identity.ExecutorID != joinExecutorID || cfg.TLS.Disable || cfg.Credentials.EnrollmentToken != "" || cfg.Pricing.Currency != "TEST" || cfg.Network.PacketCounter != "fallback" || cfg.Network.Policy.Spec().LocalTargets || cfg.Network.Policy.Spec().Inbound || cfg.Network.Policy.Spec().SCION {
		t.Fatalf("unexpected enrollment profile: %+v", cfg)
	}
	if cfg.Tesla.EpochSeconds != 30 || cfg.Tesla.Delay != 0 {
		t.Fatalf("unexpected TESLA epoch configuration: %+v", cfg.Tesla)
	}
	if _, err := tls.LoadX509KeyPair(cfg.Credentials.ClientCert, cfg.Credentials.ClientKey); err != nil {
		t.Fatal(err)
	}
	caData, err := os.ReadFile(cfg.Credentials.CACert)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caData)
	if _, err := fixture.server.Certificate().Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("bootstrap server trust not retained: %v", err)
	}
	if err := storagecheck.Check(context.Background(), storagecheck.Executor, cfg.Database.Path); err != nil {
		t.Fatalf("database: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), fixture.args(state), &stdout, &stderr); code != exitFailure {
		t.Fatalf("existing state exit = %d", code)
	}
	if fixture.requests.Load() != 1 {
		t.Fatal("existing identity contacted enrollment endpoint")
	}
	if !strings.Contains(stderr.String(), "already exists") {
		t.Fatalf("unclear existing identity error: %s", stderr.String())
	}
}

func TestExecutorJoinRejectsInvalidCertificateResponse(t *testing.T) {
	cases := map[string]func(*executorJoinResponse){
		"other executor":        func(r *executorJoinResponse) { r.ExecutorID = "00000000-1111-2222-3333-444444444444" },
		"invalid address":       func(r *executorJoinResponse) { r.GRPCAddress = "https://wrong.example" },
		"untrusted certificate": func(r *executorJoinResponse) { r.CAPEM = "not a CA" },
		"different key": func(r *executorJoinResponse) {
			other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			tmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: joinExecutorID}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &other.PublicKey, other)
			if err != nil {
				t.Fatal(err)
			}
			r.CertificatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		},
	}
	for name, alter := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := newJoinFixture(t, alter)
			state := filepath.Join(t.TempDir(), "node")
			var stdout, stderr bytes.Buffer
			if code := run(context.Background(), fixture.args(state), &stdout, &stderr); code != exitFailure {
				t.Fatalf("exit=%d", code)
			}
			if _, err := os.Stat(filepath.Join(state, "service.toml")); !os.IsNotExist(err) {
				t.Fatalf("config written for invalid response: %v", err)
			}
			if _, err := os.Stat(filepath.Join(state, "executor.key")); err != nil {
				t.Fatalf("key not retained: %v", err)
			}
			if !strings.Contains(stderr.String(), "replace the token") || strings.Contains(stderr.String(), fixSecret) {
				t.Fatalf("unsafe or unclear diagnostic: %s", stderr.String())
			}
		})
	}
}

func TestExecutorJoinRequiresTrustedHTTPS(t *testing.T) {
	fixture := newJoinFixture(t, nil)
	state := filepath.Join(t.TempDir(), "node")
	args := fixture.args(state)
	args = append(args[:8], args[10:]...)
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), args, &stdout, &stderr); code != exitFailure {
		t.Fatalf("exit %d stderr %s", code, stderr.String())
	}
	if fixture.requests.Load() != 0 {
		t.Fatal("enrollment token sent to untrusted TLS server")
	}
}

func TestExecutorEnrollmentURL(t *testing.T) {
	for _, endpoint := range []string{"http://remote.example", "http://localhost:9000", "https://user:password@example.com", "https://example.com/?token=secret", "https://example.com/#fragment", "", "file:///tmp/socket"} {
		if _, err := executorEnrollmentURL(endpoint); err == nil {
			t.Errorf("accepted %q", endpoint)
		}
	}
	for endpoint, want := range map[string]string{"https://example.com/api/": "https://example.com/api/executor-enrollment", "http://127.0.0.1:9000": "http://127.0.0.1:9000/executor-enrollment", "http://[::1]:9000": "http://[::1]:9000/executor-enrollment"} {
		got, err := executorEnrollmentURL(endpoint)
		if err != nil || got != want {
			t.Errorf("%q got %q, %v", endpoint, got, err)
		}
	}
}

func TestEnrollmentTokenInput(t *testing.T) {
	for _, value := range []string{fixSecret + "\n", "", strings.Repeat("x", maxAccountKeyFile+1), "two values\n"} {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		go func() { defer w.Close(); w.WriteString(value) }()
		var prompt bytes.Buffer
		token, err := readEnrollmentToken(context.Background(), "", r, &prompt)
		r.Close()
		if value == fixSecret+"\n" {
			if err != nil || token != fixSecret {
				t.Fatalf("token input: %v", err)
			}
		} else if err == nil {
			t.Error("invalid token accepted")
		}
		if prompt.Len() != 0 {
			t.Fatal("noninteractive input printed a prompt")
		}
	}
}

func TestEnrollmentTokenCancellation(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := readEnrollmentToken(ctx, "", reader, io.Discard); done <- err }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("token input ignored cancellation")
	}
}

func TestExecutorJoinBinaryUsesInstalledSibling(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "install with spaces")
	bin := filepath.Join(prefix, "lib", "debuglet", "v0.3.0", "bin")
	if err := os.MkdirAll(bin, 0700); err != nil {
		t.Fatal(err)
	}
	cli := filepath.Join(bin, "dbl")
	if err := os.WriteFile(cli, nil, 0700); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(prefix, "dbl")
	if err := os.Symlink(cli, entry); err != nil {
		t.Fatal(err)
	}
	if _, err := executorJoinBinary(entry); err == nil || !strings.Contains(err.Error(), "install the full Debuglet bundle") {
		t.Fatalf("missing daemon: %v", err)
	}
	daemon := filepath.Join(bin, "debuglet-executor")
	if err := os.WriteFile(daemon, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := executorJoinBinary(entry); err == nil {
		t.Fatal("accepted a non-executable daemon")
	}
	if err := os.Chmod(daemon, 0700); err != nil {
		t.Fatal(err)
	}
	got, err := executorJoinBinary(entry)
	if err != nil || got != daemon {
		t.Fatalf("installed daemon: got %q, %v; want %q", got, err, daemon)
	}
}

func TestExecutorJoinMissingDaemonDoesNotEnroll(t *testing.T) {
	fixture := newJoinFixture(t, nil)
	if err := os.Remove(fixture.executorBinary); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "node")
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), fixture.args(state), &stdout, &stderr); code != exitFailure {
		t.Fatalf("exit %d", code)
	}
	if fixture.requests.Load() != 0 {
		t.Fatal("enrolled without an installed executor")
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatalf("created unusable state: %v", err)
	}
	if !strings.Contains(stderr.String(), "install the full Debuglet bundle") {
		t.Fatalf("missing installation guidance: %s", stderr.String())
	}
}
