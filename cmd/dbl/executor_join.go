package main

import (
	"bufio"
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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/netsec-ethz/debuglet/internal/buildinfo"
	"github.com/netsec-ethz/debuglet/internal/configcheck"
	"github.com/netsec-ethz/debuglet/internal/demo/service"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
	"golang.org/x/term"
)

const executorJoinUsage = `Usage:
  dbl executor join --dispatcher URL --executor ID --state-dir DIR
      [--ca-file FILE] [--token-file FILE]

Enroll this machine using the one-time token from Console > My nodes.
The token is read without echo from the terminal, or from standard input or
--token-file. HTTPS verifies the dispatcher using the system trust store or
--ca-file; plain HTTP is accepted only on a literal loopback IP.

DIR must not exist. The command creates private identity, configuration and
storage files, then prints the command to start the executor. It does not
start a service or configure payments. Keep DIR for subsequent restarts.
For a persistent Linux system service, follow docs/operations/executor-onboarding.md
and enroll directly into /var/lib/debuglet/executors/NAME before service install.
`

type executorJoinResponse struct {
	ExecutorID     string `json:"executor_id"`
	CertificatePEM string `json:"certificate_pem"`
	CAPEM          string `json:"ca_pem"`
	GRPCAddress    string `json:"grpc_address"`
	YamuxAddress   string `json:"yamux_address"`
}

func executorJoinCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer) int {
	fs := newCommandFlagSet("executor join")
	endpoint := fs.String("dispatcher", "", "dispatcher HTTPS URL, including any API prefix")
	id := fs.String("executor", "", "executor ID shown in the console")
	state := fs.String("state-dir", "", "new directory for this executor's identity and storage")
	caFile := fs.String("ca-file", "", "trusted dispatcher CA certificate")
	tokenFile := fs.String("token-file", "", "file containing the enrollment token")
	if code, ok := parseCommandFlags(fs, args, executorJoinUsage, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() != 0 || options.EndpointSet || options.Dispatcher != "" || strings.TrimSpace(*state) == "" {
		return usageError("dbl executor join", executorJoinUsage, stderr, "supply --dispatcher, --executor and a new --state-dir after executor join")
	}
	if !uuidPattern.MatchString(*id) || strings.Trim(*id, "0-") == "" {
		return usageError("dbl executor join", executorJoinUsage, stderr, "--executor must be a nonzero lowercase UUID")
	}
	joinURL, err := executorEnrollmentURL(*endpoint)
	if err != nil {
		return usageError("dbl executor join", executorJoinUsage, stderr, "%v", err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if *caFile != "" {
		data, err := os.ReadFile(*caFile)
		if err != nil {
			return reportFailure(ctx, "dbl executor join", stderr, err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(data) {
			return usageError("dbl executor join", executorJoinUsage, stderr, "--ca-file contains no certificates")
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	statePath, err := filepath.Abs(*state)
	if err == nil {
		_, err = os.Lstat(statePath)
		if err == nil {
			err = fmt.Errorf("state directory already exists: %s; keep existing identities and choose a new directory", statePath)
		} else if errors.Is(err, os.ErrNotExist) {
			err = nil
		}
	}
	if err != nil {
		return reportFailure(ctx, "dbl executor join", stderr, err)
	}
	executable, err := os.Executable()
	if err != nil {
		return reportFailure(ctx, "dbl executor join", stderr, err)
	}
	executorBinary, err := executorJoinBinary(executable)
	if err != nil {
		return reportFailure(ctx, "dbl executor join", stderr, err)
	}
	token, err := readEnrollmentToken(ctx, *tokenFile, os.Stdin, stderr)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(stderr, "dbl executor join: enrollment canceled")
			return exitInterrupted
		}
		return reportFailure(ctx, "dbl executor join", stderr, err)
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("enrollment redirects are not followed; use the dispatcher's HTTPS API URL")
	}}
	if err := joinExecutor(ctx, client, joinURL, *id, statePath, token); err != nil {
		return reportFailure(ctx, "dbl executor join", stderr, err)
	}
	config := filepath.Join(statePath, "service.toml")
	command := roleShellWord(executorBinary) + " -config " + roleShellWord(config)
	managed := ""
	if name := filepath.Base(statePath); statePath == service.StateDirectory("/", storagecheck.Executor, name) {
		managed = "sudo " + roleShellWord(executable) + " service install --role executor --name " + roleShellWord(name) + " --enrolled-state " + roleShellWord(statePath)
	}
	return emitReported(ctx, "dbl executor join", options.Output, stdout, stderr, map[string]string{
		"executor_id": *id, "config": config, "start_command": command, "service_command": managed,
	}, func(w io.Writer) error {
		if managed != "" {
			_, err := fmt.Fprintf(w, "Executor %s enrolled. Identity and storage saved in %s.\n\nInstall and start the system service (requires an existing debuglet service account):\n  %s\n\nThe console shows Connected after the executor connects. Keep this state and do not enroll again.\n", *id, statePath, managed)
			return err
		}
		_, err := fmt.Fprintf(w, "Executor %s enrolled. Identity and storage saved in %s.\n\nStart the executor:\n  %s\n\nKeep this terminal open. The console shows Connected after the executor connects.\nReuse this command after restarting; do not enroll again.\n", *id, statePath, command)
		return err
	})
}

// The installer exposes dbl on PATH; its daemon stays beside the resolved
// executable in the versioned package, including after an entry-point symlink.
func executorJoinBinary(executable string) (string, error) {
	real, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return "", fmt.Errorf("locate installed CLI: %w", err)
	}
	binary := filepath.Join(filepath.Dir(real), "debuglet-executor")
	info, err := os.Stat(binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return "", fmt.Errorf("executor binary unavailable at %s; install the full Debuglet bundle with executor join support before enrolling", binary)
	}
	return binary, nil
}

func executorEnrollmentURL(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("--dispatcher must be an HTTPS URL without credentials, query or fragment")
	}
	loopback := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback != nil && loopback.IsLoopback()) {
		return "", errors.New("--dispatcher requires HTTPS except for a literal loopback HTTP address")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/executor-enrollment"
	u.RawPath = ""
	return u.String(), nil
}

func readEnrollmentToken(ctx context.Context, path string, input *os.File, prompt io.Writer) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var data []byte
	var err error
	if path != "" {
		info, err := os.Stat(path)
		if err != nil {
			return "", err
		}
		if !info.Mode().IsRegular() || info.Size() > maxAccountKeyFile {
			return "", errors.New("enrollment token file must be a regular file no larger than 4 KiB")
		}
		data, err = os.ReadFile(path)
	} else {
		data, err = readEnrollmentInput(ctx, input, prompt)
	}
	if err != nil {
		return "", fmt.Errorf("read enrollment token: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	if token == "" || len(data) > maxAccountKeyFile || strings.ContainsAny(token, " \t\r\n") {
		return "", errors.New("enrollment token must be one nonempty value no longer than 4 KiB")
	}
	return token, nil
}

func readEnrollmentInput(ctx context.Context, input *os.File, prompt io.Writer) ([]byte, error) {
	defer func() {
		if ctx.Err() != nil {
			_ = input.Close()
		}
	}()
	read := func() ([]byte, error) {
		line, err := bufio.NewReader(io.LimitReader(input, maxAccountKeyFile+1)).ReadString('\n')
		if errors.Is(err, io.EOF) {
			err = nil
		}
		return []byte(line), err
	}
	if term.IsTerminal(int(input.Fd())) {
		state, err := term.MakeRaw(int(input.Fd()))
		if err != nil {
			return nil, err
		}
		// Restore before closing input on cancellation. The terminal reader
		// edits its own line buffer, so it cannot change these settings later.
		defer term.Restore(int(input.Fd()), state)
		terminal := term.NewTerminal(struct {
			io.Reader
			io.Writer
		}{input, prompt}, "")
		read = func() ([]byte, error) {
			line, err := terminal.ReadPassword("Enrollment token (input hidden): ")
			if errors.Is(err, io.EOF) {
				err = context.Canceled // Ctrl-C or Ctrl-D in the raw terminal.
			}
			return []byte(line), err
		}
	}
	type result struct {
		data []byte
		err  error
	}
	ready := make(chan result, 1)
	go func() { data, err := read(); ready <- result{data, err} }()
	select {
	case value := <-ready:
		return value.data, value.err
	case <-ctx.Done():
		// Closing a pipe releases its blocked reader. Restore a terminal first
		// via the defer above; main exits immediately after this command returns.
		return nil, ctx.Err()
	}
}

func joinExecutor(ctx context.Context, client *http.Client, endpoint, id, state, token string) (err error) {
	if err := os.MkdirAll(filepath.Dir(state), 0700); err != nil {
		return err
	}
	if err := os.Mkdir(state, 0700); err != nil {
		return fmt.Errorf("create new executor state directory: %w", err)
	}
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w; incomplete state is preserved at %s. If enrollment was sent, replace the token in My nodes before retrying with a new state directory", err, state)
		}
	}()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := writeJoinFile(filepath.Join(state, "executor.key"), keyPEM); err != nil {
		return err
	}
	if err := storagecheck.BootstrapFresh(ctx, storagecheck.Executor, filepath.Join(state, "executor.sqlite")); err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: id}}, key)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{"executor_id": id, "token": token, "csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Debuglet-API-Version", "1.10")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request executor enrollment: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("dispatcher refused enrollment (HTTP %d); check the dispatcher URL and replace expired or used tokens in My nodes", resp.StatusCode)
	}
	var result executorJoinResponse
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 64*1024))
	if err := decoder.Decode(&result); err != nil {
		return fmt.Errorf("decode enrollment response: %w", err)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("enrollment response contains unexpected data")
	}
	if err := validateEnrollmentCertificate(result, id, keyPEM); err != nil {
		return err
	}
	// The server can use a public certificate while issuing client identities
	// from its own CA. Keep both authenticated trust roots for control TLS.
	if resp.TLS != nil {
		for _, chain := range resp.TLS.VerifiedChains {
			if len(chain) != 0 {
				result.CAPEM += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain[len(chain)-1].Raw}))
			}
		}
	}
	for _, file := range []struct{ name, data string }{{"executor.crt", result.CertificatePEM}, {"ca.crt", result.CAPEM}, {"service.toml", executorJoinConfig(id, state, result)}} {
		if err := writeJoinFile(filepath.Join(state, file.name), []byte(file.data)); err != nil {
			return err
		}
	}
	return nil
}

func validateEnrollmentCertificate(result executorJoinResponse, id string, keyPEM []byte) error {
	if result.ExecutorID != id {
		return errors.New("enrollment response names another executor")
	}
	for _, address := range []string{result.GRPCAddress, result.YamuxAddress} {
		if err := configcheck.Endpoint("enrollment control address", address); err != nil {
			return err
		}
	}
	pair, err := tls.X509KeyPair([]byte(result.CertificatePEM), keyPEM)
	if err != nil {
		return fmt.Errorf("enrollment certificate does not match this machine's key: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	if leaf.IsCA || leaf.Subject.CommonName != id {
		return errors.New("enrollment certificate does not identify this executor")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(result.CAPEM)) {
		return errors.New("enrollment response contains no trusted CA certificate")
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("verify enrollment certificate: %w", err)
	}
	return nil
}

func writeJoinFile(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".join-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	return os.Link(file.Name(), path)
}

func executorJoinConfig(id, state string, result executorJoinResponse) string {
	return fmt.Sprintf(`[identity]
executor_id = %q
version = %q
[dispatcher]
addr = %q
yamux_addr = %q
[tls]
disable = false
[credentials]
ca_cert = %q
client_cert = %q
client_key = %q
[database]
path = %q
[resources]
capacity = 10485760
max_debuglets = 4
[tesla]
epoch_seconds = 30
[network]
packet_counter = "fallback"
disable_scion_environment = true
[network.policy]
local_targets = false
scion = false
inbound = false
[logging]
log_level = "info"
[pricing]
price_per_bw_s = 1
currency = "TEST"
`, id, buildinfo.Version, result.GRPCAddress, result.YamuxAddress,
		filepath.Join(state, "ca.crt"), filepath.Join(state, "executor.crt"), filepath.Join(state, "executor.key"), filepath.Join(state, "executor.sqlite"))
}
