// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/connections"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

// Exercise the boundary between provider cookies and an actual CLI process.
// Provider servers and browser launching are owned fixtures; the dispatcher,
// SQLite, TLS, cookie jar, SDK and CLI credential persistence are real.
func TestProviderBrowserAndHeadlessCLIOverTLS(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("browser launcher fixture exercises the supported Linux CLI")
	}
	dbl := ccBuildCLI(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := newCILogonStub(t, key)
	stubGitHub(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			if err := r.ParseForm(); err != nil || r.Form.Get("code") != "one-time" || r.Form.Get("code_verifier") == "" {
				t.Error("invalid GitHub exchange")
			}
			io.WriteString(w, `{"access_token":"github-provider-secret"}`)
		case "/user":
			if r.Header.Get("Authorization") != "Bearer github-provider-secret" {
				t.Error("provider credential missing")
			}
			io.WriteString(w, `{"id":42,"login":"owned-researcher","name":"Researcher"}`)
		default:
			http.NotFound(w, r)
		}
	})
	var handler *Handler
	p.fixture(t, GitHubOAuth(GitHubOAuthConfig{Enabled: true, ClientID: "test-id", ClientSecret: "test-secret"}), func(h *Handler) { handler = h })
	tls := httptest.NewUnstartedServer(nil)
	t.Cleanup(tls.Close)
	origin := "https://" + tls.Listener.Addr().String()
	endpoint := origin + "/api"
	handler.authPublicURL, handler.deviceVerificationURL = endpoint, origin+"/console/device"
	handler.githubOAuth.CallbackURL, handler.githubOAuth.SuccessURL = endpoint+"/auth/github/callback", origin+"/console/"
	handler.cilogonOIDC.CallbackURL, handler.cilogonOIDC.SuccessURL = endpoint+"/auth/cilogon/callback", origin+"/console/"
	p.mu.Lock()
	p.callbackURL = handler.cilogonOIDC.CallbackURL
	p.mu.Unlock()
	// Register middleware only after the exact configured audience is known.
	e := echo.New()
	handler.RegisterRoutes(e)
	tls.Config.Handler = http.StripPrefix("/api", e)
	tls.StartTLS()
	browser := tls.Client()
	browser.Timeout = 5 * time.Second
	browser.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	apiURL, _ := url.Parse(endpoint)
	request := func(t *testing.T, method, path string, body any, want int) (*http.Response, []byte) {
		t.Helper()
		var requestData []byte
		if body != nil {
			requestData = credentialJSON(t, body)
		}
		for attempt := 0; ; attempt++ {
			r, err := http.NewRequestWithContext(t.Context(), method, endpoint+path, bytes.NewReader(requestData))
			if err != nil {
				t.Fatal(err)
			}
			if body != nil {
				r.Header.Set("Content-Type", "application/json")
			}
			for _, c := range browser.Jar.Cookies(apiURL) {
				if c.Name == csrfCookieName {
					r.Header.Set(csrfHeaderName, c.Value)
				}
			}
			response, err := browser.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			// These sequential login cases share one browser address. Honor the
			// real authentication limiter instead of bypassing it in the fixture.
			if response.StatusCode == http.StatusTooManyRequests && attempt < 5 {
				seconds, err := strconv.Atoi(response.Header.Get("Retry-After"))
				if err != nil || seconds < 1 || seconds > 10 {
					t.Fatal("invalid authentication retry interval")
				}
				select {
				case <-time.After(time.Duration(seconds) * time.Second):
				case <-t.Context().Done():
					t.Fatal("browser request cancelled")
				}
				continue
			}
			if response.StatusCode != want {
				t.Fatalf("%s %s: status %d, want %d", method, path, response.StatusCode, want)
			}
			return response, data
		}
	}
	completeProvider := func(t *testing.T, provider, authorization string, linked bool) {
		t.Helper()
		u, err := url.Parse(authorization)
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		if q.Get("state") == "" || q.Get("code_challenge_method") != "S256" {
			t.Fatal("missing state or PKCE")
		}
		if provider == "cilogon" {
			p.mu.Lock()
			p.nonce, p.challenge = q.Get("nonce"), q.Get("code_challenge")
			p.mu.Unlock()
		}
		response, _ := request(t, http.MethodGet, "/auth/"+provider+"/callback?code=one-time&state="+url.QueryEscape(q.Get("state")), nil, http.StatusFound)
		want := tls.URL + "/console/"
		if linked {
			want += "?auth_action=link_pending&provider=" + provider
		}
		if response.Header.Get("Location") != want {
			t.Fatal("callback did not end at the configured safe destination")
		}
		for _, c := range response.Cookies() {
			if c.Name == sessionCookieName && (!c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode) {
				t.Fatal("unsafe browser session cookie")
			}
		}
	}
	accountID := func(t *testing.T) string {
		t.Helper()
		_, data := request(t, http.MethodGet, "/me", nil, 200)
		var account client.User
		if err := json.Unmarshal(data, &account); err != nil {
			t.Fatal(err)
		}
		return account.ID
	}
	response, _ := request(t, http.MethodGet, "/auth/github", nil, 302)
	completeProvider(t, "github", response.Header.Get("Location"), false)
	owner := accountID(t)
	if owner == "" {
		t.Fatal("provider login returned no account ID")
	}
	_, data := request(t, http.MethodPost, "/me/identities/cilogon/link", map[string]any{}, 200)
	var link struct {
		URL string `json:"authorization_url"`
	}
	if err := json.Unmarshal(data, &link); err != nil {
		t.Fatal(err)
	}
	completeProvider(t, "cilogon", link.URL, true)
	request(t, http.MethodPost, "/me/identities/cilogon/confirm", map[string]bool{"confirm": true}, 204)
	if accountID(t) != owner {
		t.Fatal("link changed canonical account")
	}

	cert := filepath.Join(t.TempDir(), "dispatcher.pem")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tls.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, provider := range []string{"github", "cilogon"} {
		t.Run(provider, func(t *testing.T) {
			response, _ := request(t, http.MethodGet, "/auth/"+provider, nil, 302)
			completeProvider(t, provider, response.Header.Get("Location"), false)
			if accountID(t) != owner {
				t.Fatal("linked provider changed canonical account")
			}
			for _, mode := range []string{"browser", "headless"} {
				t.Run(mode, func(t *testing.T) {
					dir := t.TempDir()
					config := filepath.Join(dir, "config.json")
					opened := filepath.Join(dir, "opened-url")
					launcher := filepath.Join(dir, "xdg-open")
					if err := os.WriteFile(launcher, []byte("#!/bin/sh\nprintf '%s' \"$1\" > \"$DEBUGLET_OPENED_URL\"\n"), 0700); err != nil {
						t.Fatal(err)
					}
					env := append(os.Environ(), "SSL_CERT_FILE="+cert, "DEBUGLET_ACCOUNT_KEY=", "DEBUGLET_OPENED_URL="+opened, "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
					ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
					defer cancel()
					command := func(args ...string) *exec.Cmd {
						cmd := exec.CommandContext(ctx, dbl, append([]string{"--config", config}, args...)...)
						cmd.Env = env
						return cmd
					}
					var output strings.Builder
					run := func(args ...string) []byte {
						t.Helper()
						data, err := command(args...).CombinedOutput()
						output.Write(data)
						if err != nil {
							t.Fatalf("CLI %s failed: %v: %s", args[0], err, data)
						}
						return data
					}
					run("connect", endpoint, "--name", "owned")
					args := []string{"login", "--browser", "--credential-store", "file"}
					if mode == "headless" {
						args = append(args, "--no-browser")
					}
					cmd := command(args...)
					pipe, err := cmd.StdoutPipe()
					if err != nil {
						t.Fatal(err)
					}
					var stderr bytes.Buffer
					cmd.Stderr = &stderr
					if err := cmd.Start(); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if cmd.ProcessState == nil {
							_ = cmd.Process.Kill()
							_ = cmd.Wait()
						}
					})
					scanner := bufio.NewScanner(pipe)
					var code string
					for scanner.Scan() {
						line := scanner.Text()
						output.WriteString(line + "\n")
						if strings.HasPrefix(line, "Enter code: ") {
							code = strings.TrimPrefix(line, "Enter code: ")
							break
						}
					}
					if code == "" {
						t.Fatal("CLI emitted no approval code")
					}
					approval := DeviceApprovalRequest{UserCode: code, Audience: endpoint, Confirm: true}
					_, inspected := request(t, http.MethodPost, "/auth/device/inspect", approval, 200)
					if !bytes.Contains(inspected, []byte(endpoint)) || !bytes.Contains(inspected, []byte("account:read")) {
						t.Fatal("approval omitted dispatcher or scope")
					}
					request(t, http.MethodPost, "/auth/device/approve", approval, 204)
					for scanner.Scan() {
						output.WriteString(scanner.Text() + "\n")
					}
					if err := scanner.Err(); err != nil {
						t.Fatal(err)
					}
					if err := cmd.Wait(); err != nil {
						t.Fatalf("CLI login failed: %v: %s", err, stderr.Bytes())
					}
					output.Write(stderr.Bytes())
					launched, err := os.ReadFile(opened)
					if mode == "browser" && (err != nil || string(launched) != handler.deviceVerificationURL) {
						t.Fatal("browser did not receive verification URL")
					}
					if mode == "headless" && !os.IsNotExist(err) {
						t.Fatal("headless login launched a browser")
					}
					credential, err := connections.CredentialFor(ctx, config, "owned", endpoint)
					if err != nil || credential.AccountID != owner || !strings.HasPrefix(credential.Token, "dbt_") {
						t.Fatal("CLI did not save the local account credential")
					}
					info, err := os.Stat(filepath.Join(dir, connections.CredentialFileName))
					if err != nil || info.Mode().Perm() != 0600 {
						t.Fatal("unsafe credential file permissions")
					}
					if !bytes.Contains(run("whoami"), []byte(owner)) {
						t.Fatal("CLI identity differs from browser")
					}
					if !bytes.Contains(run("whoami", "--credential"), []byte("kind: api")) {
						t.Fatal("CLI did not receive API credential")
					}
					sdk, err := client.New(endpoint, client.Options{HTTPClient: tls.Client(), Credential: credential.Token})
					if err != nil {
						t.Fatal(err)
					}
					if me, err := sdk.Whoami(ctx); err != nil || me.ID != owner {
						t.Fatal("SDK identity differs from browser")
					}
					run("logout")
					if _, err := sdk.Whoami(ctx); !authIsUnauthorized(err) {
						t.Fatal("logout left a reusable credential")
					}
					stored, err := connections.CredentialFor(ctx, config, "owned", endpoint)
					if err != nil || stored.Token != "" {
						t.Fatal("logout retained local credential")
					}
					for _, secret := range []string{credential.Token, "github-provider-secret", "provider-token"} {
						if strings.Contains(output.String(), secret) {
							t.Fatal("CLI output exposed a credential")
						}
					}
				})
			}
			request(t, http.MethodPost, "/auth/logout", nil, 204)
			request(t, http.MethodGet, "/me", nil, 401)
		})
	}
}
