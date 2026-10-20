// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/workflow"
)

type ServerConfig struct {
	Address    string
	UI         string
	Dispatcher string
	CAFile     string
}

// Serve binds only a literal loopback address. The browser and authoring API share one origin.
func Serve(ctx context.Context, builder *Builder, config ServerConfig, ready func(string)) error {
	host, _, err := net.SplitHostPort(config.Address)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("--listen must be a literal loopback address, for example 127.0.0.1:8090")
	}
	listener, err := net.Listen("tcp", config.Address)
	if err != nil {
		return err
	}
	defer listener.Close()
	origin := "http://" + listener.Addr().String()
	handler, err := NewHandler(builder, config, origin)
	if err != nil {
		return err
	}
	server := &http.Server{Handler: handler, BaseContext: func(net.Listener) context.Context { return ctx }, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 7 * time.Minute, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(stop)
		case <-done:
		}
	}()
	if ready != nil {
		ready(origin + "/console/builder")
	}
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func NewHandler(builder *Builder, config ServerConfig, origin string) (http.Handler, error) {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		return nil, errors.New("invalid studio origin")
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, err
	}
	token := hex.EncodeToString(tokenBytes)
	mux := http.NewServeMux()
	experimentRoutes(mux, builder, token)
	mux.HandleFunc("GET /studio/api/session", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"token": token}) })
	mux.HandleFunc("GET /studio/api/catalog", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, workflow.Catalog()) })
	mutate := func(fn func(http.ResponseWriter, *http.Request, workflow.Workflow)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Studio-Token") != token {
				writeError(w, 403, errors.New("open the studio page again to obtain its session token"))
				return
			}
			mediaType, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if mediaErr != nil || mediaType != "application/json" {
				writeError(w, 415, errors.New("Content-Type must be application/json"))
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, MaxWorkflowBytes)
			wf, err := DecodeWorkflow(r.Body)
			if err != nil {
				writeError(w, 400, err)
				return
			}
			fn(w, r, wf)
		}
	}
	mux.HandleFunc("POST /studio/api/validate", mutate(func(w http.ResponseWriter, r *http.Request, wf workflow.Workflow) {
		diagnostics := workflow.Validate(wf)
		if diagnostics == nil {
			diagnostics = []workflow.Diagnostic{}
		}
		writeJSON(w, 200, map[string]any{"diagnostics": diagnostics})
	}))
	mux.HandleFunc("POST /studio/api/build", mutate(func(w http.ResponseWriter, r *http.Request, wf workflow.Workflow) {
		if builder == nil {
			writeError(w, 503, errors.New("compiler is unavailable; restart dbl-studio with --sdk pointing to the matching Debuglet checkout"))
			return
		}
		bundle, err := builder.Build(r.Context(), wf)
		if err != nil {
			writeError(w, 422, err)
			return
		}
		writeJSON(w, 200, bundle)
	}))
	if config.Dispatcher != "" {
		target, err := url.Parse(config.Dispatcher)
		if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" || target.User != nil || target.RawQuery != "" || target.Fragment != "" || (target.Path != "" && target.Path != "/") {
			return nil, errors.New("--dispatcher must be an http(s) origin without credentials, path, query or fragment")
		}
		upstreamIP := net.ParseIP(target.Hostname())
		if target.Hostname() != "localhost" && (upstreamIP == nil || !upstreamIP.IsLoopback()) {
			return nil, errors.New("--dispatcher supports an owned loopback development dispatcher only; import the built bundle into a public dispatcher’s hosted console to sign in and submit there")
		}
		proxy := httputil.NewSingleHostReverseProxy(target)
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			if host == "localhost" {
				address = net.JoinHostPort("127.0.0.1", port)
			}
			return (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, network, address)
		}
		if config.CAFile != "" {
			certs, err := os.ReadFile(config.CAFile)
			if err != nil {
				return nil, err
			}
			pool, err := x509.SystemCertPool()
			if err != nil {
				pool = x509.NewCertPool()
			}
			if !pool.AppendCertsFromPEM(certs) {
				return nil, errors.New("--ca-file contains no PEM certificates")
			}
			transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		}
		proxy.Transport = transport
		original := proxy.Director
		proxy.Director = func(r *http.Request) {
			r.URL.Path = strings.TrimPrefix(r.URL.Path, "/api")
			if r.URL.RawPath != "" {
				r.URL.RawPath = strings.TrimPrefix(r.URL.RawPath, "/api")
			}
			original(r)
			r.Host = target.Host
			r.Header.Del("X-Studio-Token")
			if r.Header.Get("Origin") != "" {
				r.Header.Set("Origin", target.Scheme+"://"+target.Host)
			}
		}
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			writeError(w, 502, errors.New("dispatcher is unreachable; check the configured dispatcher address"))
		}
		proxy.ModifyResponse = func(response *http.Response) error {
			if response.ContentLength > 32<<20 {
				return errors.New("dispatcher response exceeds 32 MiB")
			}
			response.Body = &limitedBody{ReadCloser: response.Body, remaining: 32 << 20}
			// Cookies belong to the local console proxy, not the upstream hostname.
			cookies := response.Cookies()
			response.Header.Del("Set-Cookie")
			for _, cookie := range cookies {
				cookie.Domain = ""
				response.Header.Add("Set-Cookie", cookie.String())
			}
			return nil
		}
		mux.Handle("/api/", http.MaxBytesHandler(proxy, 32<<20))
	} else {
		mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
			writeError(w, 503, errors.New("no dispatcher configured; start dbl-studio serve with --dispatcher to sign in and submit"))
		})
	}
	if config.UI != "" {
		root, err := filepath.Abs(config.UI)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(filepath.Join(root, "index.html"))
		if err != nil || info.IsDir() {
			return nil, errors.New("--ui must name the built console directory containing index.html")
		}
		files := http.FileServer(http.Dir(root))
		mux.HandleFunc("GET /console/", func(w http.ResponseWriter, r *http.Request) {
			relative := strings.TrimPrefix(r.URL.Path, "/console/")
			path := filepath.Join(root, filepath.FromSlash(relative))
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				copy := r.Clone(r.Context())
				copy.URL.Path = "/" + relative
				files.ServeHTTP(w, copy)
				return
			}
			if filepath.Ext(relative) != "" {
				http.NotFound(w, r)
				return
			}
			http.ServeFile(w, r, filepath.Join(root, "index.html"))
		})
	} else {
		mux.HandleFunc("GET /console/", func(w http.ResponseWriter, r *http.Request) {
			writeError(w, 503, errors.New("build the Debuglet console and restart with --ui <console>/dist to open the visual editor"))
		})
	}
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/console/builder", http.StatusTemporaryRedirect)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
		if r.Host != parsed.Host || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != origin) || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			writeError(w, 403, errors.New("studio requests must use its own loopback origin"))
			return
		}
		mux.ServeHTTP(w, r)
	}), nil
}

type limitedBody struct {
	io.ReadCloser
	remaining int64
}

func (r *limitedBody) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		var probe [1]byte
		n, err := r.ReadCloser.Read(probe[:])
		if n > 0 {
			return 0, errors.New("dispatcher response exceeds 32 MiB")
		}
		return 0, err
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.ReadCloser.Read(p)
	r.remaining -= int64(n)
	return n, err
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, err error) {
	body := map[string]any{"error": err.Error()}
	var invalid *ValidationError
	if errors.As(err, &invalid) {
		body["diagnostics"] = invalid.Diagnostics
	}
	var experimentInvalid *ExperimentValidationError
	if errors.As(err, &experimentInvalid) {
		body["diagnostics"] = experimentInvalid.Diagnostics
	}
	writeJSON(w, status, body)
}
