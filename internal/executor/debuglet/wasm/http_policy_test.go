// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
)

// Exercise HTTP and HTTPS through the guest's real socket boundary against
// owned loopback servers. A permitted job destination is still subject to the
// operator's port policy; refusal must happen before any connection reaches it.
func TestHTTPDestinationPolicy(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprintf("tls=%t", secure), func(t *testing.T) {
			var connections, requests atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.URL.Path != "/healthz" {
					t.Errorf("unexpected path %q", r.URL.Path)
				}
				_, _ = io.WriteString(w, "healthy\n")
			}))
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					connections.Add(1)
				}
			}
			kind := socket.SocketTypeTCP
			if secure {
				server.StartTLS()
				kind = socket.SocketTypeTLS
			} else {
				server.Start()
			}
			defer server.Close()
			target := server.Listener.Addr().String()
			host, port, err := net.SplitHostPort(target)
			if err != nil {
				t.Fatal(err)
			}
			spec := localSpec()
			spec.PermittedPorts = "1" // The owned server has an ephemeral port.
			refused := policyEnv(t, spec, netpolicy.Run{Addresses: []string{host}})
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			if handle, err := connectSocket(ctx, ctx, refused, kind, target); handle != -1 || !errors.Is(err, netpolicy.ErrDenied) {
				t.Fatalf("operator policy refusal = %d, %v", handle, err)
			}
			if connections.Load() != 0 || requests.Load() != 0 {
				t.Fatal("refused destination was contacted")
			}

			spec.PermittedPorts = port
			allowed := policyEnv(t, spec, netpolicy.Run{Addresses: []string{host}})
			if secure {
				roots := x509.NewCertPool()
				roots.AddCert(server.Certificate())
				allowed.TlsCfg = &tls.Config{RootCAs: roots}
			}
			handle, err := connectSocket(ctx, ctx, allowed, kind, target)
			if err != nil {
				t.Fatalf("allowed owned target: %v", err)
			}
			conn, err := allowed.Registry.Get(handle)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := fmt.Fprintf(conn, "GET /healthz HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != http.StatusOK || string(body) != "healthy\n" || requests.Load() != 1 {
				t.Fatalf("HTTP result = %d %q, %v; requests=%d", response.StatusCode, body, err, requests.Load())
			}
		})
	}
}
