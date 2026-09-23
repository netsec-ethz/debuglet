package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCaptureSharedBudget(t *testing.T) {
	c := newCapture(5)
	if n, err := c.stdout().Write([]byte("abc")); n != 3 || err != nil {
		t.Fatal(n, err)
	}
	c.stderr().Write([]byte("def"))
	data, over := c.result()
	if string(data) != "abc" || !over {
		t.Fatalf("capture=%q overflow=%t", data, over)
	}
	c.stdout().Write([]byte("more"))
	data, _ = c.result()
	if string(data) != "abc" {
		t.Fatal("bound changed")
	}
}
func TestOwnedAPIPrefixProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, r.URL.RequestURI()) }))
	defer upstream.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s := &local{}
	endpoint, err := s.startProxy(ctx, strings.TrimPrefix(upstream.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, end := context.WithTimeout(context.Background(), time.Second)
		defer end()
		if _, err := s.Cleanup(cleanup); err != nil {
			t.Error(err)
		}
	}()
	httpClient := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: time.Second}
	defer httpClient.CloseIdleConnections()
	for _, tc := range []struct {
		path, want string
		status     int
	}{{"/executors?x=1", "/executors?x=1", 200}, {"/api/nested", "/api/nested", 200}} {
		response, err := httpClient.Get(endpoint + tc.path)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != tc.status || string(body) != tc.want {
			t.Fatalf("proxy response %d %q %v", response.StatusCode, body, err)
		}
	}
	response, err := httpClient.Get(strings.TrimSuffix(endpoint, "/api") + "/apix/version")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 404 {
		t.Fatal("proxy accepted non-prefix path")
	}
}
func TestTargetRequiresACKAndNormalClose(t *testing.T) {
	for _, good := range []bool{true, false} {
		t.Run(map[bool]string{true: "valid", false: "wrong_ack"}[good], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			target, err := startCanaryTarget(ctx, testNonce)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				endCtx, end := context.WithTimeout(context.Background(), time.Second)
				defer end()
				if err := target.stop(endCtx); err != nil {
					t.Error(err)
				}
			}()
			conn, err := net.DialTimeout("tcp", target.addr(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(time.Second))
			line, err := readProtocolLine(conn)
			if err != nil || line != "DEBUGLET/1 "+testNonce+"\n" {
				t.Fatalf("reply %q %v", line, err)
			}
			nonce := testNonce
			if !good {
				nonce = "wrong"
			}
			io.WriteString(conn, "ACK "+nonce+"\n")
			if err := target.wait(ctx); (err == nil) != good {
				t.Fatalf("target result=%v good=%t", err, good)
			}
			if good {
				data, err := io.ReadAll(conn)
				if err != nil || len(data) != 0 {
					t.Fatalf("normal EOF: %q %v", data, err)
				}
			}
		})
	}
}
