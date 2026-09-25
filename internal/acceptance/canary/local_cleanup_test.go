package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTargetCancellationJoinsOwnedCallback(t *testing.T) {
	t.Run("waiting_for_connection", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		target, err := startCanaryTarget(ctx, "cleanup-nonce")
		if err != nil {
			t.Fatal(err)
		}
		defer cleanupTestStopTarget(t, target)
		cancel()
		joined, end := context.WithTimeout(context.Background(), time.Second)
		defer end()
		if err := target.wait(joined); err == nil || errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("cancelled accept did not finish with a target error: %v", err)
		}
		cleanupTestClosed(t, target.Done(), "target exchange")
		cleanupTestListenerClosed(t, target.addr())
	})

	t.Run("exchange_finishes_before_close_callback", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		target, err := startCanaryTarget(ctx, "cleanup-nonce")
		if err != nil {
			t.Fatal(err)
		}
		var peer net.Conn
		var gate *cleanupTestCloseGate
		defer func() {
			// Release the test gate before joining the production callback, even
			// if an earlier assertion failed while that callback held target.mu.
			if gate != nil {
				gate.unblock()
			}
			cancel()
			if peer != nil {
				peer.Close()
			}
			cleanupTestStopTarget(t, target)
		}()
		peer, err = net.DialTimeout("tcp", target.addr(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if err := peer.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		line, err := readProtocolLine(peer)
		if err != nil || line != "DEBUGLET/1 cleanup-nonce\n" {
			t.Fatalf("target did not reach its ACK wait: line=%q err=%v", line, err)
		}
		// The exchange keeps its original real socket. Only cancellation's
		// cached connection gets a gate, installed through its existing lock.
		// Closing the peer can then finish the exchange independently of the
		// cancellation callback, exposing an omitted callback join.
		target.mu.Lock()
		if target.conn != nil {
			gate = &cleanupTestCloseGate{Conn: target.conn, entered: make(chan struct{}), release: make(chan struct{})}
			target.conn = gate
		}
		target.mu.Unlock()
		if gate == nil {
			t.Fatal("target has no active connection after sending its reply")
		}
		cancel()
		cleanupTestAwait(t, gate.entered, "owned cancellation callback entering Close")
		if err := peer.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-target.Done():
			t.Fatal("target published completion while its cancellation callback was still in Close")
		case <-time.After(100 * time.Millisecond):
		}
		gate.unblock()
		joined, end := context.WithTimeout(context.Background(), time.Second)
		defer end()
		if err := target.wait(joined); err == nil || errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("withheld ACK became success or failed to join after cancellation: %v", err)
		}
		cleanupTestClosed(t, target.Done(), "target exchange and cancellation callback")
		cleanupTestListenerClosed(t, target.addr())
		if err := target.stop(joined); err != nil {
			t.Fatalf("already cancelled target did not remain joinable: %v", err)
		}
	})
}

func TestProxyCancellationJoinsActiveHandler(t *testing.T) {
	entered, upstreamCancelled, upstreamDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sentinel" {
			io.WriteString(w, "still-owned-by-test")
			return
		}
		if r.URL.Path != "/blocked" {
			http.NotFound(w, r)
			return
		}
		defer close(upstreamDone)
		close(entered)
		select {
		case <-r.Context().Done():
			close(upstreamCancelled)
		case <-release:
		}
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	peerCtx, cancelPeer := context.WithTimeout(context.Background(), 5*time.Second)
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 3 * time.Second}
	s := &local{}
	var peerDone chan struct{}
	var peerErr error
	var peerStatus int
	defer func() {
		// This emergency path owns the peer and upstream, but runs only after
		// the assertions below have observed production cleanup on its own.
		unblock()
		cancel()
		cancelPeer()
		client.CloseIdleConnections()
		upstream.CloseClientConnections()
		if peerDone != nil {
			select {
			case <-peerDone:
			case <-time.After(time.Second):
				t.Error("test HTTP peer did not join during teardown")
			}
		}
		upstream.Close()
		cleanupCtx, end := context.WithTimeout(context.Background(), time.Second)
		defer end()
		if _, err := s.Cleanup(cleanupCtx); err != nil {
			t.Errorf("fallback proxy cleanup: %v", err)
		}
	}()
	endpoint, err := s.startProxy(ctx, strings.TrimPrefix(upstream.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(peerCtx, http.MethodGet, endpoint+"/blocked", nil)
	if err != nil {
		t.Fatal(err)
	}
	peerDone = make(chan struct{})
	go func() {
		defer close(peerDone)
		var response *http.Response
		response, peerErr = client.Do(req)
		if peerErr == nil {
			peerStatus = response.StatusCode
			_, peerErr = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
			peerErr = errors.Join(peerErr, response.Body.Close())
		}
	}()
	cleanupTestAwait(t, entered, "real upstream request")
	s.handlers.mu.Lock()
	active := s.handlers.active
	s.handlers.mu.Unlock()
	if active != 1 {
		t.Fatalf("expected one active owned proxy handler, got %d", active)
	}
	select {
	case <-peerDone:
		t.Fatal("peer completed before session cancellation")
	default:
	}
	cancel()
	cleanupCtx, end := context.WithTimeout(context.Background(), 2*time.Second)
	defer end()
	evidence, err := s.Cleanup(cleanupCtx)
	if err != nil {
		t.Fatalf("proxy cleanup after session cancellation: %v", err)
	}
	if evidence.ChildrenReaped == nil || !*evidence.ChildrenReaped || evidence.ForcedKills == nil || *evidence.ForcedKills != 0 {
		t.Fatalf("cleanup did not report joined ownership: %+v", evidence)
	}
	cleanupTestClosed(t, s.proxyDone, "proxy Serve loop at cleanup return")
	if !s.handlers.complete() {
		t.Fatal("cleanup returned while an owned proxy handler was active")
	}
	cleanupTestListenerClosed(t, s.proxyListener.Addr().String())
	cleanupTestAwait(t, upstreamCancelled, "upstream request cancellation without harness release")
	cleanupTestAwait(t, upstreamDone, "upstream handler return without harness release")
	cleanupTestAwait(t, peerDone, "test HTTP peer without harness cancellation")
	if errors.Is(peerErr, context.DeadlineExceeded) || errors.Is(peerErr, context.Canceled) {
		t.Fatalf("peer needed its own deadline or cancellation to finish: %v", peerErr)
	}
	if peerErr == nil && peerStatus != http.StatusBadGateway {
		t.Fatalf("cancelled upstream reported HTTP %d", peerStatus)
	}
	// Cleanup owns the proxy listener, not the independent upstream server.
	response, err := client.Get(upstream.URL + "/sentinel")
	if err != nil {
		t.Fatalf("cleanup disrupted the unrelated upstream listener: %v", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 128))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK || string(body) != "still-owned-by-test" {
		t.Fatalf("unrelated upstream response: status=%d body=%q read=%v close=%v", response.StatusCode, body, readErr, closeErr)
	}
}

type cleanupTestCloseGate struct {
	net.Conn
	entered, release       chan struct{}
	closeOnce, releaseOnce sync.Once
	err                    error
}

func (c *cleanupTestCloseGate) Close() error {
	c.closeOnce.Do(func() {
		close(c.entered)
		<-c.release
		c.err = c.Conn.Close()
	})
	return c.err
}

func (c *cleanupTestCloseGate) unblock() { c.releaseOnce.Do(func() { close(c.release) }) }

func cleanupTestStopTarget(t *testing.T, target *canaryTarget) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := target.stop(ctx); err != nil {
		t.Errorf("fallback target join: %v", err)
	}
}

func cleanupTestAwait(t *testing.T, done <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("timed out joining %s", label)
	}
}

func cleanupTestClosed(t *testing.T, done <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-done:
	default:
		t.Fatalf("%s was not joined", label)
	}
}

func cleanupTestListenerClosed(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatalf("owned listener %s still accepts after completion", addr)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("dial timed out instead of observing a closed owned listener: %v", err)
	}
}
