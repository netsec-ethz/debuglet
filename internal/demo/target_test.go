package demo

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDemoTargetExchange(t *testing.T) {
	for _, tc := range []struct {
		name, ack string
		wantError bool
	}{
		{"normal", "ACK 0123456789abcdef0123456789abcdef\n", false},
		{"wrong nonce", "ACK wrong\n", true},
		{"oversized", strings.Repeat("x", maxProtocolLine+1), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			target, err := startTarget(ctx, "0123456789abcdef0123456789abcdef")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cleanup, stop := context.WithTimeout(context.Background(), time.Second)
				defer stop()
				if err := target.Stop(cleanup); err != nil {
					t.Error(err)
				}
			})
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", target.Addr())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			deadline, _ := ctx.Deadline()
			conn.SetDeadline(deadline)
			line, err := readProtocolLine(conn)
			if err != nil || line != "DEBUGLET/1 0123456789abcdef0123456789abcdef\n" {
				t.Fatalf("response %q: %v", line, err)
			}
			// Fragment the peer's acknowledgement; target must accumulate it.
			for _, part := range []string{tc.ack[:2], tc.ack[2:]} {
				if _, err := io.WriteString(conn, part); err != nil {
					t.Fatal(err)
				}
			}
			if err := target.Wait(ctx); (err != nil) != tc.wantError {
				t.Fatalf("target outcome: %v", err)
			}
			if !tc.wantError {
				b := make([]byte, 1)
				if n, err := conn.Read(b); n != 0 || !errors.Is(err, io.EOF) {
					t.Fatalf("normal close must produce EOF: %d %v", n, err)
				}
			}
		})
	}
}

func TestDemoTargetCancellation(t *testing.T) {
	for _, connect := range []bool{false, true} {
		t.Run(map[bool]string{false: "waiting for connection", true: "waiting for ack"}[connect], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			target, err := startTarget(ctx, "nonce")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				stopCtx, stop := context.WithTimeout(context.Background(), time.Second)
				defer stop()
				target.Stop(stopCtx)
			})
			if connect {
				conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", target.Addr())
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				d, _ := ctx.Deadline()
				conn.SetDeadline(d)
				if _, err := readProtocolLine(conn); err != nil {
					t.Fatal(err)
				}
			}
			cancel()
			stopCtx, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if err := target.Stop(stopCtx); err != nil {
				t.Fatal(err)
			}
			if err := target.Wait(stopCtx); err == nil {
				t.Fatal("forced closure was counted as a valid exchange")
			}
		})
	}
}
