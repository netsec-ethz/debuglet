package rpc

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"go.uber.org/zap"
)

func TestBidiCancellation(t *testing.T) {
	for _, established := range []bool{false, true} {
		name := "handshake"
		if established {
			name = "established"
		}
		t.Run(name, func(t *testing.T) {
			deadline, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			ctx, cancel := context.WithCancel(deadline)
			defer cancel()
			lis, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer lis.Close()
			peerReady := make(chan struct{})
			peerDone := make(chan error, 1)
			go func() {
				conn, err := lis.Accept()
				if err != nil {
					peerDone <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(8 * time.Second))
				if established {
					session, err := yamux.Server(conn, nil)
					if err != nil {
						peerDone <- err
						return
					}
					defer session.Close()
					close(peerReady)
					select {
					case <-session.CloseChan():
						peerDone <- nil
					case <-deadline.Done():
						peerDone <- deadline.Err()
					}
				} else {
					// Observing the Ping bytes proves that cancellation interrupts an
					// in-progress handshake, rather than a dial that never started.
					buf := make([]byte, 12)
					if _, err := io.ReadFull(conn, buf); err != nil {
						peerDone <- err
						return
					}
					close(peerReady)
					_, err = io.Copy(io.Discard, conn)
					peerDone <- err
				}
			}()
			b, err := NewBidiClient(BidiOptions{Address: lis.Addr().String(), YamuxAddress: lis.Addr().String(), Logger: zap.NewNop()}, nil)
			if err != nil {
				lis.Close()
				<-peerDone
				t.Fatal(err)
			}
			served := make(chan error, 1)
			waited := make(chan error, 1)
			go func() { served <- b.ConnectAndServe(ctx) }()
			go func() { waited <- b.WaitReadyContext(deadline) }()
			// All owned workers are joined even when an assertion fails.
			defer func() {
				cancel()
				b.Close()
				lis.Close()
				if served != nil {
					<-served
				}
				if waited != nil {
					<-waited
				}
				if peerDone != nil {
					<-peerDone
				}
			}()
			select {
			case <-peerReady:
			case err := <-peerDone:
				peerDone = nil
				t.Fatalf("peer setup: %v", err)
			case <-deadline.Done():
				t.Fatal(deadline.Err())
			}
			// Ping/serving alone never establishes negotiated readiness.
			if established {
				select {
				case <-b.serving:
				case <-deadline.Done():
					t.Fatal(deadline.Err())
				}
			}
			select {
			case err := <-waited:
				waited = nil
				t.Fatalf("ready before Hello/Bind: %v", err)
			default:
			}

			cancel()
			select {
			case err := <-served:
				served = nil
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("serve cancellation: %v", err)
				}
			case <-deadline.Done():
				t.Fatal(deadline.Err())
			}
			if waited != nil {
				select {
				case err := <-waited:
					waited = nil
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("failed handshake readiness: %v", err)
					}
				case <-deadline.Done():
					t.Fatal(deadline.Err())
				}
			}
			select {
			case err := <-peerDone:
				peerDone = nil
				if err != nil {
					t.Fatalf("owned connection not cleanly closed: %v", err)
				}
			case <-deadline.Done():
				t.Fatal(deadline.Err())
			}
		})
	}
}
