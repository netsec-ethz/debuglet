// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

func hostEgressGrant() *pb.EgressGrant {
	now := time.Now().Unix()
	return &pb.EgressGrant{Version: 1, BitsPerSecond: 8, BurstBytes: 64, Bytes: 32, AttemptsPerSecond: 1, AttemptBurst: 4, Attempts: 4, Addresses: []string{"127.0.0.1"}, NotBeforeUnix: now - 60, ExpiresUnix: now + 3600}
}

func TestHostEgressPayloadSharedAcrossSockets(t *testing.T) {
	for _, kind := range []socket.SocketType{socket.SocketTypeTCP, socket.SocketTypeTLS, socket.SocketTypeUDP} {
		t.Run(map[socket.SocketType]string{socket.SocketTypeTCP: "tcp", socket.SocketTypeTLS: "tls", socket.SocketTypeUDP: "udp"}[kind], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			env := policyEnv(t, localSpec(), netpolicy.Run{Addresses: []string{"127.0.0.1"}, Egress: netpolicy.NewEgress(hostEgressGrant())})
			var address string
			received := make(chan int64, 3)
			if kind == socket.SocketTypeUDP {
				listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				address = listener.LocalAddr().String()
				_ = listener.SetDeadline(time.Now().Add(5 * time.Second))
				go func() {
					for range 2 {
						n, _, err := listener.ReadFrom(make([]byte, 64))
						if err != nil {
							received <- -1
							return
						}
						received <- int64(n)
					}
				}()
			} else {
				var listener net.Listener
				var err error
				if kind == socket.SocketTypeTLS {
					cert, pool := smSelfSigned(t)
					env.TlsCfg = &tls.Config{RootCAs: pool}
					listener, err = tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
				} else {
					listener, err = net.Listen("tcp4", "127.0.0.1:0")
				}
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				address = listener.Addr().String()
				go func() {
					for range 3 {
						conn, err := listener.Accept()
						if err != nil {
							received <- -1
							return
						}
						go func() {
							defer conn.Close()
							_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
							n, err := io.Copy(io.Discard, conn)
							if err != nil {
								received <- -1
							} else {
								received <- n
							}
						}()
					}
				}()
			}
			for range 2 {
				handle, err := connectSocket(ctx, ctx, env, kind, address)
				if err != nil {
					t.Fatal(err)
				}
				conn, err := env.Registry.Get(handle)
				if err != nil {
					t.Fatal(err)
				}
				if n, err := conn.Write(make([]byte, 16)); err != nil || n != 16 {
					t.Fatalf("write=%d,%v", n, err)
				}
				if err := env.Registry.Close(handle); err != nil {
					t.Fatal(err)
				}
			}
			handle, err := connectSocket(ctx, ctx, env, kind, address)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := env.Registry.Get(handle)
			if err != nil {
				t.Fatal(err)
			}
			if n, err := conn.Write([]byte{1}); n != 0 || !errors.Is(err, netpolicy.ErrDenied) {
				t.Fatalf("escaped shared budget=%d,%v", n, err)
			}
			_ = env.Registry.Close(handle)
			count := 3
			if kind == socket.SocketTypeUDP {
				count = 2
			}
			var total int64
			for range count {
				select {
				case n := <-received:
					if n < 0 {
						t.Fatal("peer read failed")
					}
					total += n
				case <-ctx.Done():
					t.Fatal("peer did not receive admitted payload")
				}
			}
			if total != 32 {
				t.Fatalf("peers observed %d bytes", total)
			}
		})
	}
}

func TestHostEgressChargesEachResolvedConnectionAttempt(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	resolver := &fixedResolver{answers: map[string][]netip.Addr{"owned.example": {netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.1")}}}
	grant := hostEgressGrant()
	grant.Addresses = []string{"127.0.0.2", "127.0.0.1"}
	grant.Attempts, grant.AttemptBurst = 2, 2
	env := policyEnv(t, localSpec(), netpolicy.Run{Addresses: []string{"owned.example"}, Egress: netpolicy.NewEgress(grant)}, netpolicy.WithResolver(resolver))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	handle, err := connectSocket(ctx, ctx, env, socket.SocketTypeTCP, net.JoinHostPort("owned.example", port))
	if err != nil {
		t.Fatal(err)
	}
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if _, err := connectSocket(ctx, ctx, env, socket.SocketTypeTCP, net.JoinHostPort("owned.example", port)); !errors.Is(err, netpolicy.ErrDenied) {
		t.Fatalf("failed first address was not charged: %v", err)
	}
	_ = env.Registry.Close(handle)
}

func TestHostEgressAcceptedTCPRepliesShareBudget(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	env := policyEnv(t, localSpec(), netpolicy.Run{Addresses: []string{"127.0.0.1"}, ListenTCP: true, Egress: netpolicy.NewEgress(hostEgressGrant())})
	env.TcpServer = listener
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for range 2 {
		peer, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer peer.Close()
		_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
		handle := HostAcceptTCP(env)(ctx)
		conn, err := env.Registry.Get(handle)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(make([]byte, 16)); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(peer, make([]byte, 16)); err != nil {
			t.Fatal(err)
		}
		if err := env.Registry.Close(handle); err != nil {
			t.Fatal(err)
		}
	}
	peer, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	handle := HostAcceptTCP(env)(ctx)
	conn, err := env.Registry.Get(handle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{1}); !errors.Is(err, netpolicy.ErrDenied) {
		t.Fatalf("accepted peer escaped budget: %v", err)
	}
}
