// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	dconfig "github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	database "github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/resource"
	drpc "github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	erpc "github.com/netsec-ethz/debuglet/internal/executor/transport/rpc"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
)

type destinationRegistration struct {
	drpc.DispatcherState
	connected chan *drpc.SessionOwner
}

func (p *destinationRegistration) OnExecutorConnected(ctx context.Context, owner *drpc.SessionOwner, hello *pb.HelloResponse, source string) error {
	if err := p.DispatcherState.OnExecutorConnected(ctx, owner, hello, source); err != nil {
		return err
	}
	p.connected <- owner
	return nil
}

// Only policy delivery fails. Real transport ProbeSession and lease renewal
// continue, so retiring the stale owner cannot be masked by a broken channel.
type delayedDestinationDeny struct {
	erpc.ExecutorState
	entered chan struct{}
}

func (s *delayedDestinationDeny) OnBandwidth(ctx context.Context, binding controlsession.Binding, req *pb.BandwidthRequest) (*pb.BandwidthResponse, error) {
	for _, limit := range req.GetLimits() {
		if limit.GetDenied() {
			select {
			case s.entered <- struct{}{}:
			default:
			}
			<-ctx.Done()
			return nil, ctx.Err()
		}
	}
	return s.ExecutorState.OnBandwidth(ctx, binding, req)
}

// This fixture uses both real daemons' control paths, real SQLite state and
// real TCP/UDP receivers. The runtime adapter sends on admitted, registered
// sockets; the existing WASM denial test covers the guest host-call wiring.
func TestDestinationDenyControlPathAndReconnect(t *testing.T) {
	for _, lost := range []bool{false, true} {
		name := "acknowledged"
		if lost {
			name = "delivery_lost_healthy_probes"
		}
		t.Run(name, func(t *testing.T) {
			db, err := sqlitedb.Open(filepath.Join(t.TempDir(), "dispatcher.sqlite"), sqlitedb.Create())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { db.Close() })
			if _, err := sqlitedb.Migrate(t.Context(), db, database.MigrationFS(), sqlitedb.Latest); err != nil {
				t.Fatal(err)
			}
			cfg := &dconfig.DispatcherConfig{}
			cfg.Sui.Disabled = true
			ph, err := payments.NewPaymentHandler(db, cfg, zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}
			d, err := dispatcher.New(zap.NewNop(), db, "destination-control", time.Second, time.Second, ph)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(d.Close)
			operator := newAbuseDrillAPI(t, d, db)
			// A report does not carry authority. The account must receive the
			// operator role through the normal host administration path first.
			operator.expect(t, http.MethodGet, "/destinations", "", false, nil, http.StatusUnauthorized)
			operator.expect(t, http.MethodGet, "/destinations", operator.session.Token, false, nil, http.StatusForbidden)
			if _, err := db.Exec("UPDATE users SET role='operator' WHERE uuid=?", operator.account.ID); err != nil {
				t.Fatal(err)
			}
			f := newRecoveryHarnessWithServer(t, newOperationPeer(), func(f *recoveryHarness) {
				f.server.Close()
				d.Bidi.Close()
				state := &destinationRegistration{DispatcherState: d, connected: f.peer.connected}
				f.server, err = drpc.NewBidiServer(zap.NewNop(), state, d.ControlIncarnation(), d.ControlLeaseDuration())
				if err != nil {
					t.Fatal(err)
				}
				d.Bidi = f.server
			})
			localTargets := true
			f.node.cfg.Network.Policy.LocalTargets = &localTargets
			blocked := make(chan struct{}, 1)
			f.node.newBidi = func(opts erpc.BidiOptions, state erpc.ExecutorState) (*erpc.BidiClient, error) {
				if lost {
					state = &delayedDestinationDeny{ExecutorState: state, entered: blocked}
				}
				return erpc.NewBidiClient(opts, state)
			}
			tcp, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { tcp.Close() })
			udp, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { udp.Close() })
			var tcpBytes, udpPackets atomic.Int64
			tcpDone, udpDone := make(chan error, 1), make(chan struct{})
			go func() {
				conn, err := tcp.Accept()
				if err != nil {
					tcpDone <- err
					return
				}
				defer conn.Close()
				buf := make([]byte, 64)
				for {
					n, err := conn.Read(buf)
					tcpBytes.Add(int64(n))
					if err != nil {
						tcpDone <- err
						return
					}
				}
			}()
			go func() {
				defer close(udpDone)
				buf := make([]byte, 64)
				for {
					if _, _, err := udp.ReadFrom(buf); err != nil {
						return
					}
					udpPackets.Add(1)
				}
			}()
			t.Cleanup(func() { tcp.Close(); udp.Close(); <-udpDone })
			configure := func(e *Executor) {
				e.newRuntime = func(spec scheduler.Spec) runtimeDebuglet {
					registry := socket.NewSocketRegistry(socket.NewBudget(socket.DefaultLimits(), socket.NewDescriptorBudget(socket.DefaultNodeDescriptors)))
					policy := netpolicy.New(denialOperator(t, e), netpolicy.Run{Addresses: spec.Policy.Addresses})
					stop := policy.WatchRevocations(spec.DebugletID.String(), func() int { return registry.CloseRemote(policy.Revoked) })
					return &operationRuntime{
						close: func(context.Context) error {
							stop()
							registry.CloseAll()
							e.limiter.RemoveDebuglet(spec.DebugletID)
							return nil
						},
						run: func(ctx context.Context, _ chan<- []byte) error {
							var connections []net.Conn
							for _, target := range []struct {
								network, address string
								transport        netpolicy.Transport
								kind             socket.SocketType
							}{{"tcp", tcp.Addr().String(), netpolicy.TCP, socket.SocketTypeTCP}, {"udp", udp.LocalAddr().String(), netpolicy.UDP, socket.SocketTypeUDP}} {
								admitted, err := policy.AdmitDestination(ctx, target.transport, target.address)
								if err != nil {
									return err
								}
								conn, err := net.Dial(target.network, admitted.DialAddresses()[0])
								if err != nil {
									return err
								}
								if _, err := registry.Add(socket.NewGenericSocket(conn, target.kind, target.address)); err != nil {
									conn.Close()
									return err
								}
								connections = append(connections, conn)
							}
							tick := time.NewTicker(5 * time.Millisecond)
							defer tick.Stop()
							for {
								select {
								case <-ctx.Done():
									return ctx.Err()
								case <-tick.C:
									for _, conn := range connections {
										if _, err := conn.Write([]byte("probe")); err != nil {
											return err
										}
									}
								}
							}
						},
					}
				}
			}
			s, owner, _ := f.start(configure)
			submit := func() error {
				id := uuid.NewString()
				if err := ph.CreateDummyIntent(id, 1, "fixture", t.Context()); err != nil {
					return err
				}
				if _, err := database.New(db).CreateDebugletOrder(t.Context(), database.CreateDebugletOrderParams{TransactionID: id, ExecutorID: f.node.cfg.Identity.ExecutorID, Price: 1, Currency: "TEST", State: int64(models.Outstanding)}); err != nil {
					return err
				}
				_, err := d.SubmitDebuglets(t.Context(), []models.DebugletSpec{{ExecutorID: f.node.cfg.Identity.ExecutorID, TransactionID: id, Wasm: []byte("\x00asm\x01\x00\x00\x00"), Policy: models.DebugletPolicy{FloorBW: 64000, CeilBW: 1000000, Timeout: 30 * time.Second, Addresses: []string{"[::ffff:127.0.0.1]:443"}}}}, nil)
				return err
			}
			if err := submit(); err != nil {
				t.Fatal(err)
			}
			until := time.Now().Add(5 * time.Second)
			for (tcpBytes.Load() == 0 || udpPackets.Load() == 0) && time.Now().Before(until) {
				time.Sleep(5 * time.Millisecond)
			}
			if tcpBytes.Load() == 0 || udpPackets.Load() == 0 {
				t.Fatal("controlled receivers saw no traffic")
			}
			started := time.Now()
			result := make(chan error, 1)
			go func() {
				result <- operator.deny(t.Context())
			}()
			if lost {
				select {
				case <-blocked:
				case <-time.After(3 * time.Second):
					t.Fatal("denial never reached the control handler")
				}
				beforeTCP, beforeUDP := tcpBytes.Load(), udpPackets.Load()
				time.Sleep(2 * time.Second) // More than the real one-second lease, with ordinary renewal/probes.
				binding, ok := s.executor.Bidi.Binding()
				if !ok || !owner.Available() || s.executor.Bidi.CheckLease(binding) != nil || tcpBytes.Load() <= beforeTCP || udpPackets.Load() <= beforeUDP {
					t.Fatal("fixture lost its healthy lease or traffic before policy retirement")
				}
			}
			select {
			case err := <-result:
				if lost != (err != nil) {
					t.Fatalf("deny delivery: %v (lost=%v)", err, lost)
				}
			case <-time.After(8 * time.Second):
				t.Fatal("policy delivery did not finish")
			}
			select {
			case err := <-tcpDone:
				if !errors.Is(err, io.EOF) {
					t.Fatalf("TCP receiver termination: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("TCP traffic survived the deny bound")
			}
			if elapsed := time.Since(started); elapsed > 5*time.Second+d.ControlLeaseDuration()+time.Second {
				t.Fatalf("receiver stop exceeded delivery plus lease allowance: %v", elapsed)
			}
			time.Sleep(100 * time.Millisecond) // Drain datagrams already queued at the receiver.
			quiet := udpPackets.Load()
			time.Sleep(150 * time.Millisecond)
			if udpPackets.Load() != quiet {
				t.Fatal("UDP traffic continued after TCP termination")
			}
			t.Logf("incident=destination-opt-out at=%s actor=%s delivery_lost=%v stop_elapsed=%s tcp_bytes=%d udp_packets=%d quiet_window=150ms", time.Now().UTC().Format(time.RFC3339Nano), operator.account.ID, lost, time.Since(started), tcpBytes.Load(), quiet)
			policies, err := d.ListDestinationPolicies(t.Context())
			if err != nil || len(policies) != 1 || policies[0].Recipients != 1 || (policies[0].Unconfirmed != 0) != lost {
				t.Fatalf("delivery accounting: %+v, %v", policies, err)
			}
			if policies[0].Actor != operator.account.ID {
				t.Fatal("policy omitted the authenticated approval actor")
			}
			operator.expect(t, http.MethodGet, "/destinations", operator.session.Token, false, nil, http.StatusOK)
			if !lost {
				_, report := s.executor.capabilityReport(t.Context(), true)
				if report.GetNetworkDenials().GetRevokedSockets() == 0 {
					t.Fatal("acknowledged live-socket revocation missing from executor observations")
				}
			}
			s.Stop(nil)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if err := s.Wait(ctx); err != nil {
				t.Fatal(err)
			}
			_, successor, _ := f.start(configure)
			if successor == owner || !successor.Available() {
				t.Fatal("successor control session unavailable")
			}
			if err := submit(); !errors.Is(err, resource.ErrDenied) {
				t.Fatalf("reconnect admitted denied traffic: %v", err)
			}
		})
	}
}
