// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"
	"github.com/netsec-ethz/debuglet/internal/guestio"
)

type meshUDPPacket struct {
	Group, Fingerprint, From, To, RunID, Kind string
	Window, Seq                               int
	Sent                                      []byte `json:",omitempty"`
}
type meshUDPWindow struct {
	sent, received, echoed       []bool
	sentAt                       []time.Time
	rtts                         []float64
	remote                       []bool
	attempted, writes, summaries int
}
type meshUDPPeer struct {
	guestio.MeshPeer
	handle  int32
	socket  socket.Socket
	windows map[int]*meshUDPWindow
}
type meshUDP struct {
	mu        sync.Mutex
	cancel    context.CancelFunc
	done      chan struct{}
	env       *WasmEnv
	config    guestio.MeshConfig
	peers     map[string]*meshUDPPeer
	queue     []guestio.MeshSnapshot
	dropped   int
	err       error
	closeOnce sync.Once
}

func startMeshUDP(ctx context.Context, env *WasmEnv, c guestio.MeshConfig) (*meshUDP, error) {
	if c.IntervalMS < 1000 || c.IntervalMS > 60000 || c.WindowMS < c.IntervalMS || c.WindowMS > 300000 || c.WindowMS%c.IntervalMS != 0 {
		return nil, fmt.Errorf("UDP interval must be 1–60 seconds and window an interval multiple up to 5 minutes")
	}
	if err := env.Net.AvailableListener(netpolicy.UDP); err != nil {
		return nil, err
	}
	if env.UdpServer == nil {
		return nil, net.ErrClosed
	}
	ctx, cancel := context.WithDeadline(ctx, time.UnixMilli(c.StartMS+c.DurationMS).Add(3*time.Second))
	s := &meshUDP{cancel: cancel, done: make(chan struct{}), env: env, config: c, peers: map[string]*meshUDPPeer{}}
	for _, p := range c.Peers {
		if p.Participant == c.Self {
			continue
		}
		dial, cancelDial := context.WithTimeout(ctx, time.Second)
		h, err := connectSocket(ctx, dial, env, socket.SocketTypeUDP, p.UDPAddress)
		cancelDial()
		if err != nil {
			cancel()
			for _, q := range s.peers {
				_ = env.Registry.Close(q.handle)
			}
			return nil, err
		}
		conn, err := env.Registry.Get(h)
		if err != nil {
			cancel()
			_ = env.Registry.Close(h)
			for _, q := range s.peers {
				_ = env.Registry.Close(q.handle)
			}
			return nil, err
		}
		s.peers[p.Participant] = &meshUDPPeer{MeshPeer: p, handle: h, socket: conn, windows: map[int]*meshUDPWindow{}}
	}
	go s.run(ctx)
	return s, nil
}

func (s *meshUDP) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		_ = s.env.UdpServer.SetReadDeadline(time.Now())
		<-s.done
		_ = s.env.UdpServer.SetReadDeadline(time.Time{})
	})
	return nil
}
func (s *meshUDP) Snapshot() guestio.MeshSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := guestio.MeshSnapshot{Rows: []map[string]any{}, SkippedWindows: s.dropped}
	if len(s.queue) > 0 {
		out = s.queue[0]
		s.queue = s.queue[1:]
		out.SkippedWindows = s.dropped
		s.dropped = 0
	}
	if s.err != nil {
		out.Error = s.err.Error()
	}
	return out
}
func (s *meshUDP) publish(v guestio.MeshSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.queue) == 4 {
		s.queue = s.queue[1:]
		s.dropped++
	}
	s.queue = append(s.queue, v)
}
func (s *meshUDP) send(p *meshUDPPeer, packet meshUDPPacket) bool {
	packet.Group, packet.Fingerprint, packet.From, packet.To = s.config.Group, s.config.Fingerprint, s.config.Self, p.Participant
	for _, self := range s.config.Peers {
		if self.Participant == s.config.Self {
			packet.RunID = self.RunID
		}
	}
	data, err := json.Marshal(packet)
	if err != nil || len(data) > 2048 {
		return false
	}
	deadline, ok := p.socket.(interface{ SetWriteDeadline(time.Time) error })
	if !ok {
		return false
	}
	if deadline.SetWriteDeadline(time.Now().Add(100*time.Millisecond)) != nil {
		return false
	}
	n, err := p.socket.Write(data)
	return err == nil && n == len(data)
}
func meshBits(v []bool) []byte {
	b := make([]byte, (len(v)+7)/8)
	for i, x := range v {
		if x {
			b[i/8] |= 1 << uint(i%8)
		}
	}
	return b
}
func meshUnpack(b []byte, n int) ([]bool, bool) {
	if len(b) != (n+7)/8 {
		return nil, false
	}
	if r := uint(n % 8); r != 0 && b[len(b)-1]>>r != 0 {
		return nil, false
	}
	v := make([]bool, n)
	for i := range v {
		v[i] = b[i/8]&(1<<uint(i%8)) != 0
	}
	return v, true
}
func meshCount(v []bool) int {
	n := 0
	for _, x := range v {
		if x {
			n++
		}
	}
	return n
}

func (s *meshUDP) run(ctx context.Context) {
	defer close(s.done)
	defer func() {
		for _, p := range s.peers {
			_ = s.env.Registry.Close(p.handle)
		}
	}()
	c := s.config
	start := time.UnixMilli(c.StartMS)
	end := start.Add(time.Duration(c.DurationMS) * time.Millisecond)
	interval := time.Duration(c.IntervalMS) * time.Millisecond
	period := time.Duration(c.WindowMS) * time.Millisecond
	slots := int(c.WindowMS / c.IntervalMS)
	last := int((end.Sub(start) - 1) / period)
	get := func(p *meshUDPPeer, w int) *meshUDPWindow {
		if p.windows[w] == nil {
			p.windows[w] = &meshUDPWindow{sent: make([]bool, slots), received: make([]bool, slots), echoed: make([]bool, slots), sentAt: make([]time.Time, slots)}
		}
		return p.windows[w]
	}
	next, flushed := 0, -1
	buffer := make([]byte, 65535)
	for ctx.Err() == nil {
		now := time.Now()
		if !now.Before(start) && now.Before(end) && !now.Before(start.Add(time.Duration(next)*interval)) {
			actual := int(now.Sub(start) / interval)
			w := int(now.Sub(start) / period)
			seq := int((now.Sub(start) % period) / interval)
			for _, p := range s.peers {
				v := get(p, w)
				v.attempted++
				v.sentAt[seq] = time.Now()
				v.sent[seq] = s.send(p, meshUDPPacket{Kind: "probe", Window: w, Seq: seq})
				if !v.sent[seq] {
					v.writes++
				}
			}
			next = actual + 1
		}
		for w := flushed + 1; w <= last; w++ {
			boundary := start.Add(time.Duration(w+1) * period)
			if boundary.After(end) {
				boundary = end
			}
			if now.Before(boundary) {
				break
			}
			for _, p := range s.peers {
				v := get(p, w)
				if v.summaries < 3 && !now.Before(boundary.Add(time.Duration(v.summaries)*600*time.Millisecond)) {
					if !s.send(p, meshUDPPacket{Kind: "summary", Window: w, Sent: meshBits(v.sent)}) {
						v.writes++
					}
					v.summaries++
				}
			}
			if now.Before(boundary.Add(2 * time.Second)) {
				break
			}
			report := guestio.MeshSnapshot{OK: true, Rows: []map[string]any{}, WindowStartMS: start.Add(time.Duration(w) * period).UnixMilli(), WindowEndMS: boundary.UnixMilli()}
			for _, p := range s.peers {
				v := get(p, w)
				scheduled := int((boundary.Sub(time.UnixMilli(report.WindowStartMS)) + interval - 1) / interval)
				report.Rows = append(report.Rows, meshUDPRow(c.Self, p.Participant, v, max(0, scheduled-v.attempted)))
				delete(p.windows, w)
			}
			sort.Slice(report.Rows, func(i, j int) bool { return report.Rows[i]["peer"].(string) < report.Rows[j]["peer"].(string) })
			s.publish(report)
			flushed = w
		}
		if flushed == last {
			return
		}
		_ = s.env.UdpServer.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		n, from, err := s.env.UdpServer.ReadFromUDPAddrPort(buffer)
		if err != nil {
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				continue
			}
			if ctx.Err() == nil {
				s.mu.Lock()
				s.err = fmt.Errorf("UDP listener stopped")
				s.mu.Unlock()
			}
			return
		}
		match, err := s.env.Net.AdmitAddr(ctx, netpolicy.Inbound, from)
		if err != nil {
			continue
		}
		if err = s.env.Accountant.Account(ctx, app.TransferIn, match.Key, n); err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		if _, err = s.env.Net.AdmitAddr(ctx, netpolicy.Inbound, from); err != nil {
			continue
		}
		if n > 2048 {
			continue
		}
		var m meshUDPPacket
		if json.Unmarshal(buffer[:n], &m) != nil || m.Group != c.Group || m.Fingerprint != c.Fingerprint || m.To != c.Self {
			continue
		}
		p := s.peers[m.From]
		if p == nil || p.RunID != m.RunID {
			continue
		}
		address, err := netip.ParseAddrPort(p.UDPAddress)
		if err != nil || address.Addr().Unmap() != from.Addr().Unmap() {
			continue
		}
		current := int(time.Since(start) / period)
		if m.Window <= flushed || m.Window < 0 || m.Window > last || m.Window > current+1 {
			continue
		}
		v := get(p, m.Window)
		switch m.Kind {
		case "probe":
			if m.Seq < 0 || m.Seq >= slots {
				continue
			}
			v.received[m.Seq] = true
			if !s.send(p, meshUDPPacket{Kind: "echo", Window: m.Window, Seq: m.Seq}) {
				v.writes++
			}
		case "echo":
			if m.Seq < 0 || m.Seq >= slots || !v.sent[m.Seq] || v.echoed[m.Seq] {
				continue
			}
			v.echoed[m.Seq] = true
			v.rtts = append(v.rtts, float64(time.Since(v.sentAt[m.Seq]))/float64(time.Millisecond))
		case "summary":
			if bits, ok := meshUnpack(m.Sent, slots); ok {
				v.remote = bits
			}
		}
	}
}

func meshUDPRow(self, peer string, v *meshUDPWindow, skipped int) map[string]any {
	r := map[string]any{"self": self, "peer": peer, "rtt_series": self + " → " + peer, "loss_series": peer + " → " + self, "rtt_ok": len(v.rtts) > 1, "loss_ok": v.remote != nil && meshCount(v.remote) > 0, "sent": meshCount(v.sent), "echoes": meshCount(v.echoed), "received": meshCount(v.received), "remote_sent": nil, "delivered": nil, "skipped": skipped, "write_errors": v.writes, "rtt_mean_ms": nil, "rtt_p95_ms": nil, "rtt_variation_ms": nil, "loss_percent": nil}
	if len(v.rtts) > 1 {
		sum, variation := 0.0, 0.0
		for i, x := range v.rtts {
			sum += x
			if i > 0 {
				variation += math.Abs(x - v.rtts[i-1])
			}
		}
		r["rtt_mean_ms"] = sum / float64(len(v.rtts))
		r["rtt_variation_ms"] = variation / float64(len(v.rtts)-1)
		sort.Float64s(v.rtts)
		r["rtt_p95_ms"] = v.rtts[int(math.Ceil(.95*float64(len(v.rtts))))-1]
	}
	if v.remote != nil {
		sent, received := meshCount(v.remote), 0
		for i, x := range v.remote {
			if x && v.received[i] {
				received++
			}
		}
		r["remote_sent"], r["delivered"] = sent, received
		if sent > 0 {
			r["loss_percent"] = 100 * float64(sent-received) / float64(sent)
		}
	}
	return r
}
