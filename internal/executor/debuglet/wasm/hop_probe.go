// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/wasm/hostconn"
	"github.com/netsec-ethz/debuglet/internal/guestio"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// hopReceiver cannot send. Its accounting/revocation key is the admitted
// destination; the source of a correlated ICMP reply may be an intermediate
// router. Only the parsed response metadata leaves this host operation.
type hopReceiver struct {
	*net.IPConn
	target *net.IPAddr
	source *net.IPAddr
}

func (c *hopReceiver) RemoteAddr() net.Addr      { return c.target }
func (c *hopReceiver) Write([]byte) (int, error) { return 0, netpolicy.ErrDenied }
func (c *hopReceiver) Read(buf []byte) (int, error) {
	n, source, err := c.IPConn.ReadFromIP(buf)
	c.source = source
	return n, err
}

func probeHop(ctx context.Context, env *WasmEnv, address string, ttl int) (_ guestio.HopReply, err error) {
	var result guestio.HopReply
	destination, err := env.Net.AdmitDestination(ctx, netpolicy.ICMP, address)
	if err != nil {
		return result, err
	}
	sendReservation, err := env.Registry.Reserve(2)
	if err != nil {
		return result, err
	}
	defer sendReservation.Release()
	dialer, err := hostconn.NewDialer(destination, env.Tagger)
	if err != nil {
		return result, err
	}
	var outgoing net.Conn
	for _, candidate := range destination.DialAddresses() {
		outgoing, err = dialer.DialContext(ctx, "ip4:icmp", candidate)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return result, context.Cause(ctx)
		}
	}
	if outgoing == nil {
		return result, err
	}
	if err := ipv4.NewConn(outgoing).SetTTL(ttl); err != nil {
		env.RecordCleanupError(outgoing.Close())
		return result, err
	}
	outgoing = tagDatagrams(env, outgoing, socket.SocketTypeICMP4)
	if tagged, ok := outgoing.(interface{ SetTTL(int) error }); ok {
		if err := tagged.SetTTL(ttl); err != nil {
			env.RecordCleanupError(outgoing.Close())
			return result, err
		}
	}
	target, ok := outgoing.RemoteAddr().(*net.IPAddr)
	if !ok || target.IP.To4() == nil {
		env.RecordCleanupError(outgoing.Close())
		return result, fmt.Errorf("hop probes require an IPv4 target")
	}
	sendHandle, err := attachSocket(ctx, env, outgoing, destination.Key, socket.SocketTypeICMP4, sendReservation)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, env.Registry.Close(sendHandle)) }()
	sender, err := env.Registry.Get(sendHandle)
	if err != nil {
		return result, err
	}

	receiveReservation, err := env.Registry.Reserve(1)
	if err != nil {
		return result, err
	}
	defer receiveReservation.Release()
	listenerConfig := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		if env.Tagger == nil {
			return nil
		}
		return hostconn.MarkSocket(raw, env.Tagger)
	}}
	packet, err := listenerConfig.ListenPacket(ctx, "ip4:icmp", "0.0.0.0")
	if err != nil {
		return result, err
	}
	receiver := &hopReceiver{IPConn: packet.(*net.IPConn), target: target}
	receiveHandle, err := attachSocket(ctx, env, receiver, destination.Key, socket.SocketTypeICMP4, receiveReservation)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, env.Registry.Close(receiveHandle)) }()
	reader, err := env.Registry.Get(receiveHandle)
	if err != nil {
		return result, err
	}
	deadline, _ := ctx.Deadline()
	writeDeadline := sender.(interface{ SetWriteDeadline(time.Time) error }).SetWriteDeadline
	readDeadline := reader.(interface{ SetReadDeadline(time.Time) error }).SetReadDeadline
	if err := writeDeadline(deadline); err != nil {
		return result, err
	}
	if err := readDeadline(deadline); err != nil {
		return result, err
	}
	// Wakes reads on cancellation even when the run has no explicit deadline.
	canceled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = writeDeadline(time.Now()); _ = readDeadline(time.Now()); close(canceled) })
	defer func() {
		if !stop() {
			<-canceled
		}
	}()
	nonce := make([]byte, 20)
	if _, err := rand.Read(nonce); err != nil {
		return result, err
	}
	id, sequence := int(binary.BigEndian.Uint16(nonce)), int(binary.BigEndian.Uint16(nonce[2:]))
	echo := &icmp.Echo{ID: id, Seq: sequence, Data: nonce[4:]}
	request, err := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: echo}).Marshal(nil)
	if err != nil {
		return result, err
	}
	started := time.Now()
	n, err := sender.Write(request)
	if err != nil {
		return result, err
	}
	if n != len(request) {
		return result, io.ErrShortWrite
	}
	buffer := make([]byte, MAX_SLICE_LENGTH)
	for {
		n, readErr := reader.Read(buffer)
		if ctx.Err() != nil {
			return result, context.Cause(ctx)
		}
		if n > 0 {
			typeID, code, reached, matches := matchHopReply(buffer[:n], receiver.source, target.IP, echo)
			if matches {
				return guestio.HopReply{Address: receiver.source.IP.String(), Type: typeID, Code: code,
					Reached: reached, DurationMS: float64(time.Since(started)) / float64(time.Millisecond)}, nil
			}
		}
		if readErr != nil {
			return result, readErr
		}
	}
}

func matchHopReply(packet []byte, source *net.IPAddr, target net.IP, echo *icmp.Echo) (int, int, bool, bool) {
	if source == nil {
		return 0, 0, false, false
	}
	message, err := icmp.ParseMessage(1, packet)
	if err != nil {
		return 0, 0, false, false
	}
	var quoted []byte
	switch body := message.Body.(type) {
	case *icmp.Echo:
		if message.Type != ipv4.ICMPTypeEchoReply || message.Code != 0 || !source.IP.Equal(target) || body.ID != echo.ID || body.Seq != echo.Seq || !bytes.Equal(body.Data, echo.Data) {
			return 0, 0, false, false
		}
		return int(ipv4.ICMPTypeEchoReply), message.Code, true, true
	case *icmp.TimeExceeded:
		if message.Type != ipv4.ICMPTypeTimeExceeded || message.Code != 0 {
			return 0, 0, false, false
		}
		quoted = body.Data
	case *icmp.DstUnreach:
		if message.Type != ipv4.ICMPTypeDestinationUnreachable {
			return 0, 0, false, false
		}
		quoted = body.Data
	default:
		return 0, 0, false, false
	}
	if len(quoted) < 28 || quoted[0]>>4 != 4 || quoted[9] != 1 || !net.IP(quoted[16:20]).Equal(target) {
		return 0, 0, false, false
	}
	headerLength := int(quoted[0]&15) * 4
	if headerLength < 20 || len(quoted) < headerLength+8 || binary.BigEndian.Uint16(quoted[6:8])&0x1fff != 0 {
		return 0, 0, false, false
	}
	body := quoted[headerLength:]
	if body[0] != byte(ipv4.ICMPTypeEcho) || body[1] != 0 || int(binary.BigEndian.Uint16(body[4:6])) != echo.ID || int(binary.BigEndian.Uint16(body[6:8])) != echo.Seq {
		return 0, 0, false, false
	}
	return int(message.Type.(ipv4.ICMPType)), message.Code, false, true
}
