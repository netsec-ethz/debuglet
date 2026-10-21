// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package tagger

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
	"golang.org/x/sys/unix"
)

func TestTaggedUDPListenerReply(t *testing.T) {
	captured := captureSocket(t, unix.IPPROTO_UDP)
	now := time.Now()
	ks, err := tesla.NewKeySchedule(tesla.Config{Seed: fixedSeed, EpochLength: time.Hour, Epoch: now.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	tgr := New(ks, testMeasurementID)
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.LocalAddr().(*net.UDPAddr).Port
	peer, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	payload := []byte("attributed reply from listener")
	wrapped, err := tgr.WrapUDPReply(listener, peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	if err = wrapped.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := wrapped.Write(payload); n != len(payload) || err != nil {
		t.Fatalf("write=%d %v", n, err)
	}
	if err = wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	pkt := capture(t, captured, func(pkt []byte) bool {
		return len(pkt) >= ipv4HeaderLen+udpHeaderLen && pkt[9] == protoUDP && int(binary.BigEndian.Uint16(pkt[20:22])) == port &&
			int(binary.BigEndian.Uint16(pkt[22:24])) == peer.LocalAddr().(*net.UDPAddr).Port && bytes.Equal(pkt[28:], payload)
	})
	verifyCaptured(t, "UDP listener reply", ks, now, pkt)
	peer.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	n, err := peer.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], payload) {
		t.Fatalf("received=%q %v", buf[:n], err)
	}
	// Closing the raw reply socket must not close the shared listener.
	if _, err = peer.Write([]byte("again")); err != nil {
		t.Fatal(err)
	}
	listener.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err = listener.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "again" {
		t.Fatalf("listener after close=%q %v", buf[:n], err)
	}
}
