// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package executor

import (
	"bytes"
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/sys/unix"
)

// staleTaggerFilter attaches, on iface's egress hook, a filter with the
// identity of a tagger's legacy filter and closes every descriptor, as an
// executor process that ended without removing it leaves it.
func staleTaggerFilter(t *testing.T, iface *net.Interface, handle uint32) {
	t.Helper()
	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.SchedCLS, License: "Apache-2.0",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, -1), asm.Return()}})
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skipf("skipping test: insufficient privileges for eBPF: %v", err)
		}
		t.Fatalf("load program: %v", err)
	}
	defer program.Close()
	conn, err := tc.Open(&tc.Config{})
	if err != nil {
		t.Fatalf("open rtnetlink: %v", err)
	}
	defer conn.Close()
	qdisc := tc.Object{Msg: tc.Msg{Family: unix.AF_UNSPEC, Ifindex: uint32(iface.Index), Handle: core.BuildHandle(tc.HandleRoot, 0), Parent: tc.HandleIngress},
		Attribute: tc.Attribute{Kind: "clsact"}}
	if err := conn.Qdisc().Add(&qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		t.Fatalf("add clsact: %v", err)
	}
	fd, name, flags := uint32(program.FD()), "debuglet_tag", uint32(tc.BpfActDirect)
	filter := tc.Object{Msg: tc.Msg{Family: unix.AF_UNSPEC, Ifindex: uint32(iface.Index), Handle: handle,
		Parent: core.BuildHandle(tc.HandleRoot, tc.HandleMinEgress), Info: core.FilterInfo(0xC0DE, unix.ETH_P_ALL)},
		Attribute: tc.Attribute{Kind: "bpf", BPF: &tc.Bpf{FD: &fd, Name: &name, Flags: &flags}}}
	if err := conn.Filter().Add(&filter); err != nil {
		t.Fatalf("add filter: %v", err)
	}
	t.Cleanup(func() {
		if conn, err := tc.Open(&tc.Config{}); err == nil {
			_ = conn.Filter().Delete(&filter)
			conn.Close()
		}
	})
}

func egressFilterAttached(t *testing.T, iface *net.Interface, handle uint32) bool {
	t.Helper()
	conn, err := tc.Open(&tc.Config{})
	if err != nil {
		t.Fatalf("open rtnetlink: %v", err)
	}
	defer conn.Close()
	filters, err := conn.Filter().Get(&tc.Msg{Family: unix.AF_UNSPEC, Ifindex: uint32(iface.Index), Parent: core.BuildHandle(tc.HandleRoot, tc.HandleMinEgress)})
	if err != nil {
		t.Fatalf("list egress filters: %v", err)
	}
	for _, filter := range filters {
		if filter.Handle == handle {
			return true
		}
	}
	return false
}

// A node restarted on the interface where the earlier process left a legacy
// tagger filter removes that filter before it derives the retired chain whose
// keys the filter may still sign with.
func TestRestartRetiresAStaleTaggerFilterBeforeTheTail(t *testing.T) {
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	db := newFixtureDatabase(t)
	cfg := fixtureConfig()
	cfg.Tesla = retiredTesla(retiredSeed)
	cfg.Network.PacketCounter, cfg.Network.Interface = "auto", "lo"
	start := func(logger *zap.Logger) *Node {
		t.Helper()
		node, err := newNode(cfg, logger, db, func(*net.Interface, *zap.Logger) (ratelimit.PacketCount, error) { return &nodeCounter{}, nil })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := node.Close(); err != nil {
				t.Error(err)
			}
		})
		return node
	}
	first := start(zap.NewNop()).schedule
	const handle = 0x0DEB0171
	staleTaggerFilter(t, iface, handle)

	core, logs := observer.New(zapcore.InfoLevel)
	node := start(zap.New(core))
	if egressFilterAttached(t, iface, handle) {
		t.Fatal("the restarted node left the earlier process's filter attached")
	}
	var removed, tail int = -1, -1
	for i, entry := range logs.All() {
		switch entry.Message {
		case "Removed a tagger filter an earlier executor process left attached":
			removed = i
		case "Disclosing the previous TESLA chain's remaining keys", "Previous TESLA chain's remaining keys are not disclosed":
			tail = i
		}
	}
	if removed < 0 || tail < 0 || removed > tail {
		t.Fatalf("removal at %d, tail decision at %d; want the removal first: %v", removed, tail, logs.All())
	}
	if !node.schedule.Config().ClockUnready && (node.retired.schedule == nil || !bytes.Equal(node.retired.schedule.Anchor(), first.Anchor())) {
		t.Fatal("the retired chain was not derived after the stale filter was removed")
	}
}
