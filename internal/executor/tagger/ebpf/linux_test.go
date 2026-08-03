//go:build linux

package ebpf

import (
	"net"
	"strings"
	"testing"
	"time"

	"debuglet/internal/executor/tagger/tesla"
)

func TestBPFLinuxLoad(t *testing.T) {
	ks, err := tesla.NewKeySchedule(tesla.Config{
		Seed:  make([]byte, 32),
		Delay: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewKeySchedule: %v", err)
	}

	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("InterfaceByName failed: %v", err)
	}

	bt, err := NewBPFTagger(iface, ks, []byte("test-measurement"))
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("skipping test: insufficient privileges for eBPF: %v", err)
		}
		t.Fatalf("NewBPFTagger failed: %v", err)
	}
	defer bt.Close()

	if bt.MapKey() == 0 {
		t.Error("MapKey() returned 0")
	}

	pkt := []byte("dummy-packet")
	result, err := bt.TagPacket(pkt)
	if err != nil {
		t.Errorf("TagPacket failed: %v", err)
	}
	if string(result) != string(pkt) {
		t.Error("TagPacket unexpectedly modified packet")
	}
}
