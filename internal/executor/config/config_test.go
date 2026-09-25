package config

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestPacketCounterConfig(t *testing.T) {
	for _, tc := range []struct {
		name, network, mode, iface string
		calls                      int
		disabled, invalid          bool
	}{
		{name: "defaults", iface: "discovered", calls: 1},
		{name: "auto", network: "packet_counter = 'auto'", mode: "auto", iface: "discovered", calls: 1},
		{name: "supplied auto", network: "interface = 'supplied'", iface: "supplied"},
		{name: "fallback skips default", network: "packet_counter = 'fallback'", mode: "fallback"},
		{name: "fallback ignores supplied", network: "packet_counter = 'fallback'\ninterface = 'does-not-exist'", mode: "fallback", iface: "does-not-exist"},
		{name: "explicit SCION disable", network: "disable_scion_environment = true\npacket_counter = 'fallback'", mode: "fallback", disabled: true},
		{name: "unknown", network: "packet_counter = 'ebpf'", invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := baseSections + "[network]\n" + tc.network + "\n"
			path := filepath.Join(t.TempDir(), "executor.toml")
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			calls := 0
			cfg, err := loadConfig(path, func() (*net.Interface, error) { calls++; return &net.Interface{Name: "discovered"}, nil })
			if tc.invalid {
				if err == nil {
					t.Fatal("unknown mode accepted")
				}
				if calls != 0 {
					t.Fatal("discovery happened before validation")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if calls != tc.calls || cfg.Network.PacketCounter != tc.mode || cfg.Network.Interface != tc.iface || cfg.Network.DisableSCIONEnvironment != tc.disabled {
				t.Fatalf("config %+v, discovery calls %d", cfg.Network, calls)
			}
			if cfg.Resources.MaxDebuglets != 100 || cfg.Logging.LogLevel != "info" || cfg.Dispatcher.YamuxAddr != cfg.Dispatcher.Addr {
				t.Fatalf("defaults changed: %+v", cfg)
			}
		})
	}
}
