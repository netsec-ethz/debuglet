// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package executor

import (
	"context"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit"
)

// ebpfCounter reports the packet counter that used to decide the ICMP
// advertisement. Whether packets can be counted says nothing about whether
// this process may open a raw socket, so it must no longer decide it.
type ebpfCounter struct{ ratelimit.PacketCount }

func (ebpfCounter) Type() string { return "ebpf" }
func (ebpfCounter) Close() error { return nil }

// TestHelloAdvertisesICMPFromTheNetworkPolicy covers what the dispatcher is
// told: the operator's switch and the host's actual raw-socket privilege, not
// the packet counter's type.
func TestHelloAdvertisesICMPFromTheNetworkPolicy(t *testing.T) {
	// The privilege is a property of the process, not of the test: a runner
	// without it must advertise no ICMP even where the policy permits it.
	permitted := netpolicy.ICMPPermitted() == nil

	on, off := true, false
	for name, tc := range map[string]struct {
		icmp *bool
		want bool
	}{
		"omitted":  {icmp: nil, want: permitted},
		"enabled":  {icmp: &on, want: permitted},
		"disabled": {icmp: &off, want: false},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := fixtureConfig()
			cfg.Identity.ExecutorID = "policy-fixture"
			cfg.Network.Policy.ICMP = tc.icmp
			// A counter that would have advertised ICMP on its own.
			e := newFixtureExecutor(t, cfg, ebpfCounter{}, newFixtureMemoryStorage(t))
			resp, err := e.OnHello(context.Background(), nil)
			if err != nil {
				t.Fatalf("OnHello: %v", err)
			}
			if resp.GetIcmpEnabled() != tc.want {
				t.Errorf("advertised icmp_enabled=%v, want %v", resp.GetIcmpEnabled(), tc.want)
			}
		})
	}
}
