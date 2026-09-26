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

package config

import (
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
)

// TestPolicyKeysKeepTheirDocumentedDefaults covers a file that writes no
// policy at all: the transports this build supports are on, SCION is off,
// loopback stays reachable and every port is permitted.
func TestPolicyKeysKeepTheirDocumentedDefaults(t *testing.T) {
	cfg, _, err := load(t, baseSections+"[network]\npacket_counter='fallback'\n")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	spec := cfg.Network.Policy.Spec()
	if spec != netpolicy.Defaults() {
		t.Fatalf("an unwritten policy = %+v, want the documented defaults %+v", spec, netpolicy.Defaults())
	}
	operator, err := cfg.Network.Policy.Compile()
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !operator.Enabled(netpolicy.TCP) || operator.Enabled(netpolicy.SCION) {
		t.Error("the default transports are not the documented ones")
	}
	// A deployment that never writes the section must not be reachable into
	// its own host: local targets are something an operator asks for.
	if err := operator.CheckAddr(netip.MustParseAddr("127.0.0.1")); err == nil {
		t.Error("a configuration without a policy section reaches loopback services")
	}
}

// TestLocalProfileEnablesLocalTargets covers the configuration the repository
// ships for the local environment: it is the one that says it measures against
// this machine.
func TestLocalProfileEnablesLocalTargets(t *testing.T) {
	path := filepath.Join("..", "..", "..", "configs", "executor", "executor.toml")
	cfg, err := loadConfig(path, func() (*net.Interface, error) { return &net.Interface{Name: "discovered"}, nil })
	if err != nil {
		t.Fatalf("load the repository configuration: %v", err)
	}
	operator, err := cfg.Network.Policy.Compile()
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if err := operator.CheckAddr(netip.MustParseAddr("127.0.0.1")); err != nil {
		t.Errorf("the local environment cannot reach its own targets: %v", err)
	}
	// The advertised listener address is not a destination, and the policy
	// does not change what the executor publishes; the local profile offers
	// no public listener, and that stays as configured.
	if cfg.Network.PublicHost != "" {
		t.Errorf("network.public_host = %q, want the empty address the local profile configures", cfg.Network.PublicHost)
	}
}

// TestPolicyKeysAreRead covers a file that writes them: each switch reaches
// the compiled policy, and an omitted switch keeps its default next to one
// that is set.
func TestPolicyKeysAreRead(t *testing.T) {
	body := baseSections + `[network]
packet_counter='fallback'

[network.policy]
udp = false
scion = true
local_targets = false
denied_destinations = "10.0.0.0/8, opted-out.example"
permitted_ports = "80,443,8000-8100"
`
	cfg, _, err := load(t, body)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	spec := cfg.Network.Policy.Spec()
	if spec.UDP || !spec.SCION || spec.LocalTargets {
		t.Errorf("policy switches = %+v, want udp off, scion on and local targets off", spec)
	}
	if !spec.TCP || !spec.TLS || !spec.ICMP || !spec.Inbound {
		t.Errorf("an omitted switch lost its default: %+v", spec)
	}
	operator, err := cfg.Network.Policy.Compile()
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if operator.Enabled(netpolicy.UDP) {
		t.Error("udp stayed enabled although the file switched it off")
	}
	if err := operator.CheckPort(22); err == nil {
		t.Error("a port outside the permitted ranges was accepted")
	}
	if err := operator.CheckHost("opted-out.example"); err == nil {
		t.Error("an opted-out destination was accepted")
	}
}

func TestPolicyRejectsUnusableValues(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{
			"misspelled key",
			baseSections + "[network.policy]\ntpc = false\n",
			`unsupported configuration key "network.policy.tpc"`,
		},
		{
			"denied range",
			baseSections + "[network.policy]\ndenied_destinations = '10.0.0.0/33'\n",
			"denied_destinations",
		},
		{
			"permitted ports",
			baseSections + "[network.policy]\npermitted_ports = '443-80'\n",
			"permitted_ports",
		},
		{
			// A switch written as text names the field it could not fill.
			"switch type",
			baseSections + "[network.policy]\ntcp = 'yes'\n",
			"PolicyConfig.TCP",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, calls, err := load(t, tc.body)
			if err == nil {
				t.Fatal("an unusable policy was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %q", err, tc.want)
			}
			if calls != 0 {
				t.Errorf("the host was consulted %d times before the file was accepted", calls)
			}
		})
	}
}
