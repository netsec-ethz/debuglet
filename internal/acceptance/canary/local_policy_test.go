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

package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	executorconfig "github.com/netsec-ethz/debuglet/internal/executor/config"
	"github.com/netsec-ethz/debuglet/internal/readiness"
	"github.com/pelletier/go-toml/v2"
)

// TestLocalConfigurationReachesTheTargetItStarts covers the configuration this
// check writes for the candidate's executor. The check starts a TCP target on
// this machine and submits it as the run's allowed destination, so the
// executor it configures has to be one that may reach local targets. The
// network policy denies loopback unless the configuration asks for it, and a
// check whose executor is not told refuses its own target: the guest ends with
// an error, the target never sees an ACK, and the whole run phase fails.
//
// The daemon reads the file rather than the value, so this goes through the
// same write and load path the check uses. Some executor configuration fields
// carry no TOML tag, so the written keys are checked as well: a typed field
// that reaches disk under its Go name is a setting the daemon never reads.
func TestLocalConfigurationReachesTheTargetItStarts(t *testing.T) {
	dir := t.TempDir()
	cfg := localExecutorConfiguration(testExecutor, "v0.0.1-test", filepath.Join(dir, "executor.sqlite"),
		readiness.Record{GRPCAddr: "127.0.0.1:9001", HTTPAddr: "127.0.0.1:9000"})
	path := filepath.Join(dir, "executor.toml")
	if err := writeConfig(path, cfg); err != nil {
		t.Fatalf("write the candidate configuration: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the candidate configuration: %v", err)
	}
	for _, key := range []string{"[identity]", "[dispatcher]", "[network]", "executor_id =", "yamux_addr =",
		"packet_counter =", "disable_scion_environment =", "version =", "local_targets = true"} {
		if !strings.Contains(string(data), key) {
			t.Fatalf("the configuration is missing %q:\n%s", key, data)
		}
	}
	var restored executorconfig.ExecutorConfig
	if err := toml.Unmarshal(data, &restored); err != nil || !reflect.DeepEqual(cfg, restored) {
		t.Fatalf("the written configuration does not read back as the typed one: %+v %v", restored, err)
	}

	loaded, err := executorconfig.LoadConfig(path)
	if err != nil {
		t.Fatalf("the candidate executor would refuse this configuration: %v", err)
	}
	operator, err := loaded.Network.Policy.Compile()
	if err != nil {
		t.Fatalf("compile the configured policy: %v", err)
	}
	if err := operator.CheckAddr(netip.MustParseAddr("127.0.0.1")); err != nil {
		t.Fatalf("the configured executor cannot reach the target this check starts: %v", err)
	}
}
