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

package debuglet

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

type udpFromResult struct {
	n, addrLen int32
	data, addr string
}

func TestSDKUDPBoundsWASM(t *testing.T) {
	guest := buildGuest(t, "udp_bounds")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigInterpreter().WithCloseOnContextDone(true))
	defer r.Close(ctx)
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		t.Fatal(err)
	}

	reads := []udpFromResult{
		{n: -1, addrLen: 1, addr: "a"},
		{n: 17, addrLen: 1, addr: "a"},
		{n: 16, addrLen: 1, data: strings.Repeat("x", 16), addr: "a"},
		{n: 0, addrLen: 4, addr: "peer"},
		{n: 5, addrLen: 4, data: "hello", addr: "peer"},
		{n: 1, addrLen: 0, data: "x"},
		{n: 1, addrLen: -1, data: "x"},
		{n: 1, addrLen: 65, data: "x"},
		{n: 1, addrLen: 64, data: "x", addr: strings.Repeat("a", 64)},
	}
	addressResults := map[string][]int32{
		"get_tcp_addr": {513, 512, 0, 4, -1},
		"get_udp_addr": {513, 512, 0, 4, -1},
	}
	b := r.NewHostModuleBuilder("env")
	b.NewFunctionBuilder().WithFunc(func(_ context.Context, mod api.Module, recvp, recvLen, senderp, senderLen, addrLenp uint32) int32 {
		if recvLen != 16 || senderLen != 64 || len(reads) == 0 {
			t.Fatalf("unexpected receive_udp_from buffers/count: %d, %d, remaining=%d", recvLen, senderLen, len(reads))
		}
		res := reads[0]
		reads = reads[1:]
		if res.data != "" && !mod.Memory().Write(recvp, []byte(res.data)) {
			t.Fatal("write receive buffer")
		}
		if res.addr != "" && !mod.Memory().Write(senderp, []byte(res.addr)) {
			t.Fatal("write sender buffer")
		}
		if !mod.Memory().WriteUint32Le(addrLenp, uint32(res.addrLen)) {
			t.Fatal("write sender length")
		}
		return res.n
	}).Export("receive_udp_from")
	for _, name := range []string{"get_tcp_addr", "get_udp_addr"} {
		name := name
		b.NewFunctionBuilder().WithFunc(func(_ context.Context, mod api.Module, p, n uint32) int32 {
			results := addressResults[name]
			if n != 512 || len(results) == 0 {
				t.Fatalf("unexpected %s buffer/count: %d, remaining=%d", name, n, len(results))
			}
			result := results[0]
			addressResults[name] = results[1:]
			if result > 0 && result <= 512 && !mod.Memory().Write(p, bytes.Repeat([]byte{'a'}, int(result))) {
				t.Fatalf("write %s buffer", name)
			}
			return result
		}).Export(name)
	}
	if _, err := b.Instantiate(ctx); err != nil {
		t.Fatal(err)
	}

	wasm, err := os.ReadFile(guest)
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	_, err = r.InstantiateWithConfig(ctx, wasm, wazero.NewModuleConfig().WithStdout(&stdout))
	if err != nil {
		t.Fatalf("guest trapped: %v\nstdout:\n%s", err, stdout.String())
	}
	want := strings.Join([]string{
		`read0 n=0 fromlen=0 err=true data=""`,
		`read1 n=0 fromlen=0 err=true data=""`,
		`read2 n=16 fromlen=1 err=false data="xxxxxxxxxxxxxxxx"`,
		`read3 n=0 fromlen=4 err=false data=""`,
		`read4 n=5 fromlen=4 err=false data="hello"`,
		`read5 n=1 fromlen=0 err=false data="x"`,
		`read6 n=0 fromlen=0 err=true data=""`,
		`read7 n=0 fromlen=0 err=true data=""`,
		`read8 n=1 fromlen=64 err=false data="x"`,
		`tcp0 len=0 err=true`, `tcp1 len=512 err=false`, `tcp2 len=0 err=false`, `tcp3 len=4 err=false`, `tcp4 len=0 err=true`,
		`udp0 len=0 err=true`, `udp1 len=512 err=false`, `udp2 len=0 err=false`, `udp3 len=4 err=false`, `udp4 len=0 err=true`,
	}, "\n") + "\n"
	if stdout.String() != want {
		t.Errorf("stdout mismatch\n got:\n%s\nwant:\n%s", stdout.String(), want)
	}
	if len(reads) != 0 || len(addressResults["get_tcp_addr"]) != 0 || len(addressResults["get_udp_addr"]) != 0 {
		t.Errorf("script results left: reads=%d tcp=%d udp=%d", len(reads), len(addressResults["get_tcp_addr"]), len(addressResults["get_udp_addr"]))
	}
}
