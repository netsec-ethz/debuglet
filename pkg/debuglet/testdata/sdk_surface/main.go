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

// sdk_surface reaches every call of the Go guest SDK so that the compiled
// module imports the SDK's complete host surface. The compatibility suite
// compares that surface against the frozen guest ABI: an added, removed,
// renamed or retyped import fails the comparison and needs a new ABI
// identifier, because guests built against it cannot run on hosts that
// implement the old one.
//
// The calls never run; the guard depends on the guest's arguments so that the
// compiler cannot drop them.
package main

import (
	"fmt"
	"os"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

func main() {
	surface(len(os.Args) > 4096)
	fmt.Println("surface")
}

func surface(run bool) {
	if !run {
		return
	}
	tcp, _ := debuglet.ConnectTCP("127.0.0.1:1")
	tls, _ := debuglet.ConnectTLS("127.0.0.1:1")
	udp, _ := debuglet.ConnectUDP("127.0.0.1:1")
	icmp, _ := debuglet.ConnectICMP4("127.0.0.1")
	accepted, _ := debuglet.AcceptTCP()

	buf := make([]byte, 8)
	for _, conn := range []*debuglet.Conn{tcp, tls, udp, icmp, accepted} {
		fmt.Println(conn.Handle())
		conn.Read(buf)
		conn.Write(buf)
		conn.Drain()
		conn.RemoteAddr()
		conn.Close()
	}

	debuglet.ListenAddr()
	debuglet.ListenUDPAddr()
	debuglet.ReadFromUDP(buf)
}
