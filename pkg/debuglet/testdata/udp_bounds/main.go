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
	"fmt"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

func main() {
	for i := 0; i < 9; i++ {
		buf := make([]byte, 16)
		n, from, err := debuglet.ReadFromUDP(buf)
		data := ""
		if n >= 0 && n <= len(buf) {
			data = string(buf[:n])
		}
		fmt.Printf("read%d n=%d fromlen=%d err=%t data=%q\n", i, n, len(from), err != nil, data)
	}
	for i := 0; i < 5; i++ {
		addr, err := debuglet.ListenAddr()
		fmt.Printf("tcp%d len=%d err=%t\n", i, len(addr), err != nil)
	}
	for i := 0; i < 5; i++ {
		addr, err := debuglet.ListenUDPAddr()
		fmt.Printf("udp%d len=%d err=%t\n", i, len(addr), err != nil)
	}
}
