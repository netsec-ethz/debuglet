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

// sdk_io is the guest fixture for the SDK's behaviour at the host transfer
// bound: a stream payload larger than the bound is written completely, a
// datagram larger than it is refused, and a read fills at most the bound.
//
// os.Args[0] is the case name and os.Args[1] the target address.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

// oversize is larger than debuglet.MaxIOBytes.
const oversize = 2 * debuglet.MaxIOBytes

func main() {
	if len(os.Args) != 2 {
		fmt.Println("usage: case name and target address")
		os.Exit(2)
	}
	switch os.Args[0] {
	case "stream_write":
		streamWrite(os.Args[1])
	case "datagram_write":
		datagramWrite(os.Args[1])
	case "stream_read":
		streamRead(os.Args[1])
	default:
		fmt.Printf("unknown case %q\n", os.Args[0])
		os.Exit(2)
	}
}

func payload(n int) []byte {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = 'A'
	}
	return buf
}

// streamWrite offers more than one host call can carry; the peer counts what
// arrived.
func streamWrite(addr string) {
	conn, err := debuglet.ConnectTCP(addr)
	if err != nil {
		fmt.Printf("connect error=%v\n", err)
		os.Exit(1)
	}
	err = conn.Write(payload(oversize))
	fmt.Printf("stream_write offered=%d err=%v\n", oversize, err)
	conn.Close()
	fmt.Println("closed")
}

// datagramWrite proves that an oversized datagram is refused rather than
// truncated, and that one at the bound is sent.
func datagramWrite(addr string) {
	conn, err := debuglet.ConnectUDP(addr)
	if err != nil {
		fmt.Printf("connect error=%v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	err = conn.Write(payload(oversize))
	fmt.Printf("oversize refused=%t toolarge=%t\n", err != nil, errors.Is(err, debuglet.ErrTooLarge))

	err = conn.Write(payload(debuglet.MaxIOBytes))
	fmt.Printf("bound err=%v\n", err)
}

// streamRead offers a buffer larger than the bound and reports one read.
func streamRead(addr string) {
	conn, err := debuglet.ConnectTCP(addr)
	if err != nil {
		fmt.Printf("connect error=%v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	if err := conn.Write([]byte("GO\n")); err != nil {
		fmt.Printf("write error=%v\n", err)
		os.Exit(1)
	}
	buf := make([]byte, oversize)
	n, err := conn.Read(buf)
	fmt.Printf("stream_read buffer=%d n=%d err=%v\n", len(buf), n, err)
}
