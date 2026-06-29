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

//go:build !wasip1

// This stub lets the package (and therefore the whole module) build and test on
// the host. The host imports it shadows are only available inside a wasip1
// guest, so calling these off-target panics. Build a debuglet with
// `GOOS=wasip1 GOARCH=wasm` to get the real implementation.
package debuglet

const offTarget = "debuglet: SDK calls only work inside a wasip1 guest; build with GOOS=wasip1 GOARCH=wasm"

func dialTCP(addr string, tls bool) (*Conn, error) { panic(offTarget) }
func dialICMP4(addr string) (*Conn, error)         { panic(offTarget) }
func acceptTCP() (*Conn, error)                    { panic(offTarget) }

func (c *Conn) Send(b []byte) error          { panic(offTarget) }
func (c *Conn) Receive(b []byte) (int, error) { panic(offTarget) }
func (c *Conn) Close() error                  { panic(offTarget) }
