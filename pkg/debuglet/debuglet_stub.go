// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

//go:build !wasip1

// This stub lets the package (and therefore the whole module) build and test on
// the host. The host imports it shadows are only available inside a wasip1
// guest, so calling these off-target panics. Build a debuglet with
// `GOOS=wasip1 GOARCH=wasm` to get the real implementation.
package debuglet

const offTarget = "debuglet: SDK calls only work inside a wasip1 guest; build with GOOS=wasip1 GOARCH=wasm"

func dialTCP(addr string, tls bool) (*Conn, error) { panic(offTarget) }
func dialICMP4(addr string) (*Conn, error)         { panic(offTarget) }
func dialUDP(addr string) (*Conn, error)           { panic(offTarget) }
func acceptTCP() (*Conn, error)                    { panic(offTarget) }
func listenAddr() (string, error)                  { panic(offTarget) }
func listenUDPAddr() (string, error)               { panic(offTarget) }
func readFromUDP(buf []byte) (int, string, error)  { panic(offTarget) }

func (c *Conn) Write(b []byte) error        { panic(offTarget) }
func (c *Conn) Read(b []byte) (int, error)  { panic(offTarget) }
func (c *Conn) Drain() error                { panic(offTarget) }
func (c *Conn) Close() error                { panic(offTarget) }
func (c *Conn) RemoteAddr() (string, error) { panic(offTarget) }
