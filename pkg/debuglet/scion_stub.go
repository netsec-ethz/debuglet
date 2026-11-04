// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build !wasip1

package debuglet

func invokeSCIONPaths([]byte) ([]byte, error)           { panic(offTarget) }
func invokeSCIONSelectPath([]byte) ([]byte, error)      { panic(offTarget) }
func invokeSCIONExchange([]byte) ([]byte, error)        { panic(offTarget) }
func invokeSCIONListenerAddress([]byte) ([]byte, error) { panic(offTarget) }
func invokeSCIONReceive([]byte) ([]byte, error)         { panic(offTarget) }
func invokeSCIONReply([]byte) ([]byte, error)           { panic(offTarget) }

func invokeSCIONQUICEchoStart([]byte) ([]byte, error) { panic(offTarget) }
func invokeSCIONQUICEchoStop([]byte) ([]byte, error)  { panic(offTarget) }
func invokeSCIONQUICExchange([]byte) ([]byte, error)  { panic(offTarget) }
