// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build !wasip1

package debuglet

func invokeMeshStart([]byte) ([]byte, error)    { panic(offTarget) }
func invokeMeshSnapshot([]byte) ([]byte, error) { panic(offTarget) }
func invokeMeshStop([]byte) ([]byte, error)     { panic(offTarget) }
func invokeMeshTransfer([]byte) ([]byte, error) { panic(offTarget) }
