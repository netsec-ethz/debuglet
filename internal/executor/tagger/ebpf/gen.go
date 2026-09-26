// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package ebpf

//go:generate go tool bpf2go -tags linux -target bpfel tagger tagger.c
