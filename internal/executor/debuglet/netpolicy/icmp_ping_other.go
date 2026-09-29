// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build !unix

package netpolicy

import "errors"

func probePingSocket() error { return errors.ErrUnsupported }
