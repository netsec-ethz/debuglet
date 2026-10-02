//go:build !linux

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package debuglet

import (
	"errors"
	"os"
)

func restrictWorker() error { return errors.New("isolated workers require Linux") }

func workerPair() (*os.File, *os.File, error) {
	return nil, nil, errors.New("isolated workers require Linux")
}

func verifyWorkerParent() error { return errors.New("isolated workers require Linux") }
