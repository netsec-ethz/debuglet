// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd

package studio

import (
	"os/exec"
	"time"
)

func configureBuildProcess(command *exec.Cmd) { command.WaitDelay = 5 * time.Second }
