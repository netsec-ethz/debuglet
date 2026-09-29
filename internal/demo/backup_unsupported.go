// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build !linux

package demo

import "errors"

func renameBackup(string, string) error {
	return errors.New("state backup and restore require Linux")
}
