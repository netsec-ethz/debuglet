//go:build !linux && !darwin

package main

import (
	"errors"
	"os"
)

func openManifestFile(string) (*os.File, error) {
	return nil, errors.New("local manifest files require Linux or Darwin")
}

func publishEvidence(string, []byte) error {
	return errors.New("local evidence files require Linux or Darwin")
}
