//go:build linux || darwin

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// Nonblocking open followed by fstat rejects FIFOs/devices without waiting for
// another process. No path or operating-system error is exposed to the caller.
func openManifestFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("cannot open local manifest")
	}
	f := os.NewFile(uintptr(fd), "local manifest")
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > manifestSizeLimit {
		_ = f.Close()
		return nil, errors.New("local manifest is not a bounded regular file")
	}
	return f, nil
}

func publishEvidence(path string, data []byte) error {
	invalid := errors.New("cannot publish local evidence in an owned private directory")
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return invalid
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Uid != uint32(os.Geteuid()) || stat.Mode&07777 != 0700 {
		return invalid
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return invalid
	}
	name := ".result-" + hex.EncodeToString(nonce[:])
	fileFD, err := unix.Openat(fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return invalid
	}
	defer unix.Unlinkat(fd, name, 0)
	f := os.NewFile(uintptr(fileFD), "local evidence temporary file")
	writeErr := f.Chmod(0600)
	if writeErr == nil {
		_, writeErr = f.Write(data)
	}
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		return invalid
	}
	// linkat publishes the complete inode atomically and fails if result.json
	// already exists, including a dangling symlink. Both names stay relative to
	// the validated directory descriptor, even if its pathname is replaced.
	if err := unix.Linkat(fd, name, fd, "result.json", 0); err != nil {
		return errors.New("cannot exclusively publish local evidence result")
	}
	if err := unix.Unlinkat(fd, name, 0); err != nil {
		return invalid
	}
	if err := unix.Fsync(fd); err != nil {
		return invalid
	}
	return nil
}
