package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

const maxProtocolLine = 128

func main() {
	// Debuglet passes Args directly to WASI: there is no program-name element.
	if err := run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "demo exchange:", err)
		os.Exit(1)
	}
	fmt.Printf("DEBUGLET_DEMO_OK %s\n", os.Args[1])
}

func run(args []string) error {
	if len(args) != 2 || args[0] == "" || !validNonce(args[1]) {
		return errors.New("expected exactly target address and 32 lowercase hex nonce")
	}
	conn, err := debuglet.ConnectTCP(args[0])
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	want := []byte("DEBUGLET/1 " + args[1] + "\n")
	line := make([]byte, 0, maxProtocolLine)
	buffer := make([]byte, 4096)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			return fmt.Errorf("read reply before ACK: %w", err)
		}
		if n == 0 {
			return io.ErrNoProgress
		}
		if len(line)+n > maxProtocolLine {
			return errors.New("reply exceeds protocol line limit")
		}
		line = append(line, buffer[:n]...)
		if bytes.IndexByte(line, '\n') >= 0 {
			if !bytes.Equal(line, want) {
				return errors.New("unexpected target reply")
			}
			break
		}
	}
	if err := conn.Write([]byte("ACK " + args[1] + "\n")); err != nil {
		return fmt.Errorf("write ACK: %w", err)
	}
	n, err := conn.Read(buffer)
	if n != 0 {
		return errors.New("unexpected data after target reply")
	}
	if !errors.Is(err, io.EOF) {
		if err == nil {
			err = io.ErrNoProgress
		}
		return fmt.Errorf("wait for target EOF: %w", err)
	}
	return nil
}

func validNonce(nonce string) bool {
	if len(nonce) != 32 {
		return false
	}
	for _, c := range nonce {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
