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
	if os.Args[0] != "echo-server" && os.Args[0] != "echo-client" {
		fmt.Printf("DEBUGLET_DEMO_OK %s\n", os.Args[1])
	}
}

func run(args []string) error {
	if len(args) > 0 && (args[0] == "echo-server" || args[0] == "echo-client") {
		return echo(args)
	}

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

// echo exchanges a caller-selected nonce across two actual guest sockets. The
// original local demo protocol above remains unchanged.
func echo(args []string) error {
	server := args[0] == "echo-server"
	if (server && len(args) != 2) || (!server && len(args) != 3) || !validNonce(args[len(args)-1]) {
		return errors.New("invalid echo arguments")
	}
	var conn *debuglet.Conn
	var err error
	if server {
		conn, err = debuglet.AcceptTCP()
	} else {
		conn, err = debuglet.ConnectTCP(args[1])
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	expected := []byte("DEBUGLET_ECHO " + args[len(args)-1] + "\n")
	if !server {
		if err = conn.Write(expected); err != nil {
			return err
		}
	}
	received := make([]byte, len(expected))
	if _, err = io.ReadFull(conn, received); err != nil {
		return err
	}
	if !bytes.Equal(received, expected) {
		return errors.New("echo response does not match request")
	}
	if server {
		if err = conn.Write(expected); err != nil {
			return err
		}
	}
	fmt.Printf("DEBUGLET_ECHO_OK %s %s\n", args[0], args[len(args)-1])
	return nil
}
