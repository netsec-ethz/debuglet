// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hostconn

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// refusingGuard is the decision of a policy that refuses the destination.
type refusingGuard struct {
	calls     int
	addresses []string
}

var errRefused = errors.New("refused by the network policy")

func (g *refusingGuard) CheckSocket(_, address string) error {
	g.calls++
	g.addresses = append(g.addresses, address)
	return errRefused
}

type admittingGuard struct{ calls int }

func (g *admittingGuard) CheckSocket(_, _ string) error {
	g.calls++
	return nil
}

// TestRefusedDestinationIsNeverContacted is the property the whole policy
// rests on: a destination the guard refuses receives no connection at all, not
// a connection that is closed afterwards.
func TestRefusedDestinationIsNeverContacted(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		accepted <- conn
	}()

	guard := &refusingGuard{}
	dialer, err := NewDialer(guard, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", listener.Addr().String())
	if err == nil {
		conn.Close()
		t.Fatal("the refused destination was dialled")
	}
	if !errors.Is(err, errRefused) {
		t.Fatalf("dial error = %v, want the guard's refusal", err)
	}
	if guard.calls != 1 {
		t.Errorf("the guard was consulted %d times, want once", guard.calls)
	}
	if got := guard.addresses[0]; got != listener.Addr().String() {
		t.Errorf("the guard saw %q, want the resolved destination %q", got, listener.Addr())
	}

	select {
	case conn := <-accepted:
		conn.Close()
		t.Fatal("the target accepted a connection although the policy refused it")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestAdmittedDestinationConnects(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		accepted <- struct{}{}
	}()

	guard := &admittingGuard{}
	dialer, err := NewDialer(guard, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("the admitted destination was not dialled: %v", err)
	}
	defer conn.Close()
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the target did not accept the admitted connection")
	}
	if guard.calls != 1 {
		t.Errorf("the guard was consulted %d times, want once", guard.calls)
	}
}

func TestDialerRequiresAGuard(t *testing.T) {
	if _, err := NewDialer(nil, nil); err == nil {
		t.Fatal("a dialer without a policy guard was created")
	}
}
