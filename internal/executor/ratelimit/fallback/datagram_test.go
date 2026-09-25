// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package fallback

import (
	"bytes"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"
)

// The tests in this file run the limiter over real loopback UDP sockets. A
// datagram socket keeps message boundaries: one read takes one whole datagram
// off the socket and discards whatever does not fit the buffer, and one write
// sends one datagram. A limiter that cuts the buffer down to what it admits,
// or sends an admitted piece at a time, destroys datagrams that a stream would
// merely delay.

const (
	// datagramRate is the budget of both limits in bytes per second: a
	// datagram of a few kilobytes spans several rate-seconds, and every test
	// still ends within seconds.
	datagramRate = 1000
	// oversizedDatagram spans two and a half rate-seconds.
	oversizedDatagram = 2500
	// wakeSlack is the headroom an upper time bound leaves for scheduling on
	// a loaded host running the race detector.
	wakeSlack = 3 * time.Second
	// quietPeriod is how long the peer keeps listening after the last
	// datagram before it concludes that nothing more was sent. Every send
	// under test has returned before the peer starts listening.
	quietPeriod = 300 * time.Millisecond
)

// udpPair returns a limited UDP socket connected to an unlimited peer. The
// limited side must be connected, because Attach keys its limits by the remote
// address; the peer is an ordinary socket that sends with WriteToUDP and
// receives with ReadFromUDP.
func udpPair(t *testing.T, rate app.Bitrate) (*FallbackConn, *net.UDPConn) {
	t.Helper()
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	raw, err := net.DialUDP("udp", nil, peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	return newTestConn(t, raw, rate, rate), peer
}

// udpDatagram returns size bytes that start with marker and continue with a
// position-dependent pattern, so a truncated, split or different datagram
// never compares equal to it.
func udpDatagram(marker string, size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(i*7 + 3)
	}
	copy(b, marker)
	return b
}

// sendToLimited sends one datagram from the peer to the limited socket.
func sendToLimited(t *testing.T, peer *net.UDPConn, fc *FallbackConn, b []byte) {
	t.Helper()
	if n, err := peer.WriteToUDP(b, fc.LocalAddr().(*net.UDPAddr)); n != len(b) || err != nil {
		t.Fatalf("peer WriteToUDP = (%d, %v), want (%d, nil)", n, err, len(b))
	}
}

// peerReceive returns the datagrams that reach the peer. It waits up to first
// for one to arrive, and after each arrival until quietPeriod passes without
// another.
func peerReceive(t *testing.T, peer *net.UDPConn, first time.Duration) [][]byte {
	t.Helper()
	var got [][]byte
	buf := make([]byte, 64<<10)
	for wait := first; ; wait = quietPeriod {
		if err := peer.SetReadDeadline(time.Now().Add(wait)); err != nil {
			t.Fatalf("peer SetReadDeadline: %v", err)
		}
		n, _, err := peer.ReadFromUDP(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return got
		}
		if err != nil {
			t.Fatalf("peer ReadFromUDP: %v", err)
		}
		got = append(got, bytes.Clone(buf[:n]))
	}
}

func datagramSizes(datagrams [][]byte) []int {
	sizes := make([]int, len(datagrams))
	for i, d := range datagrams {
		sizes[i] = len(d)
	}
	return sizes
}

// expectAtPeer fails unless want reaches the peer as exactly one datagram.
func expectAtPeer(t *testing.T, peer *net.UDPConn, want []byte) {
	t.Helper()
	got := peerReceive(t, peer, boundedWait)
	if len(got) != 1 || !bytes.Equal(got[0], want) {
		t.Errorf("peer received %d datagrams of sizes %v, want exactly the %d-byte datagram, intact",
			len(got), datagramSizes(got), len(want))
	}
}

// expectNothingAtPeer fails if any datagram reaches the peer.
func expectNothingAtPeer(t *testing.T, peer *net.UDPConn) {
	t.Helper()
	if got := peerReceive(t, peer, quietPeriod); len(got) != 0 {
		t.Errorf("peer received %d datagrams of sizes %v, want none", len(got), datagramSizes(got))
	}
}

// setRates installs rate on both limits of fc.
func setRates(t *testing.T, fc *FallbackConn, rate app.Bitrate) {
	t.Helper()
	if err := fc.count.SetLimit(testAddr, fc.id, rate); err != nil {
		t.Fatalf("SetLimit: %v", err)
	}
	if err := fc.count.SetExecLimit(fc.id, rate); err != nil {
		t.Fatalf("SetExecLimit: %v", err)
	}
}

// startIO runs op on its own goroutine and returns a channel that is closed
// once op has returned. Cleanup closes fc and joins the goroutine, so a failed
// test cannot leave an operation behind.
func startIO(t *testing.T, fc *FallbackConn, op func()) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		op()
	}()
	t.Cleanup(func() {
		_ = fc.Close()
		<-done
	})
	return done
}

// waitForReservation returns once the operation under test has reserved its
// bandwidth, which takes the destination balance below the seeded one.
func waitForReservation(t *testing.T, fc *FallbackConn, seeded app.Bitrate) {
	t.Helper()
	waitUntil(t, func() bool {
		dest, ok, _, _ := bucketTokens(fc)
		return ok && dest < seeded
	}, "reservation by the waiting operation")
}

// expectRefunded fails if a bucket that still exists holds less than it was
// seeded with: an operation that sent and received nothing keeps none of its
// reservation. No seed is a debt, so this also keeps the accounting
// nonnegative.
func expectRefunded(t *testing.T, fc *FallbackConn, seeded app.Bitrate) {
	t.Helper()
	dest, destOK, exec, execOK := bucketTokens(fc)
	if destOK && dest < seeded {
		t.Errorf("destination bucket = %d bits, want at least the %d bits it held before the canceled operation", dest, seeded)
	}
	if execOK && exec < seeded {
		t.Errorf("executor bucket = %d bits, want at least the %d bits it held before the canceled operation", exec, seeded)
	}
}

// checkElapsed fails when an operation returned before the bucket arithmetic
// allows, or long after it.
func checkElapsed(t *testing.T, what string, elapsed, earliest, latest time.Duration) {
	t.Helper()
	if elapsed < earliest {
		t.Errorf("%s returned after %v, want no earlier than %v", what, elapsed, earliest)
	}
	if elapsed > latest {
		t.Errorf("%s returned after %v, want no later than %v", what, elapsed, latest)
	}
}

// transferTime is how long size bytes take at rate bytes per second.
func transferTime(size, rate int) time.Duration {
	return time.Duration(size) * time.Second / time.Duration(rate)
}

// A datagram larger than one rate-second is returned by one Read, whole, into
// a buffer that holds it, once the wait its size implies has passed. The next
// Read returns the next datagram: nothing of the first is left over.
func TestUDPReadReturnsOversizedDatagramIntact(t *testing.T) {
	fc, peer := udpPair(t, app.FromBytes(datagramRate))
	if err := fc.SetReadDeadline(time.Now().Add(boundedWait)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	want := udpDatagram("oversized read", oversizedDatagram)
	sendToLimited(t, peer, fc, want)

	// Drained buckets: the read charges the datagram it took off the socket
	// and returns once that charge is paid, whatever the size of the buffer.
	start := time.Now()
	seedBuckets(t, fc, 0, 0)
	buf := make([]byte, oversizedDatagram+datagramRate/2)
	n, err := fc.Read(buf)
	elapsed := time.Since(start)
	if n != len(want) || err != nil || !bytes.Equal(buf[:n], want) {
		t.Errorf("Read = (%d, %v), want (%d, nil) with the datagram intact", n, err, len(want))
	}
	earliest := transferTime(len(want), datagramRate)
	checkElapsed(t, "Read", elapsed, earliest, earliest+wakeSlack)

	next := udpDatagram("next read", 32)
	sendToLimited(t, peer, fc, next)
	n, err = fc.Read(buf[:64])
	if n != len(next) || err != nil || !bytes.Equal(buf[:n], next) {
		t.Errorf("next Read = (%d, %v), want (%d, nil) with the next datagram intact", n, err, len(next))
	}
}

// A small datagram received into a large buffer from drained buckets waits
// for its own size only: a buffer larger than the datagram costs nothing.
func TestUDPReadChargesTheDatagramNotTheBuffer(t *testing.T) {
	fc, peer := udpPair(t, app.FromBytes(datagramRate))
	if err := fc.SetReadDeadline(time.Now().Add(boundedWait)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	want := udpDatagram("small", 32)
	sendToLimited(t, peer, fc, want)

	start := time.Now()
	seedBuckets(t, fc, 0, 0)
	buf := make([]byte, oversizedDatagram+datagramRate/2)
	n, err := fc.Read(buf)
	elapsed := time.Since(start)
	if n != len(want) || err != nil || !bytes.Equal(buf[:n], want) {
		t.Errorf("Read = (%d, %v), want (%d, nil) with the datagram intact", n, err, len(want))
	}
	// Half the time the buffer would take leaves more than a second for
	// scheduling and still rules out a charge for the buffer.
	checkElapsed(t, "Read", elapsed, transferTime(len(want), datagramRate), transferTime(len(buf), datagramRate)/2)
}

// One Write sends one datagram, whatever its size: smaller than a rate-second,
// larger than one, or empty.
func TestUDPWriteSendsOneDatagram(t *testing.T) {
	for _, tc := range []struct {
		name    string
		size    int
		drained bool
	}{
		{"smaller than a rate-second", datagramRate / 2, false},
		{"larger than a rate-second", oversizedDatagram, true},
		{"empty", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fc, peer := udpPair(t, app.FromBytes(datagramRate))
			if err := fc.SetWriteDeadline(time.Now().Add(boundedWait)); err != nil {
				t.Fatalf("SetWriteDeadline: %v", err)
			}
			payload := udpDatagram(tc.name, tc.size)

			// The small and the empty datagram find fresh, full buckets. The
			// large one starts from drained buckets and owes its whole size.
			var earliest time.Duration
			start := time.Now()
			if tc.drained {
				seedBuckets(t, fc, 0, 0)
				earliest = transferTime(tc.size, datagramRate)
			}
			n, err := fc.Write(payload)
			checkElapsed(t, "Write", time.Since(start), earliest, earliest+wakeSlack)
			if n != len(payload) || err != nil {
				t.Errorf("Write = (%d, %v), want (%d, nil)", n, err, len(payload))
			}
			expectAtPeer(t, peer, payload)
		})
	}
}

// A buffer smaller than the datagram gets what a datagram socket on Linux
// gives: the buffer filled with the start of the datagram and no error, while
// the socket discards the rest, so the next Read returns the next datagram.
// The limiter hands the socket the whole buffer, even one larger than a
// rate-second.
func TestUDPReadIntoSmallerBufferTruncatesAsTheSocketDoes(t *testing.T) {
	fc, peer := udpPair(t, app.FromBytes(datagramRate))
	if err := fc.SetReadDeadline(time.Now().Add(boundedWait)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	first := udpDatagram("truncated", oversizedDatagram)
	sendToLimited(t, peer, fc, first)
	buf := make([]byte, datagramRate*3/2)
	n, err := fc.Read(buf)
	if n != len(buf) || err != nil || !bytes.Equal(buf[:n], first[:len(buf)]) {
		t.Errorf("Read into %d bytes = (%d, %v), want (%d, nil) with the start of the %d-byte datagram",
			len(buf), n, err, len(buf), len(first))
	}

	next := udpDatagram("after truncation", 32)
	sendToLimited(t, peer, fc, next)
	n, err = fc.Read(buf[:64])
	if n != len(next) || err != nil || !bytes.Equal(buf[:n], next) {
		t.Errorf("next Read = (%d, %v), want (%d, nil) with the next datagram intact", n, err, len(next))
	}
}

// Canceling a datagram write's wait, by a deadline or by Close, returns the
// usual error and leaves no trace: nothing reaches the peer and the whole
// reservation is returned. The write starts from full buckets: one rate-second
// is available at once, and a limiter that sends that much as a datagram of
// its own leaves the fragment at the peer when the rest is canceled. A read
// has no such wait to cancel: it takes the datagram off the socket before it
// waits, see TestUDPCutShortReadKeepsTheCharge.
func TestUDPCanceledDatagramWaitLeavesNoTrace(t *testing.T) {
	full := app.FromBytes(datagramRate)
	for _, tc := range []struct {
		name    string
		close   bool
		wantErr error
	}{
		{"write deadline", false, os.ErrDeadlineExceeded},
		{"write close", true, net.ErrClosed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fc, peer := udpPair(t, full)
			payload := udpDatagram(tc.name, oversizedDatagram)
			if err := fc.SetDeadline(time.Now().Add(boundedWait)); err != nil {
				t.Fatalf("SetDeadline: %v", err)
			}
			seedBuckets(t, fc, full, full)

			var n int
			var err error
			done := startIO(t, fc, func() { n, err = fc.Write(payload) })
			waitForReservation(t, fc, 0)
			var cancelErr error
			if tc.close {
				cancelErr = fc.Close()
			} else {
				cancelErr = fc.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
			}
			if cancelErr != nil {
				t.Fatalf("cancel the waiting Write: %v", cancelErr)
			}
			waitBounded(t, done, "Write with its wait canceled", func() { _ = fc.Close() })
			if n != 0 || !errors.Is(err, tc.wantErr) {
				t.Errorf("Write = (%d, %v), want (0, %v)", n, err, tc.wantErr)
			}
			expectRefunded(t, fc, full)
			expectNothingAtPeer(t, peer)
		})
	}
}

// A read takes the datagram off the socket before it waits for the charge, so
// the datagram is the caller's from then on. A wait that the read deadline or
// Close cuts short returns the datagram intact and keeps its charge: the next
// call reports the deadline or the closure, and the next datagram is admitted
// only once the debt the first one left is paid.
func TestUDPCutShortReadKeepsTheCharge(t *testing.T) {
	for _, tc := range []struct {
		name    string
		close   bool
		wantErr error
	}{
		{"read deadline", false, os.ErrDeadlineExceeded},
		{"read close", true, net.ErrClosed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fc, peer := udpPair(t, app.FromBytes(datagramRate))
			payload := udpDatagram(tc.name, oversizedDatagram)
			sendToLimited(t, peer, fc, payload)
			if err := fc.SetReadDeadline(time.Now().Add(boundedWait)); err != nil {
				t.Fatalf("SetReadDeadline: %v", err)
			}
			start := time.Now()
			seedBuckets(t, fc, 0, 0)

			buf := make([]byte, oversizedDatagram+datagramRate/2)
			var n int
			var err error
			done := startIO(t, fc, func() { n, err = fc.Read(buf) })
			waitForReservation(t, fc, 0)
			var cancelErr error
			if tc.close {
				cancelErr = fc.Close()
			} else {
				cancelErr = fc.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			}
			if cancelErr != nil {
				t.Fatalf("cancel the waiting Read: %v", cancelErr)
			}
			waitBounded(t, done, "Read with its wait cut short", func() { _ = fc.Close() })
			elapsed := time.Since(start)
			if n != len(payload) || err != nil || !bytes.Equal(buf[:n], payload) {
				t.Fatalf("Read = (%d, %v), want (%d, nil) with the datagram intact", n, err, len(payload))
			}
			if paid := transferTime(len(payload), datagramRate); elapsed >= paid {
				t.Fatalf("Read returned after %v, not before the %v its charge takes: the wait was not cut short", elapsed, paid)
			}
			if n, err := fc.Read(buf); n != 0 || !errors.Is(err, tc.wantErr) {
				t.Errorf("next Read = (%d, %v), want (0, %v)", n, err, tc.wantErr)
			}
			if tc.close {
				return
			}

			// The charge was kept: the buckets owe what the time since the
			// seed has not yet paid of the datagram.
			if dest, _, exec, _ := bucketTokens(fc); dest >= 0 || exec >= 0 {
				t.Errorf("buckets = %d and %d bits, want the debt of the returned datagram", dest, exec)
			}
			// The next datagram is admitted only once the first one is paid.
			if err := fc.SetReadDeadline(time.Now().Add(boundedWait)); err != nil {
				t.Fatalf("SetReadDeadline: %v", err)
			}
			next := udpDatagram("after the debt", 32)
			sendToLimited(t, peer, fc, next)
			n, err = fc.Read(buf)
			if n != len(next) || err != nil || !bytes.Equal(buf[:n], next) {
				t.Errorf("next Read = (%d, %v), want (%d, nil) with the next datagram intact", n, err, len(next))
			}
			earliest := transferTime(len(payload)+len(next), datagramRate)
			checkElapsed(t, "Both reads", time.Since(start), earliest, earliest+wakeSlack)
		})
	}
}

func TestUDPEmptyDatagramRequiresPermission(t *testing.T) {
	for _, tc := range []struct {
		name   string
		revoke func(*FallbackConn) error
	}{
		{"zero destination", func(f *FallbackConn) error { return f.count.SetLimit(testAddr, f.id, 0) }},
		{"zero executor", func(f *FallbackConn) error { return f.count.SetExecLimit(f.id, 0) }},
		{"deleted destination", func(f *FallbackConn) error { return f.count.DeleteLimit(f.ipv6, f.id) }},
		{"deleted executor", func(f *FallbackConn) error { return f.count.DeleteExecLimit(f.id) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fc, peer := udpPair(t, app.FromBytes(datagramRate))
			if err := tc.revoke(fc); err != nil {
				t.Fatal(err)
			}
			if err := fc.SetWriteDeadline(time.Now().Add(boundedWait)); err != nil {
				t.Fatal(err)
			}
			if n, err := fc.Write(nil); n != 0 || err == nil {
				t.Errorf("Write(nil) after revocation = (%d, %v), want (0, an error)", n, err)
			}
			expectNothingAtPeer(t, peer)
		})
	}
}

// A rate change reaches a datagram that already waits for its reservation.
// Lowered, the datagram waits for what the new rate still owes; raised, it
// leaves as soon as the new rate allows; revoked, it is not sent at all. Each
// datagram is one rate-second at the old rate, so the old rate sends it whole.
func TestUDPRateChangeReachesWaitingDatagram(t *testing.T) {
	t.Run("lowered", func(t *testing.T) {
		const before, after = 3 * datagramRate, datagramRate
		fc, peer := udpPair(t, app.FromBytes(before))
		if err := fc.SetWriteDeadline(time.Now().Add(boundedWait)); err != nil {
			t.Fatalf("SetWriteDeadline: %v", err)
		}
		payload := udpDatagram("lowered", before)
		start := time.Now()
		seedBuckets(t, fc, 0, 0)
		var n int
		var err error
		var returned time.Time
		done := startIO(t, fc, func() {
			n, err = fc.Write(payload)
			returned = time.Now()
		})
		waitForReservation(t, fc, 0)
		setRates(t, fc, app.FromBytes(after))
		changed := time.Since(start)
		if oldWait := transferTime(len(payload), before); changed >= oldWait {
			t.Fatalf("rate lowered %v after the start, not within the %v wait", changed, oldWait)
		}
		waitBounded(t, done, "Write after the rate was lowered", func() { _ = fc.Close() })
		if n != len(payload) || err != nil {
			t.Errorf("Write = (%d, %v), want (%d, nil)", n, err, len(payload))
		}
		// Until the change the buckets gained at most the old rate and after
		// it at most the new one, so the datagram cannot be paid for sooner.
		owed := float64(len(payload)) - changed.Seconds()*before
		earliest := changed + time.Duration(owed/after*float64(time.Second))
		checkElapsed(t, "Write", returned.Sub(start), earliest, transferTime(len(payload), after)+wakeSlack)
		expectAtPeer(t, peer, payload)
	})

	t.Run("raised", func(t *testing.T) {
		const before, after = datagramRate, 1 << 20
		// Five rate-seconds owed from earlier traffic make the old wait long
		// enough to tell apart from the new one on a loaded host.
		const debt = 5 * before
		fc, peer := udpPair(t, app.FromBytes(before))
		if err := fc.SetWriteDeadline(time.Now().Add(boundedWait)); err != nil {
			t.Fatalf("SetWriteDeadline: %v", err)
		}
		payload := udpDatagram("raised", before)
		oldWait := transferTime(debt+len(payload), before)
		start := time.Now()
		seedBuckets(t, fc, -app.FromBytes(debt), -app.FromBytes(debt))
		var n int
		var err error
		var returned time.Time
		done := startIO(t, fc, func() {
			n, err = fc.Write(payload)
			returned = time.Now()
		})
		waitForReservation(t, fc, -app.FromBytes(debt))
		setRates(t, fc, app.FromBytes(after))
		if changed := time.Since(start); changed >= oldWait/2 {
			t.Fatalf("rate raised %v after the start, too late to tell the %v wait from a shorter one", changed, oldWait)
		}
		waitBounded(t, done, "Write after the rate was raised", func() { _ = fc.Close() })
		if n != len(payload) || err != nil {
			t.Errorf("Write = (%d, %v), want (%d, nil)", n, err, len(payload))
		}
		// The new rate pays the rest within milliseconds; half the old wait
		// leaves seconds for scheduling and still rules out the old rate.
		checkElapsed(t, "Write", returned.Sub(start), 0, oldWait/2)
		expectAtPeer(t, peer, payload)
	})

	t.Run("revoked", func(t *testing.T) {
		const before = 3 * datagramRate
		fc, peer := udpPair(t, app.FromBytes(before))
		if err := fc.SetWriteDeadline(time.Now().Add(boundedWait)); err != nil {
			t.Fatalf("SetWriteDeadline: %v", err)
		}
		payload := udpDatagram("revoked", before)
		oldWait := transferTime(len(payload), before)
		start := time.Now()
		seedBuckets(t, fc, 0, 0)
		var n int
		var err error
		done := startIO(t, fc, func() { n, err = fc.Write(payload) })
		waitForReservation(t, fc, 0)
		setRates(t, fc, 0)
		if changed := time.Since(start); changed >= oldWait {
			t.Fatalf("rate revoked %v after the start, not within the %v wait", changed, oldWait)
		}
		// A zero rate admits nothing. The deadline lies well past the moment
		// the old rate would have sent the datagram, and it ends a wait that
		// could otherwise last forever.
		if serr := fc.SetWriteDeadline(time.Now().Add(oldWait + time.Second)); serr != nil {
			t.Fatalf("SetWriteDeadline: %v", serr)
		}
		waitBounded(t, done, "Write after the rate was revoked", func() { _ = fc.Close() })
		if n != 0 || err == nil {
			t.Errorf("Write = (%d, %v), want (0, an error): a revoked rate admits nothing", n, err)
		}
		expectRefunded(t, fc, 0)
		expectNothingAtPeer(t, peer)
	})
}
