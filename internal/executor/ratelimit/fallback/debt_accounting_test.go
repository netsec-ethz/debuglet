package fallback

import (
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"
)

// A token bucket holds bits and a write reserves bytes. Rounding the balance
// to whole bytes before comparing the two loses every debt smaller than a
// byte, and a balance of exactly one byte owed used to round to nothing owed
// at all, so the reservation that followed was granted a second too early.
// The cases below reserve one byte from a bucket seeded with an exact balance
// and compare the wait against the arithmetic, not against a throughput.

// debtRate is one byte per second: a wait in bytes and a wait in bits are the
// same number of seconds apart, so every expectation below is exact.
const debtRate = app.Bitrate(8)

// seedBuckets installs an exact balance on both accounting levels and stamps
// them with the current instant. At debtRate the refill between the stamp and
// the reservation stays far below a single bit, so the reservation is decided
// by the seeded balance alone.
func seedBuckets(t *testing.T, fc *FallbackConn, dest, exec app.Bitrate) {
	t.Helper()
	now := time.Now()
	fc.count.mu.Lock()
	defer fc.count.mu.Unlock()
	fc.count.packetSize[debugletKey{id: fc.id, dest: fc.ipv6}] = &bucketState{last: now, tokens: dest}
	fc.count.execPacketSize[fc.id] = &bucketState{last: now, tokens: exec}
}

func TestReservationWaitsForTheBalanceItFinds(t *testing.T) {
	for _, tc := range []struct {
		name    string
		tokens  app.Bitrate
		waitFor time.Duration
	}{
		{"one byte owed", -8, 2 * time.Second},
		{"two bytes owed", -16, 3 * time.Second},
		{"one bit owed", -1, time.Second * 9 / 8},
		{"seven bits owed", -7, time.Second * 15 / 8},
		{"empty", 0, time.Second},
		{"half a byte", 4, time.Second / 2},
		{"seven bits", 7, time.Second / 8},
		{"one byte", 8, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fc := newTestConn(t, newScriptedConn(nil), debtRate, debtRate)
			seedBuckets(t, fc, tc.tokens, tc.tokens)

			reservation, err := fc.reserve(1)
			if err != nil {
				t.Fatalf("reserve: %v", err)
			}
			if reservation.allocated != 1 {
				t.Fatalf("allocated %d bytes, want 1", reservation.allocated)
			}
			if reservation.waitFor != tc.waitFor {
				t.Fatalf("wait = %s, want %s: the bucket holds %d bits and the reservation takes 8",
					reservation.waitFor, tc.waitFor, int64(tc.tokens))
			}
			// The reservation is charged in full, whatever the balance was.
			assertTokens(t, fc, tc.tokens-8, tc.tokens-8)

			// Giving it back leaves exactly the balance it found, so a canceled
			// wait neither forgives a debt nor invents credit.
			reservation.free()
			assertTokens(t, fc, tc.tokens, tc.tokens)
		})
	}
}

// TestReservationNeverGrantsABorrowedByteEarly states the property the cases
// above sample, at the one rate that keeps the arithmetic exact: a bucket that
// does not hold the whole reservation always waits, and the wait grows with
// the debt rather than collapsing to zero around a byte boundary. The rates
// where the wait itself is shorter than the clock's resolution are covered by
// TestTokenWaitNeverRoundsADeficitDownToNothing, which needs no bucket.
func TestReservationNeverGrantsABorrowedByteEarly(t *testing.T) {
	var previous time.Duration
	for tokens := app.Bitrate(8); tokens >= -24; tokens-- {
		fc := newTestConn(t, newScriptedConn(nil), debtRate, debtRate)
		seedBuckets(t, fc, tokens, tokens)
		reservation, err := fc.reserve(1)
		if err != nil {
			t.Fatalf("reserve at %d bits: %v", int64(tokens), err)
		}
		switch {
		case tokens >= 8 && reservation.waitFor != 0:
			t.Fatalf("a covered reservation waited %s at %d bits", reservation.waitFor, int64(tokens))
		case tokens < 8 && reservation.waitFor <= 0:
			t.Fatalf("an uncovered reservation was granted at once at %d bits", int64(tokens))
		}
		if previous != 0 && reservation.waitFor <= previous {
			t.Fatalf("wait at %d bits is %s, not longer than the %s owed one bit earlier",
				int64(tokens), reservation.waitFor, previous)
		}
		previous = reservation.waitFor
	}
}

// TestExecutorDebtDecidesTheWaitToo covers the second bucket: the longer of
// the two waits is the one the caller sleeps.
func TestExecutorDebtDecidesTheWaitToo(t *testing.T) {
	fc := newTestConn(t, newScriptedConn(nil), debtRate, debtRate)
	seedBuckets(t, fc, 8, -8)
	reservation, err := fc.reserve(1)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if reservation.waitFor != 2*time.Second {
		t.Fatalf("wait = %s, want the executor debt of 2s", reservation.waitFor)
	}
	assertTokens(t, fc, 0, -16)
}

// TestTokenWaitNeverRoundsADeficitDownToNothing covers the rates a seeded
// bucket cannot hold still for. At a byte per second every wait is a whole
// number of nanoseconds, but at a gigabit the wait owed for the last bit of a
// reservation is a fraction of one, and truncating it would grant that bit for
// free however often the reservation repeats.
func TestTokenWaitNeverRoundsADeficitDownToNothing(t *testing.T) {
	for _, tc := range []struct {
		name    string
		deficit app.Bitrate
		rate    app.Bitrate
		want    time.Duration
	}{
		{"nothing owed", 0, debtRate, 0},
		{"a negative deficit is nothing owed", -8, debtRate, 0},
		{"a whole second", 8, debtRate, time.Second},
		{"half a second", 4, debtRate, time.Second / 2},
		{"one bit at a gigabit", 1, app.Gigabit, time.Nanosecond},
		{"one bit at eight gigabit", 1, 8 * app.Gigabit, time.Nanosecond},
		{"one bit at a petabit", 1, app.Petabit, time.Nanosecond},
		{"a byte at a petabit", 8, app.Petabit, time.Nanosecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tokenWait(tc.deficit, tc.rate); got != tc.want {
				t.Fatalf("tokenWait(%d bits, %d bits per second) = %s, want %s",
					int64(tc.deficit), int64(tc.rate), got, tc.want)
			}
		})
	}
}
