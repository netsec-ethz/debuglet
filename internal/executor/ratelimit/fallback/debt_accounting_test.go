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
// the reservation stays below a whole bit, though it can shorten the wait.
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
			seeded := fc.count.packetSize[debugletKey{id: fc.id, dest: fc.ipv6}].last

			reservation, err := fc.reserve(1)
			if err != nil {
				t.Fatalf("reserve: %v", err)
			}
			if reservation.allocated != 1 {
				t.Fatalf("allocated %d bytes, want 1", reservation.allocated)
			}
			least := max(0, tc.waitFor-time.Since(seeded))
			if reservation.waitFor < least || reservation.waitFor > tc.waitFor+time.Nanosecond {
				t.Fatalf("wait = %s, want between %s and %s after refill from %d bits",
					reservation.waitFor, least, tc.waitFor, int64(tc.tokens))
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
	seeded := fc.count.execPacketSize[fc.id].last
	reservation, err := fc.reserve(1)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if least := max(0, 2*time.Second-time.Since(seeded)); reservation.waitFor < least || reservation.waitFor > 2*time.Second+time.Nanosecond {
		t.Fatalf("wait = %s, want the executor debt between %s and 2s after refill", reservation.waitFor, least)
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

func TestBucketRefillPreservesFractionalCredit(t *testing.T) {
	for _, tc := range []struct {
		name          string
		before, after app.Bitrate
		wantCredit    app.Bitrate
		wantWait      time.Duration
	}{
		{"unchanged rate", 8, 8, 8, 0},
		{"changed rate", 3, 5, 4, 800 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Unix(1, 0)
			b := &bucketState{last: start}
			var c charge
			c.owed(b, app.FromBytes(1), tc.before)
			for i := 1; i <= 100; i++ {
				rate := tc.before
				if i > 50 {
					rate = tc.after
				}
				b.refill(start.Add(time.Duration(i)*10*time.Millisecond), rate)
				c.owed(b, app.FromBytes(1), rate)
			}
			if got := c.owed(b, app.FromBytes(1), tc.after); got != tc.wantWait {
				t.Fatalf("wait after 100 refills = %v, want %v", got, tc.wantWait)
			}
			if b.refilled != tc.wantCredit || b.tokens != tc.wantCredit-app.FromBytes(1) {
				t.Fatalf("refilled = %d, tokens = %d; want %d credited bits against the 8-bit charge",
					b.refilled, b.tokens, tc.wantCredit)
			}
		})
	}
}

func TestFullBucketDiscardsIdleFractionForNewCharge(t *testing.T) {
	start := time.Unix(1, 0)
	b := &bucketState{last: start, tokens: debtRate}
	b.refill(start.Add(100*time.Millisecond), debtRate)
	var c charge
	if got := c.owed(b, app.FromBytes(2), debtRate); got != time.Second {
		t.Fatalf("initial wait = %v, want 1s", got)
	}
	// The earlier idle 0.8 bits cannot contribute to the new eight-bit debt.
	b.refill(start.Add(time.Second), debtRate)
	if got := c.owed(b, app.FromBytes(2), debtRate); got != 100*time.Millisecond {
		t.Fatalf("wait after 900ms = %v, want 100ms", got)
	}
	b.refill(start.Add(1100*time.Millisecond), debtRate)
	if got := c.owed(b, app.FromBytes(2), debtRate); got != 0 {
		t.Fatalf("wait after 1s = %v, want 0", got)
	}
}

func TestRefundedFullBucketKeepsOlderChargeProgress(t *testing.T) {
	start := time.Unix(1, 0)
	b := &bucketState{last: start, tokens: debtRate}
	var first, waiting charge
	first.owed(b, app.FromBytes(2), debtRate)
	waiting.owed(b, app.FromBytes(1), debtRate)
	// Refunding the first charge fills the bucket before the second charge's
	// recorded threshold is reached. Capping tokens must not erase its progress.
	b.tokens += app.FromBytes(2)
	b.cap(debtRate)
	b.refill(start.Add(time.Second), debtRate)
	if got := waiting.owed(b, app.FromBytes(1), debtRate); got != time.Second {
		t.Fatalf("older charge's wait = %v, want 1s", got)
	}
	for i := 1; i <= 100; i++ {
		b.refill(start.Add(time.Second+time.Duration(i)*10*time.Millisecond), debtRate)
		var later charge
		if got := later.owed(b, app.FromBytes(1), debtRate); got != 0 {
			t.Fatalf("charge from a full bucket waited %v", got)
		}
		b.tokens += app.FromBytes(1)
		b.cap(debtRate)
		want := time.Second - time.Duration(i)*10*time.Millisecond
		if got := waiting.owed(b, app.FromBytes(1), debtRate); got != want {
			t.Fatalf("older charge after refill %d waits %v, want %v", i, got, want)
		}
	}
}
