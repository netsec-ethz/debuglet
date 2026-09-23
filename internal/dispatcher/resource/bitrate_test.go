package resource

import (
	"math"
	"testing"
)

// A bitrate is read in two units. A buffer size rounds up, because a partial
// byte still needs a whole one; a token balance rounds towards negative
// infinity, because a partial byte is not yet a byte anyone may spend and a
// partial byte owed is still owed. One expression cannot serve both: rounding
// up a signed balance reports no debt for everything from -7 to -1 bits, and
// for -8 bits it reports none either, because the intermediate sum truncates
// towards zero.

func TestByteConversionsSeparateSizesFromBalances(t *testing.T) {
	for _, tc := range []struct {
		bits   Bitrate
		size   int
		signed int
	}{
		{bits: math.MinInt64, size: 0, signed: math.MinInt64 / 8},
		{bits: -17, size: 0, signed: -3},
		{bits: -16, size: 0, signed: -2},
		{bits: -9, size: 0, signed: -2},
		{bits: -8, size: 0, signed: -1},
		{bits: -7, size: 0, signed: -1},
		{bits: -1, size: 0, signed: -1},
		{bits: 0, size: 0, signed: 0},
		{bits: 1, size: 1, signed: 0},
		{bits: 7, size: 1, signed: 0},
		{bits: 8, size: 1, signed: 1},
		{bits: 9, size: 2, signed: 1},
		{bits: 16, size: 2, signed: 2},
		{bits: Kilobyte, size: 1000, signed: 1000},
		{bits: math.MaxInt64 - 7, size: math.MaxInt64 / 8, signed: math.MaxInt64 / 8},
		{bits: math.MaxInt64, size: math.MaxInt64/8 + 1, signed: math.MaxInt64 / 8},
	} {
		if got := tc.bits.Bytes(); got != tc.size {
			t.Errorf("Bitrate(%d).Bytes() = %d, want %d", int64(tc.bits), got, tc.size)
		}
		if got := tc.bits.SignedBytes(); got != tc.signed {
			t.Errorf("Bitrate(%d).SignedBytes() = %d, want %d", int64(tc.bits), got, tc.signed)
		}
	}
}

// TestFromBytesSaturatesOutsideItsRange states the other direction. A byte
// count beyond the range has no bit count, and reporting one of the opposite
// sign would turn a size into a credit.
func TestFromBytesSaturatesOutsideItsRange(t *testing.T) {
	for _, tc := range []struct {
		bytes int
		bits  Bitrate
	}{
		{bytes: 0, bits: 0},
		{bytes: 1, bits: 8},
		{bytes: -1, bits: -8},
		{bytes: 1000, bits: Kilobyte},
		{bytes: MaxByteCount, bits: MaxByteCount * 8},
		{bytes: -MaxByteCount, bits: -MaxByteCount * 8},
		{bytes: MaxByteCount + 1, bits: math.MaxInt64},
		{bytes: math.MaxInt64, bits: math.MaxInt64},
		{bytes: -MaxByteCount - 1, bits: math.MinInt64},
		{bytes: math.MinInt64, bits: math.MinInt64},
	} {
		if got := FromBytes(tc.bytes); got != tc.bits {
			t.Errorf("FromBytes(%d) = %d, want %d bits", tc.bytes, int64(got), int64(tc.bits))
		}
	}
}

// TestSignedBytesRoundTripsEveryExactByteCount is the invariant the token
// accounting rests on: whatever FromBytes charged, SignedBytes reports back.
func TestSignedBytesRoundTripsEveryExactByteCount(t *testing.T) {
	for _, bytes := range []int{0, 1, -1, 7, -7, 8, -8, 1024, -1024, MaxByteCount, -MaxByteCount} {
		if got := FromBytes(bytes).SignedBytes(); got != bytes {
			t.Errorf("FromBytes(%d).SignedBytes() = %d, want %d", bytes, got, bytes)
		}
	}
}
