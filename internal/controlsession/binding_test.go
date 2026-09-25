package controlsession

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/google/uuid"
)

const testIncarnation = "cd678a91-a1ba-4def-8192-123456789abc"
const testSession = "92ab28aa-189a-4fd0-9924-abcdef123456"

func TestBindingCanonicalValues(t *testing.T) {
	want := Binding{Incarnation: testIncarnation, SessionID: testSession}
	got, err := ParseBinding(want.Incarnation, want.SessionID)
	if err != nil || got != want || !got.Valid() {
		t.Fatalf("canonical binding rejected: %v", err)
	}
	invalid := []struct{ name, value string }{
		{"empty", ""}, {"zero", uuid.Nil.String()}, {"upper", strings.ToUpper(testSession)},
		{"space", testSession + " "}, {"compact", strings.ReplaceAll(testSession, "-", "")},
		{"braces", "{" + testSession + "}"}, {"urn", "urn:uuid:" + testSession},
		{"bad_hex", "secret-input-is-not-a-valid-uuid-value"}, {"utf8", "\xff" + testSession[1:]},
	}
	for _, tc := range invalid {
		for _, field := range []string{"incarnation", "session"} {
			t.Run(tc.name+"/"+field, func(t *testing.T) {
				candidate := want
				if field == "incarnation" {
					candidate.Incarnation = tc.value
				} else {
					candidate.SessionID = tc.value
				}
				if candidate.Valid() {
					t.Fatal("noncanonical binding accepted")
				}
				got, err := ParseBinding(candidate.Incarnation, candidate.SessionID)
				if err == nil || got != (Binding{}) {
					t.Fatal("invalid parse returned a binding")
				}
				for _, input := range []string{candidate.Incarnation, candidate.SessionID} {
					if input != "" && strings.Contains(err.Error(), input) {
						t.Fatal("parse diagnostic exposed supplied identity")
					}
				}
			})
		}
	}
}

func TestBindingGeneratedIdentities(t *testing.T) {
	seen := make(map[string]bool)
	for range 32 {
		incarnation, err := NewIncarnation()
		if err != nil {
			t.Fatal(err)
		}
		binding, err := NewBinding(incarnation)
		if err != nil || !binding.Valid() || binding.Incarnation != incarnation {
			t.Fatalf("generated binding invalid: %v", err)
		}
		for _, value := range []string{incarnation, binding.SessionID} {
			id, err := uuid.Parse(value)
			if err != nil || id.Version() != 4 || id.Variant() != uuid.RFC4122 || !canonicalID(value) {
				t.Fatal("generated identity is not a canonical random UUID")
			}
			if seen[value] {
				t.Fatal("generated identity reused")
			}
			seen[value] = true
		}
	}
}

type bindingErrorReader struct {
	err   error
	calls int
}

func (r *bindingErrorReader) Read([]byte) (int, error) { r.calls++; return 0, r.err }

func TestBindingEntropyFailure(t *testing.T) {
	entropyErr := errors.New("entropy unavailable")
	reader := &bindingErrorReader{err: entropyErr}
	if got, err := newIdentity(reader); got != "" || !errors.Is(err, entropyErr) || reader.calls != 1 {
		t.Fatalf("identity replaced or lost entropy failure: %q %v", got, err)
	}
	reader.calls = 0
	if got, err := newBinding(testIncarnation, reader); got != (Binding{}) || !errors.Is(err, entropyErr) || reader.calls != 1 {
		t.Fatalf("binding replaced or lost entropy failure: %v %v", got, err)
	}
	if got, err := newIdentity(strings.NewReader("short")); got != "" || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("partial random input accepted: %q %v", got, err)
	}
	reader.calls = 0
	bad := "invalid-private-supplied-incarnation"
	got, err := newBinding(bad, reader)
	if err == nil || got != (Binding{}) || reader.calls != 0 || strings.Contains(err.Error(), bad) {
		t.Fatal("invalid incarnation consumed entropy, returned identity, or leaked input")
	}
}
