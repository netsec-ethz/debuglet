package cleanup

import (
	"errors"
	"fmt"
	"testing"
)

func TestReleasedSeparatesReleaseFromCause(t *testing.T) {
	initial := errors.New("BPF unavailable")
	program, mapErr := errors.New("program close"), errors.New("map close")
	if got := Join(initial, nil); got != initial {
		t.Fatalf("Join without a release failure changed the error: %v", got)
	}
	if got := Released(Join(initial, nil)); got != nil {
		t.Fatalf("ordinary initialization became cleanup: %v", got)
	}
	if got := Released(nil); got != nil {
		t.Fatalf("nil classification: %v", got)
	}
	failure := fmt.Errorf("constructor: %w", Join(initial, errors.Join(program, mapErr)))
	for _, want := range []error{initial, program, mapErr} {
		if !errors.Is(failure, want) {
			t.Fatalf("constructor lost error identity: %v", want)
		}
	}
	released := Released(failure)
	if !errors.Is(released, program) || !errors.Is(released, mapErr) || errors.Is(released, initial) {
		t.Fatalf("cleanup classification mixed error categories: %v", released)
	}
}
