package ebpf

import (
	"errors"
	"fmt"
	"testing"
)

func TestConstructorCleanupClassification(t *testing.T) {
	initial := errors.New("BPF unavailable")
	program, mapErr := errors.New("program close"), errors.New("map close")
	if got := CleanupError(withCleanupError(initial, nil)); got != nil {
		t.Fatalf("ordinary initialization became cleanup: %v", got)
	}
	if got := CleanupError(nil); got != nil {
		t.Fatalf("nil classification: %v", got)
	}
	failure := fmt.Errorf("constructor: %w", withCleanupError(initial, errors.Join(program, mapErr)))
	for _, want := range []error{initial, program, mapErr} {
		if !errors.Is(failure, want) {
			t.Fatalf("constructor lost error identity: %v", want)
		}
	}
	cleanup := CleanupError(failure)
	if !errors.Is(cleanup, program) || !errors.Is(cleanup, mapErr) || errors.Is(cleanup, initial) {
		t.Fatalf("cleanup classification mixed error categories: %v", cleanup)
	}
}
