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

package engine

import (
	"testing"
)

// TestMaxSliceLength verifies that the exported constant is sane.
func TestMaxSliceLength(t *testing.T) {
	if MAX_SLICE_LENGTH <= 0 {
		t.Errorf("MAX_SLICE_LENGTH must be positive, got %d", MAX_SLICE_LENGTH)
	}
}

// panicSafeCall executes fn and returns any panic as an error string.
// The wasmer-go library dereferences a wasmer.Instance pointer before our
// code can return a Go error, so we catch the resulting nil-pointer panic.
func panicSafeCall(fn func()) (panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
		}
	}()
	fn()
	return false
}

// TestGetResultNilInstancePanicsOrErrors verifies that calling getResult with a
// nil instance either returns an error or panics — but does not silently
// succeed.
func TestGetResultNilInstancePanicsOrErrors(t *testing.T) {
	var gotErr error
	panicked := panicSafeCall(func() {
		_, gotErr = getResult(nil, 4)
	})
	if !panicked && gotErr == nil {
		t.Error("expected either a panic or an error for nil instance")
	}
}

// TestExtractResIdxNilInstancePanicsOrErrors verifies that extractResIdx with
// a nil instance either returns an error or panics.
func TestExtractResIdxNilInstancePanicsOrErrors(t *testing.T) {
	var gotErr error
	panicked := panicSafeCall(func() {
		_, gotErr = extractResIdx(nil)
	})
	if !panicked && gotErr == nil {
		t.Error("expected either a panic or an error for nil instance")
	}
}

// TestExtractSliceNilInstancePanicsOrErrors verifies that extractSlice with a
// nil instance either returns an error or panics.
func TestExtractSliceNilInstancePanicsOrErrors(t *testing.T) {
	var gotErr error
	panicked := panicSafeCall(func() {
		_, gotErr = extractSlice(nil, "some_buffer", 0, 16)
	})
	if !panicked && gotErr == nil {
		t.Error("expected either a panic or an error for nil instance")
	}
}
