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

package wasm

import (
	"testing"
)

// TestMaxSliceLength verifies that the exported constant is sane.
func TestMaxSliceLength(t *testing.T) {
	if MAX_SLICE_LENGTH <= 0 {
		t.Errorf("MAX_SLICE_LENGTH must be positive, got %d", MAX_SLICE_LENGTH)
	}
}

// TestGetResultNilModule verifies that calling GetResult with a nil module
// panics (as expected with wazero's api.Module).
func TestGetResultNilModule(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil module")
		}
	}()
	GetResult(nil, 4)
}

// TestExtractResIdxNilModule verifies that ExtractResIdx with a nil module panics.
func TestExtractResIdxNilModule(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil module")
		}
	}()
	ExtractResIdx(nil)
}

// TestExtractSliceNilModule verifies that ExtractSlice with a nil module panics.
func TestExtractSliceNilModule(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil module")
		}
	}()
	ExtractSlice(nil, "some_buffer", 0, 16)
}
