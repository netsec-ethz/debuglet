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

import "fmt"

// WASMExitError represents an error code returned from a WASM host function
// call. Error codes are partitioned by transport protocol family.
type WASMExitError struct {
	code int32
}

func NewWASMExitError(code int32) *WASMExitError {
	return &WASMExitError{code: code}
}

func (e *WASMExitError) Code() int32 { return e.code }

func (e *WASMExitError) Error() string {
	switch e.code {
	// ----- UDP (IP) -----
	case 1:
		return "failed to write to specified UDP address"
	case 2:
		return "failed to set read/write deadline"

	// ----- TCP -----
	case 3:
		return "failed to resolve TCP address"
	case 4:
		return "failed to dial TCP address"
	case 5:
		return "failed to accept TCP connection"
	case 6:
		return "failed to read TCP data"
	case 7:
		return "failed to write TCP data"
	case 8:
		return "failed to close TCP connection"

	// ----- TLS -----
	case 10:
		return "failed to dial TLS address"
	case 11:
		return "failed to perform TLS handshake"
	case 12:
		return "failed to read TLS data"
	case 13:
		return "failed to write TLS data"
	case 14:
		return "failed to close TLS connection"

	// ----- UDP socket (future) -----
	case 20:
		return "failed to dial UDP address"
	case 21:
		return "failed to read UDP data"
	case 22:
		return "failed to write UDP data"

	// ----- Raw socket (future) -----
	case 30:
		return "failed to open raw socket"
	case 31:
		return "failed to read raw socket data"
	case 32:
		return "failed to write raw socket data"

	// ----- SCION -----
	case 100:
		return "failed to dial SCION address"
	case 101:
		return "failed to read SCION packet"
	case 102:
		return "failed to write SCION packet"

	// ----- WASM memory -----
	case 500:
		return "memory buffer is not correctly exported"
	case 501:
		return "global memory is not correctly exported"
	}

	return fmt.Sprintf("unknown exit code: %d", e.code)
}
