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

package debuglet

import "fmt"

type WasmExitCode struct {
	code int32
}

func (self *WasmExitCode) Error() string {
	switch self.code {
	case 1:
		return "Failed to write to specified UDP address"
	case 2:
		return "Failed to set read/write deadline"
	case 3:
		return "Failed to resolve TCP address"
	case 4:
		return "Failed to dial TCP address"
	case 5:
		return "Failed to accept TCP connection"
	case 6:
		return "Failed to read TCP data"
	case 7:
		return "Failed to write TCP data"
	case 8:
		return "Failed to close TCP connection"
	case 100:
		return "Failed to dial SCION address"
	case 101:
		return "Failed to read SCION packet"
	case 102:
		return "Failed to write SCION packet"

	case 500:
		return "Memory buffer is not correctly exported"
	case 501:
		return "Global memory is not correctly exported"

	}

	return fmt.Sprintf("exit code: %d", self.code)
}
