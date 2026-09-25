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

package ratelimit

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"
)

// Accountant accounts traffic that no connection wrapper covers. Attach
// returns a wrapper that accounts a connected socket as the guest reads and
// writes it; a job's listener is not a connected socket, and neither is a
// SCION connection, so the datagrams they carry would otherwise be moved
// without touching any limit. They are accounted here against the same
// per-destination and per-run limits as a connected socket.
//
// A nil Accountant accounts nothing, which is what a run without a limiter
// has; the policy decision that admitted the peer is separate and always
// applies.
type Accountant struct {
	limiter *app.Limiter
	id      uuid.UUID
}

// NewAccountant returns an accountant for one run, or nil when the run has no
// limiter to account against.
func NewAccountant(limiter *app.Limiter, id uuid.UUID) *Accountant {
	if limiter == nil {
		return nil
	}
	return &Accountant{limiter: limiter, id: id}
}

// Account waits until size bytes in the given direction fit within the limits
// of addr, which is the declared destination the traffic belongs to. It
// returns when the bytes are covered, or with the context's error.
func (a *Accountant) Account(ctx context.Context, direction app.TransferDirection, addr string, size int) error {
	if a == nil || a.limiter == nil || size <= 0 {
		return nil
	}
	if err := a.limiter.Wait(ctx, direction, a.id, addr, app.FromBytes(size)); err != nil {
		return fmt.Errorf("failed to account %d bytes for %s: %w", size, addr, err)
	}
	return nil
}
