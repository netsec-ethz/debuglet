// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package protocol

import "time"

// DisclosureSampleLifetime bounds the actual age of a sender completion sample,
// independently of how recently its enclosing heartbeat reached the dispatcher.
const DisclosureSampleLifetime = time.Minute

// MaxDisclosureReceipts bounds current plus historical chain coverage per call.
const MaxDisclosureReceipts = 5
