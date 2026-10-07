// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"bytes"
	"math"
	"sync"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

// disclosureDelivery belongs to one in-process schedule, across reconnects.
// No wall timestamp from another host or a recovered generation enters it.
type disclosureDelivery struct {
	mu        sync.Mutex
	invalid   bool
	through   int64
	sampled   bool
	bound, at time.Duration
}

const maxDisclosureReceipts = pb.MaxDisclosureReceipts

func (d *disclosureDelivery) checkClock(schedule *tesla.KeySchedule, now time.Time) {
	if d == nil || schedule == nil {
		return
	}
	cfg := schedule.Config()
	drift := schedule.Drift(now)
	invalid := cfg.ClockUnready || cfg.DisclosureOnly || cfg.Epoch == cfg.Epoch.Round(0) ||
		drift > schedule.MaxDrift() || drift < -schedule.MaxDrift()
	if invalid {
		d.mu.Lock()
		d.invalid, d.sampled = true, false
		d.mu.Unlock()
	}
}

func (d *disclosureDelivery) invalidate() {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.invalid, d.sampled = true, false
	d.mu.Unlock()
}

func (d *disclosureDelivery) failed() {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.sampled = false
	d.mu.Unlock()
}

func (d *disclosureDelivery) acknowledge(schedule *tesla.KeySchedule, receipts []*pb.TeslaDisclosureReceipt, now time.Time) {
	if d == nil || schedule == nil {
		return
	}
	d.checkClock(schedule, now)
	if len(receipts) > maxDisclosureReceipts {
		d.failed()
		return
	}
	through := int64(0)
	for _, receipt := range receipts {
		if bytes.Equal(receipt.GetAnchor(), schedule.Anchor()) {
			through = receipt.GetStoredThroughEpoch()
		}
	}
	cfg := schedule.Config()
	elapsed, _ := cfg.Clock.Elapsed(cfg.Epoch, now)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.invalid || through <= 0 || through >= cfg.ChainLength {
		d.sampled = false
		return
	}
	if through <= d.through {
		return
	} // A retry never refreshes a sample.
	first := d.through + 1
	if cfg.EpochLength <= 0 || cfg.DisclosureDelay < 0 ||
		first > math.MaxInt64-cfg.DisclosureDelay ||
		first+cfg.DisclosureDelay > math.MaxInt64/int64(cfg.EpochLength) {
		d.invalid, d.sampled = true, false
		return
	}
	due := time.Duration(first+cfg.DisclosureDelay) * cfg.EpochLength
	if elapsed < due {
		d.invalid, d.sampled = true, false
		return
	}
	d.through, d.bound, d.at, d.sampled = through, elapsed-due, elapsed, true
}

func (d *disclosureDelivery) report(schedule *tesla.KeySchedule, now time.Time) *pb.DisclosureDeliveryObservation {
	if d == nil || schedule == nil {
		return nil
	}
	d.checkClock(schedule, now)
	cfg := schedule.Config()
	elapsed, _ := cfg.Clock.Elapsed(cfg.Epoch, now)
	d.mu.Lock()
	defer d.mu.Unlock()
	age := elapsed - d.at
	if d.invalid || !d.sampled || age < 0 || age >= pb.DisclosureSampleLifetime {
		return nil
	}
	return &pb.DisclosureDeliveryObservation{Anchor: schedule.Anchor(), StoredThroughEpoch: d.through,
		ScheduledToAckNs: int64(d.bound), SampleAgeNs: int64(age)}
}

// matchingDisclosureReceipts bounds the reply before inspection. Coverage is
// useful only for a key requested under this call's still-current binding.
func matchingDisclosureReceipts(req *pb.HeartbeatRequest, response *pb.HeartbeatResponse, currentAnchor []byte) []*pb.TeslaDisclosureReceipt {
	if req == nil || response == nil || len(response.DisclosureReceipts) > maxDisclosureReceipts {
		return nil
	}
	requested := []*pb.TeslaDisclosure{{Anchor: req.TeslaKeyAnchor, Epoch: req.TeslaKeyEpoch, Key: req.TeslaKey}}
	if len(requested[0].Anchor) == 0 {
		requested[0].Anchor = currentAnchor
	}
	if len(req.ExtraDisclosures) <= maxDisclosureReceipts-1 {
		requested = append(requested, req.ExtraDisclosures...)
	}
	var out []*pb.TeslaDisclosureReceipt
	for _, receipt := range response.DisclosureReceipts {
		if len(receipt.GetAnchor()) != 32 || receipt.GetStoredThroughEpoch() <= 0 {
			return nil
		}
		for _, previous := range out {
			if bytes.Equal(previous.Anchor, receipt.Anchor) {
				return nil
			}
		}
		matched := false
		for _, sent := range requested {
			if len(sent.GetKey()) > 0 && bytes.Equal(sent.GetAnchor(), receipt.Anchor) && receipt.StoredThroughEpoch <= sent.GetEpoch() {
				matched = true
				break
			}
		}
		if !matched {
			return nil
		}
		out = append(out, receipt)
	}
	return out
}
