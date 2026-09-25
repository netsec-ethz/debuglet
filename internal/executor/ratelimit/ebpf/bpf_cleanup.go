//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/cleanup"
)

type counterResource struct {
	name   string
	closer io.Closer
}

// Resources are acquired before publication. Once Close begins the list is
// immutable; concurrent Close callers join the same synchronous release pass.
// The daemon must join every session before closing the shared counter.
type counterCleanup struct {
	resources []counterResource
	once      sync.Once
	err       error
}

func (c *counterCleanup) add(name string, closer io.Closer) {
	if closer != nil {
		c.resources = append(c.resources, counterResource{name, closer})
	}
}

func (c *counterCleanup) Close() error {
	c.once.Do(func() {
		for i := len(c.resources) - 1; i >= 0; i-- {
			resource := c.resources[i]
			if err := resource.closer.Close(); err != nil {
				c.err = errors.Join(c.err, fmt.Errorf("close %s: %w", resource.name, err))
			}
		}
		if c.err != nil {
			c.err = errors.Join(cleanup.ErrCleanupFailed, c.err)
		}
	})
	return c.err
}

// Do not use generated countObjects.Close: it stops after the first failure.
// Keep this explicit list aligned with the generated two programs and five maps.
// Nil checks happen before conversion to io.Closer, avoiding typed-nil handles.
func counterObjectResources(objects *countObjects) []counterResource {
	var owned counterCleanup
	if objects.HandleEgress != nil {
		owned.add("handle_egress", objects.HandleEgress)
	}
	if objects.HandleIngress != nil {
		owned.add("handle_ingress", objects.HandleIngress)
	}
	if objects.DebugletSkMap != nil {
		owned.add("debuglet_sk_map", objects.DebugletSkMap)
	}
	if objects.ExecPacketSizeMap != nil {
		owned.add("exec_packet_size_map", objects.ExecPacketSizeMap)
	}
	if objects.ExecRatesMap != nil {
		owned.add("exec_rates_map", objects.ExecRatesMap)
	}
	if objects.PacketSizeMap != nil {
		owned.add("packet_size_map", objects.PacketSizeMap)
	}
	if objects.RatesMap != nil {
		owned.add("rates_map", objects.RatesMap)
	}
	return owned.resources
}
