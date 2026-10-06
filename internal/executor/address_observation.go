// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"crypto/rand"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/netsec-ethz/debuglet/internal/connectivity"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

// addressObservationInterval spaces the calls that let the dispatcher observe
// this executor's address in each family. The address changes rarely; the
// listing reports when it was last seen.
const addressObservationInterval = 10 * time.Minute

// addressObservationTimeout bounds one family's name lookup and call, which
// run on the heartbeat loop.
const addressObservationTimeout = 1500 * time.Millisecond

// addressTarget is the dispatcher endpoint of one family and the name its
// certificate is verified for.
type addressTarget struct {
	network, host string
	port          uint16
	literal       netip.Addr // Valid when dispatcher.addr is a literal.
}

// addressTargets returns the families to observe: those without a configured
// reflector, whose own calls already let the dispatcher observe them.
func (e *Executor) addressTargets() []addressTarget {
	host, portText, err := net.SplitHostPort(e.cfg.Dispatcher.Addr)
	port, portErr := strconv.ParseUint(portText, 10, 16)
	if err != nil || portErr != nil || port == 0 || host == "" {
		return nil
	}
	literal, _ := netip.ParseAddr(host)
	targets := []addressTarget{}
	for _, family := range []struct {
		network    string
		configured string
		v4         bool
	}{{"ip4", e.cfg.Connectivity.IPv4Reflector, true}, {"ip6", e.cfg.Connectivity.IPv6Reflector, false}} {
		if family.configured != "" || literal.IsValid() && literal.Unmap().Is4() != family.v4 {
			continue
		}
		targets = append(targets, addressTarget{network: family.network, host: host, port: uint16(port), literal: literal.Unmap()})
	}
	return targets
}

// observeAddresses lets the dispatcher see this executor's address in each
// address family, at most every addressObservationInterval. For each family it
// resolves the configured dispatcher name and calls the authenticated address
// reflection over that family. The dispatcher records the peer address of the
// call, never a value the executor sends, and TLS verifies that the resolved
// address is the dispatcher. Outcomes are not reported: a family that does not
// work is simply not observed. Called only by the serialized heartbeat loop.
func (e *Executor) observeAddresses(ctx context.Context, binding controlsession.Binding) {
	if !e.cfg.Connectivity.ObserveAddresses || e.Bidi == nil {
		return
	}
	now := time.Now()
	e.capabilityMu.Lock()
	if now.Before(e.addressNext) {
		e.capabilityMu.Unlock()
		return
	}
	e.addressNext = now.Add(addressObservationInterval)
	e.capabilityMu.Unlock()
	var wg sync.WaitGroup
	for _, target := range e.addressTargets() {
		wg.Add(1)
		go func(target addressTarget) {
			defer wg.Done()
			callCtx, cancel := context.WithTimeout(ctx, addressObservationTimeout)
			defer cancel()
			address := target.literal
			if !address.IsValid() {
				addresses, err := net.DefaultResolver.LookupNetIP(callCtx, target.network, target.host)
				if err != nil || len(addresses) == 0 {
					return
				}
				address = addresses[0].Unmap()
			}
			nonce := make([]byte, connectivity.TokenSize)
			if _, err := rand.Read(nonce); err != nil {
				return
			}
			endpoint := netip.AddrPortFrom(address, target.port).String()
			_, _ = e.Bidi.ReflectAddressAs(callCtx, binding, endpoint, target.host, &pb.ReflectAddressRequest{ExecutorId: e.cfg.Identity.ExecutorID, Nonce: nonce})
		}(target)
	}
	wg.Wait()
}
