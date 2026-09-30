// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

// CapabilityError identifies the requested policy field that current discovery
// evidence cannot serve. It remains an invalid-policy error for older clients.
type CapabilityError struct {
	Field, Code, Message string
	OrderID              int64
}

func (e *CapabilityError) Error() string { return e.Message }
func (e *CapabilityError) Unwrap() error { return ErrInvalidPolicy }

func validateExecutorCapabilities(spec *models.DebugletSpec, exec *executorEntry, now time.Time) error {
	refuse := func(field, code, message string) error {
		return &CapabilityError{Field: "policy." + field, Code: code, Message: message, OrderID: spec.OrderID}
	}
	if spec.Policy.RequireICMP && !exec.ICMPEnabled {
		return refuse("require_icmp", "unsupported", "executor does not support ICMP, but policy requires it")
	}
	if spec.Policy.RequireICMP && exec.Capabilities != nil {
		if vantageExpired(exec.capabilityObserved, now) {
			return refuse("require_icmp", "stale_observation", "ICMP capability observation has expired")
		}
		if !slices.Contains(exec.Capabilities.Protocols, "icmp") {
			return refuse("require_icmp", "unsupported", "executor does not currently support ICMP")
		}
	}
	if (spec.Policy.ListenTCP || spec.Policy.ListenUDP) && exec.PublicHost() == "" {
		field := "listen_tcp"
		if !spec.Policy.ListenTCP {
			field = "listen_udp"
		}
		return refuse(field, "unsupported", "executor has no public host, but policy requires a listener")
	}
	for _, item := range []struct {
		transport, field string
		required         bool
	}{{"tcp", "listen_tcp", spec.Policy.ListenTCP}, {"udp", "listen_udp", spec.Policy.ListenUDP}, {"scion", "listen_scion", spec.Policy.ListenSCION}} {
		if !item.required {
			continue
		}
		if exec.vantage != nil && !vantageExpired(exec.vantageObserved, now) && !slices.Contains(exec.vantage.listeners, item.transport) {
			return refuse(item.field, "unsupported", "executor does not support the requested listener")
		}
		if exec.connectivity == nil {
			continue
		} // Older or unconfigured peers retain declared-capability admission.
		observation := exec.connectivity.TCPListener
		if item.transport == "udp" {
			observation = exec.connectivity.UDPListener
		}
		if item.transport == "scion" {
			observation = exec.connectivity.SCIONListener
		}
		if observation.Reason == "not_configured" || observation.Reason == "no_controlled_peer" {
			continue
		}
		if !observation.FreshReachable(now) {
			return refuse(item.field, connectivityRefusal(observation, now), "requested listener has no fresh successful controlled reachability observation")
		}
	}
	if exec.connectivity == nil {
		return nil
	}
	for _, address := range spec.Policy.Addresses {
		ip, err := netip.ParseAddr(address)
		if err != nil {
			if prefix, prefixErr := netip.ParsePrefix(address); prefixErr == nil {
				ip, err = prefix.Addr(), nil
			}
		}
		if err != nil {
			if host, _, splitErr := net.SplitHostPort(address); splitErr == nil {
				ip, err = netip.ParseAddr(host)
			}
		}
		if err != nil {
			continue
		} // Never resolve names during admission or invent their family.
		observation := exec.connectivity.IPv6
		if ip.Unmap().Is4() {
			observation = exec.connectivity.IPv4
		}
		if observation.Reason == "not_configured" {
			continue
		}
		if !observation.FreshReachable(now) {
			return refuse("addresses", connectivityRefusal(observation, now), "requested address family has no fresh successful controlled egress observation")
		}
	}
	return nil
}

func connectivityRefusal(r wire.Reachability, now time.Time) string {
	if r.Stale || r.ExpiresAt != nil && (now.Unix() >= *r.ExpiresAt || r.ObservedAt != nil && now.Unix() < *r.ObservedAt) {
		return "stale_observation"
	}
	if r.State == "untested" {
		return "unmeasured"
	}
	return "reachability_failed"
}
