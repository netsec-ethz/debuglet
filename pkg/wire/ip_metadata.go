// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wire

import (
	"strconv"
	"strings"
)

// IPLookup records an offline database lookup at registration. Reason is empty
// for a known value; otherwise it explains why Value is null. Source identifies
// the database and its build epoch, including for a negative lookup.
type IPLookup[T any] struct {
	Value      *T      `json:"value"`
	Source     *string `json:"source"`
	ObservedAt int64   `json:"observed_at"`
	Reason     string  `json:"reason"`
}

type ASInfo struct {
	Number uint32 `json:"number"`
	Name   string `json:"name"`
	Prefix string `json:"prefix"`
}

// GeoLocation is approximate and deliberately excludes coordinates and region
// detail. Precision is country or city; city is optional for country precision.
type GeoLocation struct {
	Country   string `json:"country"`
	City      string `json:"city"`
	Precision string `json:"precision"`
}

// AddressMetadata identifies the provenance of the lookup key without exposing
// the address itself in the public listing. The result already records the
// private keys as source_ip and public_host.
type AddressMetadata struct {
	AddressSource string                `json:"address_source"`
	ASN           IPLookup[ASInfo]      `json:"asn"`
	Location      IPLookup[GeoLocation] `json:"location"`
}

type IPMetadata struct {
	Reported       *AddressMetadata `json:"reported,omitempty"` // Separate hello claim when it differs from the observed control address.
	Observed       AddressMetadata  `json:"observed"`
	Advertised     AddressMetadata  `json:"advertised"`
	LocationOptOut bool             `json:"location_opt_out"`
	Disagreements  []string         `json:"disagreements"`
}

// DatabaseSource recognises the source convention used by offline MMDB data.
func DatabaseSource(source string) bool {
	name, version, ok := strings.Cut(strings.TrimPrefix(source, "database:"), "@")
	if !strings.HasPrefix(source, "database:") || !ok || name == "" || len(name) > 128 {
		return false
	}
	for _, r := range name {
		if r < 33 || r > 126 || r == '@' {
			return false
		}
	}
	epoch, err := strconv.ParseUint(version, 10, 64)
	return err == nil && epoch > 0 && strconv.FormatUint(epoch, 10) == version
}

// Location returns the display location for a client. Existing Display fields
// remain operator-only on the wire and in result files, so older readers retain
// their original source vocabulary. New clients can use this optional fallback.
func (e Executor) Location() (city, country LabelledString) {
	city, country = e.Display.City, e.Display.Country
	if city.Value != nil || country.Value != nil || e.IPMetadata == nil || e.IPMetadata.LocationOptOut {
		return
	}
	auto := e.IPMetadata.Observed.Location
	if auto.Value == nil {
		auto = e.IPMetadata.Advertised.Location
	}
	if auto.Value == nil || auto.Source == nil || auto.Reason != "" {
		return
	}
	source := *auto.Source
	if auto.Value.City != "" {
		value := auto.Value.City
		city = LabelledString{Value: &value, Source: &source}
	}
	if auto.Value.Country != "" {
		value := auto.Value.Country
		country = LabelledString{Value: &value, Source: &source}
	}
	return
}
