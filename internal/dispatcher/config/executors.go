// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/netsec-ethz/debuglet/internal/configcheck"
)

// ExecutorDisplay is the operator's presentation metadata for one executor,
// configured as [executors."<executor-id>"]. Every key is optional. It is
// published in the executor listing and in result provenance with source
// operator; nothing here is verified against the executor.
type ExecutorDisplay struct {
	DisplayName string `toml:"display_name"`
	City        string `toml:"city"`
	Country     string `toml:"country"` // ISO 3166-1 alpha-2, upper case.
	Network     string `toml:"network"`
	// Only this locally approved literal host and pool may receive connect-back
	// challenges for this executor. Neither hello nor a measurement selects it.
	ConnectivityHost  string `toml:"connectivity_host"`
	ConnectivityPorts string `toml:"connectivity_ports"`
}

// Bounds on operator display metadata, in characters.
const (
	MaxExecutorEntries   = 4096
	MaxDisplayTextLength = 64
	maxExecutorIDLength  = 128 // identity.executor_id in the executor configuration.
)

func validateExecutors(executors map[string]ExecutorDisplay) error {
	if len(executors) > MaxExecutorEntries {
		return fmt.Errorf("executors: at most %d entries, got %d", MaxExecutorEntries, len(executors))
	}
	for _, id := range slices.Sorted(maps.Keys(executors)) {
		display := executors[id]
		if err := validateConnectivityTarget(id, display); err != nil {
			return err
		}
		if err := configcheck.Label(fmt.Sprintf("executors key %q", id), id, maxExecutorIDLength); err != nil {
			return err
		}
		for _, field := range [][2]string{{"display_name", display.DisplayName}, {"city", display.City}, {"network", display.Network}} {
			if err := displayText(fmt.Sprintf("executors.%q.%s", id, field[0]), field[1]); err != nil {
				return err
			}
		}
		if display.Country != "" && !isoCountry(display.Country) {
			return fmt.Errorf("executors.%q.country must be an assigned upper-case ISO 3166-1 alpha-2 code, got %q", id, display.Country)
		}
	}
	return nil
}

// Empty is allowed and means not configured. Otherwise the text is printable,
// without leading or trailing space and at most MaxDisplayTextLength runes.
func displayText(field, value string) error {
	if value == "" {
		return nil
	}
	if !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must be UTF-8 without leading or trailing space", field)
	}
	if n := utf8.RuneCountInString(value); n > MaxDisplayTextLength {
		return fmt.Errorf("%s must be at most %d characters, got %d", field, MaxDisplayTextLength, n)
	}
	for _, r := range value {
		if !unicode.IsPrint(r) {
			return fmt.Errorf("%s must not contain control or non-printing characters", field)
		}
	}
	return nil
}

// Officially assigned ISO 3166-1 alpha-2 codes.
const isoCountryCodes = "" +
	"AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ " +
	"BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ " +
	"CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ " +
	"DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR " +
	"GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY " +
	"HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP " +
	"KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY " +
	"MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ " +
	"NA NC NE NF NG NI NL NO NP NR NU NZ OM " +
	"PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW " +
	"SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ " +
	"TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ " +
	"UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW"

func isoCountry(code string) bool {
	return len(code) == 2 && code[0] >= 'A' && code[0] <= 'Z' && code[1] >= 'A' && code[1] <= 'Z' &&
		strings.Contains(" "+isoCountryCodes+" ", " "+code+" ")
}
