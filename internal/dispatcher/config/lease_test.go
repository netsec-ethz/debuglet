package config

import "testing"

func TestControlLeaseConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		seconds    int
		invalid    bool
	}{
		{"omitted", "", 60, false},
		{"minimum_seconds", "[scheduler]\nexecutor_timeout = 1\n", 1, false},
		{"maximum_seconds", "[scheduler]\nexecutor_timeout = 300\n", 300, false},
		{"explicit_zero", "[scheduler]\nexecutor_timeout = 0\n", 0, true},
		{"negative", "[scheduler]\nexecutor_timeout = -1\n", 0, true},
		{"over_maximum", "[scheduler]\nexecutor_timeout = 301\n", 0, true},
		{"duration_overflow", "[scheduler]\nexecutor_timeout = 9223372036854775807\n", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadConfig(writeConfig(t, baseSections+tc.body))
			if tc.invalid {
				if err == nil || cfg != nil {
					t.Fatalf("invalid lease config accepted: %v/%v", cfg, err)
				}
				return
			}
			if err != nil || cfg.Scheduler.ExecutorTimeout != tc.seconds {
				t.Fatalf("lease seconds: %v/%v", cfg, err)
			}
		})
	}
}
