// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/observability"
)

// MetricsStateDirectory selects the local filesystem whose available bytes are
// observed. It must be the directory holding this dispatcher's database.
func MetricsStateDirectory(path string) Option {
	return func(h *Handler) { h.metrics.stateDirectory = path }
}

type metricsMemo struct {
	mu             sync.Mutex
	stateDirectory string
	at             time.Time
	body           string
}

// GetMetrics exports aggregate observations only to an established operator.
// The one-second memo bounds the cost of repeated scrapes. Its lock owns only
// this report: collection takes no runtime ownership guard across storage I/O.
func (h *Handler) GetMetrics(c echo.Context) error {
	if _, err := requireOperator(c); err != nil {
		return err
	}
	if !h.metrics.mu.TryLock() {
		c.Response().Header().Set("Retry-After", "1")
		return apiError(http.StatusServiceUnavailable, CodeUnavailable, "metrics collection is already in progress")
	}
	if time.Since(h.metrics.at) >= time.Second {
		control := dispatcher.ControlMetrics{ObservedAt: time.Now().UTC(), RegistryUnavailable: "unavailable"}
		control.Runs.Unavailable = "unavailable"
		if h.dispatcher != nil {
			control = h.dispatcher.CollectMetrics(c.Request().Context())
		}
		host := observability.CollectHost(h.metrics.stateDirectory)
		h.metrics.body = formatMetrics(control, host)
		h.metrics.at = time.Now()
	}
	body := h.metrics.body
	h.metrics.mu.Unlock()
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.Blob(http.StatusOK, "text/plain; version=0.0.4; charset=utf-8", []byte(body))
}

func formatMetrics(control dispatcher.ControlMetrics, host observability.HostSnapshot) string {
	var out, availability strings.Builder
	gauge := func(name, help string, value any) {
		fmt.Fprintf(&out, "# HELP debuglet_%s %s\n# TYPE debuglet_%s gauge\ndebuglet_%s %v\n", name, help, name, name, value)
	}
	fmt.Fprintln(&availability, "# HELP debuglet_observation_available Whether the named observation is available (1) or unavailable (0).")
	fmt.Fprintln(&availability, "# TYPE debuglet_observation_available gauge")
	available := func(name, reason string) bool {
		value := 1
		if reason != "" {
			value = 0
		}
		// Both labels come from fixed product vocabulary, never request data.
		fmt.Fprintf(&availability, "debuglet_observation_available{observation=%q,reason=%q} %d\n", name, reason, value)
		return value == 1
	}
	gauge("control_observed_timestamp_seconds", "Unix timestamp at the start of this non-atomic control observation.", float64(control.ObservedAt.UnixNano())/1e9)
	if available("registry", control.RegistryUnavailable) {
		gauge("executors_registered", "Executor registry entries.", control.Registered)
		gauge("executors_ready", "Executor entries whose control session is available.", control.Ready)
		gauge("ready_capacity_bits_per_second", "Total advertised capacity of ready executors, before reservations.", control.ReadyCapacityBitsPerSecond)
	}
	if available("retained_runs", control.Runs.Unavailable) {
		gauge("retained_runs_admitted", "Retained run rows admitted to storage; includes failed uploads and unknown outcomes.", control.Runs.Admitted)
		gauge("retained_runs_pending", "Retained pre-start runs bound to an available session with an unexpired window.", control.Runs.Pending)
		gauge("retained_runs_started", "Retained started runs bound to an available session with an unexpired window.", control.Runs.Started)
		gauge("retained_runs_reported_success", "Retained terminal rows with no reported error; says nothing about output completeness.", control.Runs.ReportedSuccess)
		gauge("retained_runs_reported_error", "Retained terminal rows with an error, including cancellations; not a cause classification.", control.Runs.ReportedError)
		gauge("retained_runs_unknown", "Retained nonterminal rows without a live binding/window or a reconciled lifecycle state.", control.Runs.Unknown)
		gauge("pending_scheduled_start_overdue_seconds", "Largest elapsed scheduled-start delay among current pending runs, or zero when none is overdue; not submission queue age.", control.Runs.PendingOverdueSeconds)
	}
	for _, metric := range []struct {
		name, help string
		value      observability.HostValue
	}{
		{"process_rss_bytes", "Resident bytes of this dispatcher process.", host.ProcessRSSBytes},
		{"process_open_fds", "Open file descriptors of this dispatcher process.", host.OpenFDs},
		{"state_available_bytes", "Bytes available to unprivileged writes on the local state filesystem; excludes quotas.", host.StateAvailableBytes},
		{"state_capacity_bytes", "Total bytes of the local state filesystem.", host.StateCapacityBytes},
	} {
		reason := metric.value.Unavailable
		if metric.value.Value == nil && reason == "" {
			reason = "unavailable"
		}
		if available(metric.name, reason) {
			gauge(metric.name, metric.help, *metric.value.Value)
		}
	}
	// These require timestamps, finality or authoritative subsystem contracts
	// that the current process does not persist or expose. Silence is not zero.
	for _, name := range []string{"interrupted_runs", "queue_age_seconds", "start_delay_seconds", "allocation_age_seconds", "output_lag_seconds", "output_truncated", "output_complete", "enforcement_mode", "denied_traffic", "clock_uncertainty_seconds", "disclosure_lag_seconds", "schedule_remaining_seconds", "settlement_backlog"} {
		available(name, "unsupported")
	}
	return out.String() + availability.String()
}
