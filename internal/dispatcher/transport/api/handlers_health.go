package api

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher"

	"github.com/labstack/echo/v4"
)

// The three health routes observe this process while a request is served:
// liveness, admission readiness, and the dependency observations behind it.
// docs/API.md states what each answers and what none of them consults.

// healthRoutes report on this process rather than serve a caller. They
// establish no caller and negotiate no contract version.
var healthRoutes = map[string]bool{routeLiveness: true, routeReadiness: true, routeHealth: true}

// Readiness reasons. They are fixed identifiers a probe branches on, never an
// operator's note and never a path: these routes are public and answer anyone.
const (
	reasonAdmissionPaused    = "admission_paused"
	reasonStorageUnavailable = "storage_unavailable"
	reasonControlUnavailable = "control_unavailable"
)

// Observation values of the health report and the probe status.
const (
	healthOK          = "ok"
	healthUnready     = "unready"
	healthDegraded    = "degraded"
	healthUnavailable = "unavailable"
)

// healthProbeTimeout bounds the single storage read a readiness check makes,
// so a probe still answers while the database does not.
const healthProbeTimeout = 2 * time.Second

// healthObservationWindow bounds how often the dependencies are actually read.
// Probes arrive from every supervisor watching this dispatcher, and each
// observation costs the one database connection the daemon keeps, so one
// observation serves this long instead of one per request. It is a variable
// because a test drives a transition faster than an operator ever does.
var healthObservationWindow = time.Second

// healthMemo is the last observation and the moment it was made.
type healthMemo struct {
	mu       sync.Mutex
	at       time.Time
	observed HealthResponse
}

// ProbeResponse is the body of the liveness and readiness probes. Reasons is
// present only on a refusal.
type ProbeResponse struct {
	Status  string   `json:"status"`
	Reasons []string `json:"reasons,omitempty"`
}

// HealthResponse is the aggregate report. It is a fixed set of small fields:
// no operator note, no identifier, no path, because the route is public.
type HealthResponse struct {
	Live      bool           `json:"live"`
	Ready     bool           `json:"ready"`
	Reasons   []string       `json:"reasons"`
	Storage   string         `json:"storage"`
	Control   string         `json:"control"`
	Executors ExecutorCounts `json:"executors"`
}

// ExecutorCounts reports the executor registry and its eligible subset.
type ExecutorCounts struct {
	// Eligible counts executors whose control session lease is valid now.
	Eligible int `json:"eligible"`
	// Registered counts the entries of the executor registry.
	Registered int `json:"registered"`
}

// GetLiveness answers GET /healthz. Reaching it is the whole check.
func (h *Handler) GetLiveness(c echo.Context) error {
	return c.JSON(http.StatusOK, ProbeResponse{Status: healthOK})
}

// GetReadiness answers GET /readyz: 200 while this dispatcher would admit new
// work, 503 naming the failed checks otherwise.
func (h *Handler) GetReadiness(c echo.Context) error {
	observed := h.observeHealth(c.Request().Context())
	if observed.Ready {
		return c.JSON(http.StatusOK, ProbeResponse{Status: healthOK})
	}
	return c.JSON(http.StatusServiceUnavailable, ProbeResponse{Status: healthUnready, Reasons: observed.Reasons})
}

// GetHealth answers GET /health. It always answers 200: the report is the
// answer, and a probe that could not read it would learn nothing.
func (h *Handler) GetHealth(c echo.Context) error {
	return c.JSON(http.StatusOK, h.observeHealth(c.Request().Context()))
}

// observeHealth evaluates each dependency once per window, in a fixed order,
// and repeats that observation to every probe arriving inside it. The lock is
// held across the evaluation, so probes that arrive together share one storage
// read instead of queueing behind each other for the single connection. The
// report it returns is shared and must not be modified.
func (h *Handler) observeHealth(ctx context.Context) HealthResponse {
	h.health.mu.Lock()
	defer h.health.mu.Unlock()
	if time.Since(h.health.at) < healthObservationWindow {
		return h.health.observed
	}
	report := HealthResponse{Live: true, Reasons: []string{}, Storage: healthOK, Control: healthOK}
	if dispatcher.AdmissionPaused() != nil {
		// Why admission is paused is the operator's note, which this route
		// never repeats: a public probe learns that it is, and nothing else.
		report.Reasons = append(report.Reasons, reasonAdmissionPaused)
	}
	if !h.storageAnswers(ctx) {
		report.Storage = healthDegraded
		report.Reasons = append(report.Reasons, reasonStorageUnavailable)
	}
	if h.dispatcher == nil || !h.dispatcher.Bidi.Serving() {
		report.Control = healthUnavailable
		report.Reasons = append(report.Reasons, reasonControlUnavailable)
	}
	if h.dispatcher != nil {
		report.Executors.Eligible, report.Executors.Registered = h.dispatcher.ExecutorEligibility()
	}
	report.Ready = len(report.Reasons) == 0
	h.health.at, h.health.observed = time.Now(), report
	return report
}

// storageAnswers performs the cheapest read the database can answer: it names
// no table, so it cannot be slowed by how much work this dispatcher holds, and
// it writes nothing.
func (h *Handler) storageAnswers(ctx context.Context) bool {
	if h.db == nil {
		return false
	}
	// The observation is shared with every probe in the window, so one caller
	// going away must not record its cancellation as a degraded database.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), healthProbeTimeout)
	defer cancel()
	var answer int
	return h.db.QueryRowContext(ctx, "SELECT 1").Scan(&answer) == nil && answer == 1
}
