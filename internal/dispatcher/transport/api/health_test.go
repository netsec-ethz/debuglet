package api

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	apispec "github.com/netsec-ethz/debuglet/api"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

// These tests drive the three public health routes of a real dispatcher. Every
// transition below is produced by taking one of its own dependencies away —
// the database, the control transport, the admission switch this process reads
// — never by telling a handler what to answer.

// healthBodyLimit bounds every probe answer read here. A health route answers
// a fixed set of small fields; anything larger is a defect.
const healthBodyLimit = 512

// healthGet reads one public health route through a bounded reader and checks
// the served answer, its status and its announced contract version against the
// contract document.
func healthGet(t *testing.T, f *maintenanceFixture, path string) (int, []byte) {
	t.Helper()
	response, err := f.server.Client().Get(f.server.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, healthBodyLimit+1))
	if err != nil || len(body) > healthBodyLimit {
		t.Fatalf("GET %s: %v; answered %d bytes, at most %d: %s", path, err, len(body), healthBodyLimit, body)
	}
	oaCheckExchange(t, oaContract(t), oaExchange{
		method: http.MethodGet, route: path, status: response.StatusCode, response: body,
		announced: response.Header.Get(apispec.VersionHeader), served: true,
	})
	return response.StatusCode, body
}

// healthProbe reads a liveness or readiness probe.
func healthProbe(t *testing.T, f *maintenanceFixture, path string) (int, ProbeResponse, []byte) {
	t.Helper()
	status, body := healthGet(t, f, path)
	var probe ProbeResponse
	if err := json.Unmarshal(body, &probe); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return status, probe, body
}

// healthReport reads GET /health, which answers 200 whatever it observes.
func healthReport(t *testing.T, f *maintenanceFixture) HealthResponse {
	t.Helper()
	status, body := healthGet(t, f, routeHealth)
	var report HealthResponse
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatalf("decode the health report: %v", err)
	}
	if status != http.StatusOK || !report.Live {
		t.Fatalf("a served health report: status %d, body %s", status, body)
	}
	return report
}

// healthControl starts both real control listeners on the fixture's transport
// and returns once it accepts sessions. An executor dials the reverse listener
// to open its session and the direct one to renew that session's lease, so
// readiness observes both, and no test asserts readiness without them.
func healthControl(t *testing.T, f *maintenanceFixture) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	direct, reverse := healthListen(t), healthListen(t)
	directDone, reverseDone := make(chan struct{}), make(chan struct{})
	go func() { defer close(directDone); _ = f.d.Bidi.ServeGRPCListener(ctx, direct) }()
	go func() { defer close(reverseDone); _ = f.d.Bidi.ServeYamux(ctx, reverse) }()
	t.Cleanup(func() { cancel(); <-directDone; <-reverseDone })
	for deadline := time.Now().Add(10 * time.Second); !f.d.Bidi.Serving(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the control listeners never started accepting sessions")
		}
	}
}

func healthListen(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

// healthWindow fixes how long one observation is reused. These tests change a
// dependency and ask again far faster than whoever polls a deployment does.
func healthWindow(t *testing.T, window time.Duration) {
	t.Helper()
	previous := healthObservationWindow
	healthObservationWindow = window
	t.Cleanup(func() { healthObservationWindow = previous })
}

// healthClock is a receiver-local clock the test moves, so that a control
// lease runs out without the test waiting for one.
type healthClock struct{ at atomic.Int64 }

func (c *healthClock) now() time.Time          { return time.Unix(0, c.at.Load()) }
func (c *healthClock) advance(d time.Duration) { c.at.Add(int64(d)) }

// healthRegister registers one executor holding a control session with its own
// clock and lease, through the real registration path.
func healthRegister(t *testing.T, f *maintenanceFixture, id string, now func() time.Time, lease time.Duration) {
	t.Helper()
	binding, err := controlsession.NewBinding(f.d.ControlIncarnation())
	if err != nil {
		t.Fatal(err)
	}
	owner, err := rpc.NewSessionOwnerWithClock(id, binding, lease, now)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	hello := &pb.HelloResponse{ExecutorId: id, Version: "health", Currency: "TEST", PricePerBwS: 1}
	if err := apiTestRegister(ctx, f.d, owner, hello, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if !owner.MarkRegistered() {
		t.Fatal("the registered session retired before it was marked")
	}
}

// A dispatcher is live as soon as it serves requests, and ready only once the
// dependencies it admits work with serve too. Before its control listener
// accepts sessions it is live and explicitly unready, which is what a
// supervisor has to be able to tell apart from a failed process.
func TestHealthIsLiveBeforeItIsReadyDuringStartup(t *testing.T) {
	healthWindow(t, 0)
	f := newMaintenanceFixture(t)

	if status, probe, _ := healthProbe(t, f, routeLiveness); status != http.StatusOK || probe.Status != healthOK {
		t.Fatalf("liveness before the control listener serves: %d %+v", status, probe)
	}
	status, probe, _ := healthProbe(t, f, routeReadiness)
	if status != http.StatusServiceUnavailable || !slices.Contains(probe.Reasons, reasonControlUnavailable) {
		t.Fatalf("readiness before the control listener serves: %d %+v", status, probe)
	}
	if report := healthReport(t, f); report.Ready || report.Control != healthUnavailable || report.Storage != healthOK {
		t.Fatalf("report before the control listener serves: %+v", report)
	}

	healthControl(t, f)
	if status, probe, _ := healthProbe(t, f, routeReadiness); status != http.StatusOK || len(probe.Reasons) != 0 {
		t.Fatalf("readiness once every dependency serves: %d %+v", status, probe)
	}
	if report := healthReport(t, f); !report.Ready || report.Storage != healthOK || report.Control != healthOK {
		t.Fatalf("report once every dependency serves: %+v", report)
	}
}

// A drained dispatcher is live and unready, and says so with the fixed reason
// alone: the operator's note and the switch it was written in are no part of
// an answer this public route gives anyone who asks.
func TestHealthReportsADrainedDispatcherAsLiveAndUnready(t *testing.T) {
	healthWindow(t, 0)
	f := newMaintenanceFixture(t)
	healthControl(t, f)
	const note = "planned upgrade"
	f.pause(note)

	status, probe, body := healthProbe(t, f, routeReadiness)
	if status != http.StatusServiceUnavailable || len(probe.Reasons) != 1 || probe.Reasons[0] != reasonAdmissionPaused {
		t.Fatalf("readiness while admission is paused: %d %+v", status, probe)
	}
	if answer := string(body); strings.Contains(answer, note) || strings.Contains(answer, "maintenance") ||
		strings.Contains(answer, f.switchFile) {
		t.Fatalf("the refusal repeats the operator's note or the file it was written in: %s", body)
	}
	if report := healthReport(t, f); report.Ready || len(report.Reasons) != 1 ||
		report.Storage != healthOK || report.Control != healthOK {
		t.Fatalf("report while admission is paused: %+v", report)
	}

	f.resume()
	if status, probe, _ := healthProbe(t, f, routeReadiness); status != http.StatusOK || len(probe.Reasons) != 0 {
		t.Fatalf("readiness after admission resumed: %d %+v", status, probe)
	}
}

// Storage is reported on its own, so a dispatcher whose database cannot answer
// is distinguishable from one an operator paused, and is still live.
func TestHealthReportsStorageDegradationSeparately(t *testing.T) {
	healthWindow(t, 0)
	f := newMaintenanceFixture(t)
	healthControl(t, f)
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}

	if status, _, _ := healthProbe(t, f, routeLiveness); status != http.StatusOK {
		t.Fatalf("liveness while storage is unavailable: %d", status)
	}
	status, probe, _ := healthProbe(t, f, routeReadiness)
	if status != http.StatusServiceUnavailable || len(probe.Reasons) != 1 || probe.Reasons[0] != reasonStorageUnavailable {
		t.Fatalf("readiness while storage is unavailable: %d %+v", status, probe)
	}
	if report := healthReport(t, f); report.Ready || report.Storage != healthDegraded || report.Control != healthOK {
		t.Fatalf("report while storage is unavailable: %+v", report)
	}
}

// Eligibility follows the authoritative control lease. An executor whose lease
// runs out with no renewal stops counting although nothing retired its session
// and nothing closed its connection, which is what one-way loss looks like from
// here, and a fresh session restores the count.
func TestHealthCountsOnlyExecutorsHoldingAControlLease(t *testing.T) {
	healthWindow(t, 0)
	f := newMaintenanceFixture(t)
	healthControl(t, f)
	const executorID = "health-executor"
	clock := &healthClock{}
	clock.at.Store(time.Now().UnixNano())
	healthRegister(t, f, executorID, clock.now, time.Second)
	if report := healthReport(t, f); report.Executors.Eligible != 1 || report.Executors.Registered != 1 {
		t.Fatalf("a registered executor holding its lease: %+v", report.Executors)
	}

	clock.advance(2 * time.Second)
	if report := healthReport(t, f); report.Executors.Eligible != 0 {
		t.Fatalf("an executor whose lease ran out still counts as eligible: %+v", report.Executors)
	}
	// Losing an executor is not a reason to stop admitting work.
	if status, probe, _ := healthProbe(t, f, routeReadiness); status != http.StatusOK {
		t.Fatalf("readiness after an executor lease ran out: %d %+v", status, probe)
	}

	healthRegister(t, f, executorID, time.Now, time.Minute)
	if report := healthReport(t, f); report.Executors.Eligible != 1 || report.Executors.Registered != 1 {
		t.Fatalf("a fresh session did not restore eligibility: %+v", report.Executors)
	}
}

// Whoever watches a deployment polls these routes, and each observation costs
// the one database connection the daemon keeps and one look at the admission
// switch. An observation already made inside the window is repeated instead of
// made again, so the probes cannot become the load they report on.
func TestHealthRepeatsOneObservationWithinItsWindow(t *testing.T) {
	healthWindow(t, time.Minute)
	f := newMaintenanceFixture(t)
	healthControl(t, f)
	if report := healthReport(t, f); !report.Ready {
		t.Fatalf("report once every dependency serves: %+v", report)
	}

	// Both dependencies are gone, and the answer inside the window is still
	// the observation that was already made.
	f.pause("planned upgrade")
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	if status, probe, _ := healthProbe(t, f, routeReadiness); status != http.StatusOK || len(probe.Reasons) != 0 {
		t.Fatalf("readiness inside the observation window: %d %+v", status, probe)
	}
}

// A probe states no contract version and reads nothing this contract
// describes, so a requirement this dispatcher cannot satisfy must never keep
// one from answering.
func TestHealthAnswersWhateverContractAProbeRequires(t *testing.T) {
	healthWindow(t, 0)
	f := newMaintenanceFixture(t)
	for _, path := range []string{routeLiveness, routeReadiness, routeHealth} {
		request, err := http.NewRequest(http.MethodGet, f.server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set(apispec.VersionHeader, "99")
		response, err := f.server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode == http.StatusBadRequest {
			t.Fatalf("GET %s answered %d to a client requiring another contract", path, response.StatusCode)
		}
	}
}
