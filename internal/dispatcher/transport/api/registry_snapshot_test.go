package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/testutil"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
)

// This checks actual HTTP serialization from owner-aware registry snapshots.
// Direct explicit owners are unit fixtures; real transport completion is
// exercised separately in TestRegistrationAvailabilityAcrossRealTransport.
func TestRegistryHTTPSnapshotsAndAvailability(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "registry.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)
	testutil.ApplyMigrations(t, db, "../../database/migrations")
	logger := zap.NewNop()
	ph := payments.NewPaymentHandler(db, &config.DispatcherConfig{Sui: config.SuiConfig{Disabled: true}}, logger)
	d, err := dispatcher.New(logger, db, "snapshot-test", time.Minute, time.Minute, ph)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	e := echo.New()
	NewHandler(d, db, logger, LocalDevelopment(true)).RegisterRoutes(e)
	server := httptest.NewServer(e)
	t.Cleanup(func() { server.CloseClientConnections(); server.Close() })
	client := &http.Client{Timeout: 5 * time.Second}
	t.Cleanup(client.CloseIdleConnections)
	get := func(path string, wantStatus int, into any) {
		t.Helper()
		resp, err := client.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != wantStatus {
			t.Fatalf("GET %s: status %d, want %d; body %s", path, resp.StatusCode, wantStatus, body)
		}
		if into != nil {
			if err := json.Unmarshal(body, into); err != nil {
				t.Fatalf("GET %s JSON: %v", path, err)
			}
		}
	}
	register := func(h *pb.HelloResponse) *rpc.SessionOwner {
		t.Helper()
		owner := apiTestOwner(t, d, h.GetExecutorId())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := apiTestRegister(ctx, d, owner, h, "127.0.0.1"); err != nil {
			t.Fatal(err)
		}
		return owner
	}
	host := "local.example"
	anchor := []byte{1, 2, 3, 4}
	h := &pb.HelloResponse{ExecutorId: "snapshot", Version: "old", TeslaDelaySec: 3,
		TeslaAnchorTimestampNs: 123456, TeslaAnchorKey: anchor, PublicHost: &host,
		PricePerBwS: 7, Currency: "TEST"}
	owner := register(h)
	var list []ExecutorResponse
	get("/executors", http.StatusOK, &list)
	if len(list) != 0 {
		t.Fatal("HTTP discovery exposed registration before callback completion")
	}
	get("/executors/by-ip?ip=127.0.0.1", http.StatusNotFound, nil)
	get("/executors/snapshot/tesla", http.StatusNotFound, nil)
	if !owner.MarkRegistered() {
		t.Fatal("explicit fixture registration mark failed")
	}
	// Caller-owned input and returned snapshots must not be writable registry
	// aliases. The endpoint response is the external oracle for those mutations.
	anchor[0] = 99
	host = "changed.example"
	snapshot, ok := d.GetExecutor("snapshot")
	if !ok || snapshot.PublicHost() != "local.example" {
		t.Fatalf("registration did not copy the public host: %+v", snapshot)
	}
	snapshot.TeslaAnchorKey[1] = 88
	snapshot.AppendDebugletID(uuid.New())
	get("/executors", http.StatusOK, &list)
	if len(list) != 1 || list[0].ID != "snapshot" || list[0].Version != "old" ||
		list[0].PricePerBw != 7 || list[0].Currency != "TEST" || list[0].TeslaDelaySec != 3 ||
		list[0].TeslaAnchorTimestampNs != 123456 || !bytes.Equal(list[0].TeslaAnchorKey, []byte{1, 2, 3, 4}) {
		t.Fatalf("executor HTTP shape or detached metadata changed: %+v", list)
	}
	var tesla ExecutorTeslaResponse
	get("/executors/snapshot/tesla", http.StatusOK, &tesla)
	if tesla.ExecutorID != "snapshot" || tesla.AnchorKey != base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4}) || tesla.DelaySec != 3 || tesla.AnchorTimestampNs != 123456 {
		t.Fatalf("TESLA endpoint exposed caller mutation: %+v", tesla)
	}
	var byIP ExecutorByIPResponse
	get("/executors/by-ip?ip=127.0.0.1", http.StatusOK, &byIP)
	if byIP.ExecutorID != "snapshot" || len(byIP.DebugletIDs) != 0 {
		t.Fatalf("by-IP endpoint exposed snapshot history mutation: %+v", byIP)
	}
	owner.Retire()
	get("/executors", http.StatusOK, &list)
	if len(list) != 0 {
		t.Fatal("HTTP discovery exposed retired owner")
	}
	get("/executors/by-ip?ip=127.0.0.1", http.StatusNotFound, nil)
	get("/executors/snapshot/tesla", http.StatusNotFound, nil)
	// Retain the old entry until new publication, then deliver its delayed
	// disconnect. Empty replacement fields must clear prior metadata.
	next := register(&pb.HelloResponse{ExecutorId: "snapshot", Version: "new", Currency: "TEST", PricePerBwS: 2})
	if !next.MarkRegistered() {
		t.Fatal("replacement fixture mark failed")
	}
	d.OnExecutorDisconnected(owner)
	get("/executors", http.StatusOK, &list)
	if len(list) != 1 || list[0].Version != "new" || list[0].PricePerBw != 2 || len(list[0].TeslaAnchorKey) != 0 {
		t.Fatalf("HTTP replacement metadata: %+v", list)
	}
	tesla = ExecutorTeslaResponse{}
	get("/executors/snapshot/tesla", http.StatusOK, &tesla)
	if tesla.AnchorKey != "" {
		t.Fatalf("replacement retained old TESLA anchor: %+v", tesla)
	}
}
