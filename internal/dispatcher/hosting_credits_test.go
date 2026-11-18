// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/payments"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
)

// Reuse the actual enrolled TLS transport: maintenance must pass its binding
// and credential fingerprint, and use server heartbeat time rather than uptime
// claimed in a report. No minute-long wall-clock sleeps are needed.
func TestHostingCreditsMaintenanceUsesEnrolledSession(t *testing.T) {
	f := newOutputTLS(t)
	var clock atomic.Int64
	clock.Store(time.Now().UTC().Truncate(time.Second).Unix())
	f.d.now = func() time.Time { return time.Unix(clock.Load(), 0) }
	_, owner := f.connect(f.identity, true)
	account, operator := uuid.New(), uuid.New()
	for _, user := range []struct {
		id   uuid.UUID
		role string
	}{{account, "user"}, {operator, "operator"}} {
		if _, err := f.d.db.Exec(`INSERT INTO users(uuid,name,role) VALUES(?,?,?)`, user.id, user.role, user.role); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.d.db.Exec(`INSERT INTO owned_executors(executor_id,user_id,name,created_at) SELECT 'output-executor',id,'host',CURRENT_TIMESTAMP FROM users WHERE uuid=?`, account); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.db.Exec(`INSERT INTO hosting_approvals(executor_id,user_id,approved_by,updated_at) SELECT 'output-executor',u.id,o.id,? FROM users u JOIN users o ON o.uuid=? WHERE u.uuid=?`, clock.Load(), operator, account); err != nil {
		t.Fatal(err)
	}
	cfg := &config.DispatcherConfig{Sui: config.SuiConfig{Disabled: true}, Allowance: config.AllowanceConfig{
		Enabled: true, PolicyIssuer: operator.String(), DailyBase: 100, BalanceCap: 1000, HostingHourlyRate: 3600}}
	h, err := payments.NewPaymentHandler(f.d.db, cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	f.d.Payment = h
	f.d.flushProbeStatusDue()
	clock.Add(60)
	mutation, err := owner.AdmitMutation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.d.OnHeartbeat(mutation.Context(), mutation, &pb.HeartbeatRequest{ExecutorId: "output-executor"})
	mutation.Finish()
	if err != nil {
		t.Fatal(err)
	}
	f.d.flushProbeStatusDue()
	var incarnation, session, fingerprint string
	var seconds, earned, seen int64
	if err := f.d.db.QueryRow(`SELECT incarnation,session_id,fingerprint,observed_at,observed_seconds,credited FROM allowance_hosting WHERE executor_id='output-executor'`).Scan(&incarnation, &session, &fingerprint, &seen, &seconds, &earned); err != nil {
		t.Fatal(err)
	}
	if incarnation != owner.Binding().Incarnation || session != owner.Binding().SessionID || fingerprint != owner.CredentialFingerprint() || fingerprint == "" || seen != clock.Load() || seconds != 60 || earned != 60 {
		t.Fatalf("maintenance did not account authenticated heartbeat: %s/%s %d/%d at%d", incarnation, session, seconds, earned, seen)
	}
	// Turning accounting off or omitting Payment leaves the credit ledger alone.
	cfg.Allowance.Enabled = false
	clock.Add(60)
	f.d.flushProbeStatusDue()
	f.d.Payment = nil
	clock.Add(60)
	f.d.flushProbeStatusDue()
	if err := f.d.db.QueryRow(`SELECT observed_seconds,credited FROM allowance_hosting WHERE executor_id='output-executor'`).Scan(&seconds, &earned); err != nil || seconds != 60 || earned != 60 {
		t.Fatalf("disabled ledger changed: %d/%d %v", seconds, earned, err)
	}
}
