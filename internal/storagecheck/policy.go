// Package storagecheck states which database schemas a build can operate on
// and verifies a supplied SQLite file against that policy before a daemon
// serves requests or restores work. The check never migrates or repairs a
// database: an incompatible file is refused with the action its operator has
// to take. Upgrade applies the packaged migrations only when an operator runs
// it explicitly. BootstrapFresh creates only new, private databases from those
// same packaged migrations.
package storagecheck

import (
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	dispatcherdb "github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	executordb "github.com/netsec-ethz/debuglet/internal/executor/database"
)

// Role names a dispatcher or executor database.
type Role string

const (
	Dispatcher Role = "dispatcher"
	Executor   Role = "executor"
)

// Minimum supported schema versions. Every version from the minimum up to the
// version the packaged migrations produce is served without a migration step.
// Raise the minimum together with a migration the daemon's queries depend on:
// an older database can then no longer answer them and must be refused instead
// of failing later during service.
const (
	// Schema 23: usage allowances are read from allowance_grants.
	MinimumDispatcherVersion int64 = 23
	MinimumExecutorVersion   int64 = 8
)

// Policy is the schema contract of one database for this build.
type Policy struct {
	Role Role
	// Minimum is the oldest schema version the daemon serves.
	Minimum int64
	// Current is the version the packaged migrations produce. A database
	// beyond it was written by a newer Debuglet.
	Current int64
	// DropsBelow is the version below which an upgrade drops the recorded
	// runs and their logs (tables debuglets and debuglet_logs): the packaged
	// migration that reaches it recreates both tables empty.
	DropsBelow int64
	// Identity lists tables, with columns, that only this role's database
	// has and that it has carried since its first migration. They are
	// checked before the version, so a path pointing at the other role's
	// database is reported as the wrong file rather than as a wrong version.
	Identity map[string][]string
	// Tables lists the tables the supported schema must contain, with the
	// columns that distinguish a completely applied schema from one whose
	// migrations stopped halfway.
	Tables map[string][]string
}

// PolicyFor returns the schema policy of the given role.
func PolicyFor(role Role) (Policy, error) {
	switch role {
	case Dispatcher:
		current, err := packagedVersion(dispatcherdb.MigrationFS())
		if err != nil {
			return Policy{}, err
		}
		return Policy{Role: role, Minimum: MinimumDispatcherVersion, Current: current, DropsBelow: 3, Identity: map[string][]string{
			"transaction_states": nil,
			"transactions":       nil,
		}, Tables: map[string][]string{
			"account_recovery_audit":     {"selector", "user_id", "case_reference", "issued_by_uid", "issued_at", "expires_at", "consumed_at", "revoked_at", "revoked_by_uid", "revocation_reference"},
			"allocation_reclamations":    {"debuglet_id", "reclaimed_at"},
			"allowance_grants":           {"id", "user_id", "amount", "granted_by", "reason", "idempotency_key", "granted_at"},
			"payment_receipts":           {"tx_digest", "event_seq", "nonce", "disposition", "amount", "checkpoint", "observed_at"},
			"chain_transfers":            {"id", "kind", "transaction_id", "amount", "state", "digest", "signed_transaction", "signature", "updated_at"},
			"measurement_profiles":       {"id", "user_id", "document"},
			"measurement_requests":       {"debuglet_id", "document"},
			"measurement_execution":      {"debuglet_id", "started_observed_ns", "terminal_observed_ns", "exit_code", "tcp_endpoint"},
			"retry_requests":             {"caller_scope", "request_id", "parent_run_id", "transaction_id", "request_hash", "intent_metadata"},
			"account_run_reservations":   {"debuglet_id", "account_id", "queued_bytes", "retired_at", "last_retirement_check"},
			"payload_tombstones":         {"debuglet_id", "deleted_at", "reason", "workload_sha256", "certificate_sha256"},
			"attribution_chains":         {"executor_id", "chain_id", "anchor", "t0_ns", "interval_ns", "delay_epochs", "chain_length", "tag_spec", "first_seen_ns", "last_seen_ns"},
			"attribution_keys":           {"executor_id", "chain_id", "epoch", "key", "disclosed_at_ns"},
			"attribution_runs":           {"debuglet_id", "chain_id", "source_ip", "source_ip_observed", "active_from_ns", "active_to_ns"},
			"attribution_retention":      {"singleton", "retained_from_ns"},
			"debuglet_cancellations":     {"debuglet_id", "request_id", "reason", "requested_at", "attempted_at", "acknowledged_at", "failure"},
			"debuglets":                  {"uuid", "ceil_bw", "transaction_id", "order_id", "dispatcher_incarnation", "session_id"},
			"debuglet_logs":              {"debuglet_id", "output", "source_sequence"},
			"debuglet_provenance":        {"debuglet_id", "document"},
			"debuglet_output":            {"debuglet_id", "output_version", "owner_fingerprint", "account_id", "committed_sequence", "final_sequence", "final_cursor", "status", "reason"},
			"order_settlements":          {"transaction_id", "order_id", "kind", "amount"},
			"output_account_usage":       {"account_id", "charged_bytes", "frame_count"},
			"output_node_usage":          {"singleton", "charged_bytes", "frame_count"},
			"debuglet_order":             {"transaction_id", "state", "refund_address", "debuglet_id"},
			"debuglet_users":             {"debuglet_id", "user_id"},
			"earnings":                   {"executor_id", "currency", "sui_wallet_address"},
			"executor_enrollments":       {"executor_id", "fingerprint"},
			"executor_enrollment_tokens": {"selector", "executor_id", "secret_hash", "expires_at"},
			"owned_executors":            {"executor_id", "user_id", "name", "created_at"},
			"oauth_identities":           {"provider", "issuer", "subject", "user_id", "login", "created_at", "updated_at"},
			"oauth_login_attempts":       {"state_hash", "provider", "verifier", "nonce", "purpose", "session_selector", "expires_at"},
			"pending_identity_links":     {"user_id", "provider", "issuer", "subject", "login", "session_selector", "expires_at"},
			"device_logins":              {"selector", "verifier_hash", "user_code_hash", "audience", "scopes", "label", "expires_at", "next_poll_at", "poll_interval", "state", "approver_session", "user_id"},
			"sessions":                   {"selector", "verifier_hash", "csrf_hash", "user_id", "expires_at", "revoked", "kind", "audience", "scopes", "label", "authenticated_at"},
			"transaction_users":          {"transaction_id", "user_id"},
			"transactions":               {"currency", "status", "pricing_rule"},
			"user_credentials":           {"user_id", "kind", "selector", "secret_hash"},
			"users":                      {"uuid", "name", "role"},
		}}, nil
	case Executor:
		current, err := packagedVersion(executordb.MigrationFS())
		if err != nil {
			return Policy{}, err
		}
		return Policy{Role: role, Minimum: MinimumExecutorVersion, Current: current, DropsBelow: 2, Identity: map[string][]string{
			"debuglets": {"wasm"},
		}, Tables: map[string][]string{
			"operator_dispositions": {"run_id", "recorded_at_ns", "reason"},
			"debuglets":             {"uuid", "wasm", "transaction_id", "dispatcher_incarnation", "session_id"},
			"debuglet_logs":         {"debuglet_id", "output"},
			"debuglet_exits":        {"debuglet_id", "dispatcher_incarnation", "session_id", "exit_code", "attempts", "rejected"},
			"tesla_chains":          {"generation", "anchor", "epoch_base", "delay_ns", "chain_length", "disclosure_delay"},
			"output_runs":           {"run_id", "dispatcher_incarnation", "session_id", "output_version", "last_sequence", "acknowledged_sequence", "emitted_bytes", "queued_bytes", "queued_frames", "status", "reason", "end_acknowledged", "receipt_sequence", "receipt_reason"},
			"output_frames":         {"run_id", "sequence", "timestamp_ns", "output"},
			"output_usage":          {"singleton", "charged_bytes"},
		}}, nil
	default:
		return Policy{}, fmt.Errorf("unknown database role %q", role)
	}
}

// Supports reports whether a schema version is inside the supported range.
func (p Policy) Supports(version int64) bool {
	return version >= p.Minimum && version <= p.Current
}

// packagedVersion reports the schema version the packaged migrations produce.
func packagedVersion(migrations fs.FS) (int64, error) {
	entries, err := fs.ReadDir(migrations, ".")
	if err != nil {
		return 0, fmt.Errorf("read packaged migrations: %w", err)
	}
	var current int64
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		digits, _, found := strings.Cut(name, "_")
		if !found {
			continue
		}
		version, err := strconv.ParseInt(digits, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("packaged migration %q has no version prefix", name)
		}
		if version > current {
			current = version
		}
	}
	if current == 0 {
		return 0, fmt.Errorf("packaged migrations contain no schema version")
	}
	return current, nil
}
