// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package demo

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/netsec-ethz/debuglet/internal/artifact"
	dispatcherconfig "github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	executorconfig "github.com/netsec-ethz/debuglet/internal/executor/config"
	"github.com/netsec-ethz/debuglet/internal/fsutil"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
	"github.com/pelletier/go-toml/v2"
)

const backupManifestFile = "backup.json"

// OfflineStateFile records a foreground launcher's completed child shutdown.
// A launcher must remove it before starting any daemon against this state.
const OfflineStateFile = "offline-state.json"
const backupProtection = "Private plaintext: database credentials and inline configuration are included. External keys, CLI credentials, logs and binaries are excluded."
const backupHistory = "Retained records and schedule descriptors only; no replay, historical TESLA keys or payment reconciliation."

type BackupOptions struct {
	StateDir, Destination string
	// Offline acknowledges that no unmanaged daemon is writing this directory.
	// A completed foreground shutdown receipt and its free lock are also required.
	Offline bool
	Package Manifest
}
type RestoreOptions struct {
	BackupDir, StateDir string
	Package             Manifest
}
type BackupRole struct {
	Role          storagecheck.Role `json:"role"`
	Identity      string            `json:"identity"`
	SchemaVersion int64             `json:"schema_version"`
}
type BackupManifest struct {
	SchemaVersion int                      `json:"schema_version"`
	ObservedAt    time.Time                `json:"observed_at"`
	Layout        string                   `json:"layout"`
	Package       Manifest                 `json:"package"`
	Roles         []BackupRole             `json:"roles"`
	Files         map[string]artifact.File `json:"files"`
	Protection    string                   `json:"protection"`
	History       string                   `json:"history"`
}
type offlineState struct {
	Version   string `json:"version"`
	SourceSHA string `json:"source_sha"`
	Metadata  string `json:"metadata"`
	SHA256    string `json:"sha256"`
}

func recordStoppedState(dir string, m Manifest) error {
	name := "local-state.json"
	data, err := readRegularFile(filepath.Join(dir, name), readyLimit)
	if errors.Is(err, os.ErrNotExist) {
		name = "role-state.json"
		data, err = readRegularFile(filepath.Join(dir, name), readyLimit)
	}
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	return writeLocalJSON(filepath.Join(dir, OfflineStateFile), offlineState{m.Version, m.SourceSHA, name, hex.EncodeToString(digest[:])})
}

// BackupState snapshots a stopped foreground local environment or role. It
// never stops a process or opens the source database through SQLite. SQLite
// recovers/checkpoints the main file and journals together in private staging.
// Destination must not exist; previous versioned backups are never replaced.
func BackupState(ctx context.Context, options BackupOptions) (result BackupManifest, err error) {
	if !options.Offline {
		return result, errors.New("backup requires --offline after a successful foreground shutdown; direct daemon and system-service state is unsupported")
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if err = privateBackupDir(options.StateDir); err != nil {
		return result, err
	}
	dir, unlock, err := prepareStateDir(options.StateDir, "backup source")
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	var stopped offlineState
	if err = readBackupJSON(filepath.Join(dir, OfflineStateFile), &stopped); err != nil {
		return result, fmt.Errorf("no completed foreground shutdown receipt; this command requires state managed by a package that records joined shutdown: %w", err)
	}
	if stopped.Version != options.Package.Version || stopped.SourceSHA != options.Package.SourceSHA {
		return result, errors.New("shutdown receipt belongs to another package")
	}
	for _, name := range []string{"environment.json", "dispatcher-ready.json", "executor-ready.json", "ready.json", "child-ready.json"} {
		if _, e := os.Lstat(filepath.Join(dir, name)); !errors.Is(e, os.ErrNotExist) {
			return result, fmt.Errorf("runtime record %s remains; complete foreground shutdown first", name)
		}
	}
	layout, roles, names, err := backupInventory(dir, options.Package)
	if err != nil {
		return result, err
	}
	metadata, err := hashBackupFile(ctx, filepath.Join(dir, names[0]))
	if err != nil {
		return result, err
	}
	if stopped.Metadata != names[0] || stopped.SHA256 != metadata.SHA256 {
		return result, errors.New("state identity changed after foreground shutdown")
	}
	for _, role := range roles {
		if _, err = backupConfig(dir, dir, layout, role, "", options.Package.Version); err != nil {
			return result, err
		}
	}
	destination, stage, err := backupStage(options.Destination, dir)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(stage)) }()
	for _, name := range names {
		if err = copyBackupFile(ctx, filepath.Join(dir, name), filepath.Join(stage, name)); err != nil {
			return result, err
		}
	}
	for i := range roles {
		name := string(roles[i].Role) + ".sqlite"
		for _, suffix := range []string{"-wal", "-journal"} {
			if _, e := os.Lstat(filepath.Join(dir, name+suffix)); errors.Is(e, os.ErrNotExist) {
				continue
			} else if e != nil {
				return result, e
			}
			if err = copyBackupFile(ctx, filepath.Join(dir, name+suffix), filepath.Join(stage, name+suffix)); err != nil {
				return result, err
			}
		}
		roles[i].SchemaVersion, err = checkBackupDB(ctx, filepath.Join(stage, name), roles[i].Role)
		if err != nil {
			return result, err
		}
	}
	// Copying is complete before the observation time is recorded. Both roles
	// were stopped throughout; this is not a distributed transaction snapshot.
	result = BackupManifest{SchemaVersion: 1, ObservedAt: time.Now().UTC(), Layout: layout, Package: options.Package, Roles: roles, Files: map[string]artifact.File{}, Protection: backupProtection, History: backupHistory}
	for _, name := range names {
		file, e := hashBackupFile(ctx, filepath.Join(stage, name))
		if e != nil {
			return result, e
		}
		result.Files[name] = file
	}
	if err = writeLocalJSON(filepath.Join(stage, backupManifestFile), result); err != nil {
		return result, err
	}
	if err = publishBackup(ctx, stage, destination); err != nil {
		return result, err
	}
	return result, nil
}

// RestoreState verifies a backup and publishes a separate, stopped state
// directory. It preserves identities and old control bindings; it never starts
// services, replays retained runs, changes a schema or revokes credentials.
func RestoreState(ctx context.Context, options RestoreOptions) (result BackupManifest, err error) {
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if err = privateBackupDir(options.BackupDir); err != nil {
		return result, err
	}
	if err = readBackupJSON(filepath.Join(options.BackupDir, backupManifestFile), &result); err != nil {
		return result, err
	}
	if result.SchemaVersion != 1 || result.ObservedAt.IsZero() || result.Protection != backupProtection || result.History != backupHistory || result.Package.Version != options.Package.Version || result.Package.SourceSHA != options.Package.SourceSHA {
		return result, errors.New("unsupported backup or package identity; restore with the package that created this state")
	}
	layout, roles, names, err := backupInventory(options.BackupDir, options.Package)
	if err != nil {
		return result, err
	}
	if layout != result.Layout || len(roles) != len(result.Roles) || len(names) != len(result.Files) {
		return result, errors.New("backup inventory does not match manifest")
	}
	entries, err := os.ReadDir(options.BackupDir)
	if err != nil {
		return result, err
	}
	if len(entries) != len(names)+1 {
		return result, errors.New("backup has missing or unexpected files")
	}
	for _, name := range names {
		expected, ok := result.Files[name]
		got, e := hashBackupFile(ctx, filepath.Join(options.BackupDir, name))
		if e != nil {
			return result, e
		}
		if !ok || got != expected {
			return result, fmt.Errorf("backup digest or size mismatch: %s", name)
		}
	}
	destination, stage, err := backupStage(options.StateDir, options.BackupDir)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(stage)) }()
	for _, name := range names {
		if err = copyBackupFile(ctx, filepath.Join(options.BackupDir, name), filepath.Join(stage, name)); err != nil {
			return result, err
		}
		// Verify the copied bytes too: a changed backup cannot be published from
		// the interval between the initial hash and copy.
		got, e := hashBackupFile(ctx, filepath.Join(stage, name))
		if e != nil {
			return result, e
		}
		if got != result.Files[name] {
			return result, fmt.Errorf("backup changed while restoring: %s", name)
		}
	}
	for i := range roles {
		roles[i].SchemaVersion, err = checkBackupDB(ctx, filepath.Join(stage, string(roles[i].Role)+".sqlite"), roles[i].Role)
		if err != nil {
			return result, err
		}
		if _, err = backupConfig(stage, "", layout, roles[i], destination, options.Package.Version); err != nil {
			return result, err
		}
	}
	for i := range roles {
		if roles[i] != result.Roles[i] {
			return result, errors.New("backup role, identity or schema does not match manifest")
		}
	}
	if err = recordStoppedState(stage, options.Package); err != nil {
		return result, err
	}
	if err = publishBackup(ctx, stage, destination); err != nil {
		return result, err
	}
	return result, nil
}

func backupInventory(dir string, m Manifest) (string, []BackupRole, []string, error) {
	if !artifact.ValidVersion(m.Version) || !artifact.ValidSourceSHA(m.SourceSHA) {
		return "", nil, nil, errors.New("backup requires an installed package version and source identity")
	}
	local := filepath.Join(dir, "local-state.json")
	if _, err := os.Lstat(local); err == nil {
		if _, e := os.Lstat(filepath.Join(dir, "role-state.json")); !errors.Is(e, os.ErrNotExist) {
			return "", nil, nil, errors.New("state has both local and role metadata")
		}
		state, err := readLocalState(dir, m)
		return "local", []BackupRole{{Role: storagecheck.Dispatcher}, {Role: storagecheck.Executor, Identity: state.ExecutorID}}, []string{"local-state.json", "dispatcher.toml", "executor.toml", "dispatcher.sqlite", "executor.sqlite"}, err
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", nil, nil, err
	}
	var state RoleState
	if err := readBackupJSON(filepath.Join(dir, "role-state.json"), &state); err != nil {
		return "", nil, nil, err
	}
	if state.Role != storagecheck.Dispatcher && state.Role != storagecheck.Executor {
		return "", nil, nil, errors.New("unknown backup role")
	}
	state, err := readRoleState(dir, state.Role, m)
	return string(state.Role), []BackupRole{{Role: state.Role, Identity: state.Identity}}, []string{"role-state.json", "service.toml", string(state.Role) + ".sqlite"}, err
}

// backupConfig uses the daemons' decoder. Only this generated TEST profile is
// self-contained; silently omitting a referenced key or keystore is unsafe.
// originalDir is empty on restore, where an old absolute database path is
// expected and is replaced after the entire backup has been verified.
func backupConfig(dir, originalDir, layout string, role BackupRole, destination, version string) ([]byte, error) {
	name := "service.toml"
	if layout == "local" {
		name = string(role.Role) + ".toml"
	}
	path := filepath.Join(dir, name)
	data, err := readRegularFile(path, 64<<10)
	if err != nil {
		return nil, err
	}
	var dbPath string
	if role.Role == storagecheck.Dispatcher {
		cfg, _, e := dispatcherconfig.DecodeConfig(data)
		if e != nil {
			return nil, fmt.Errorf("invalid backup dispatcher configuration: %w", e)
		}
		if cfg.Server.Version != version || !cfg.Sui.Disabled || cfg.Sui.KeystorePath != "" || !cfg.TLS.Disable || cfg.TLS.CertFile != "" || cfg.TLS.KeyFile != "" || cfg.TLS.CAFile != "" || cfg.GitHubOAuth.Enabled || !cfg.Server.LocalDevelopment {
			return nil, errors.New("backup supports only foreground TEST configuration without external credentials")
		}
		dbPath = cfg.Database.Path
	} else {
		cfg, _, e := executorconfig.DecodeConfig(data)
		if e != nil {
			return nil, fmt.Errorf("invalid backup executor configuration: %w", e)
		}
		if cfg.Identity.Version != version || cfg.Identity.ExecutorID != role.Identity || !cfg.TLS.Disable || cfg.Credentials.CACert != "" || cfg.Credentials.ClientCert != "" || cfg.Credentials.ClientKey != "" || cfg.Credentials.EnrollmentToken != "" || cfg.Pricing.Currency != "TEST" || !cfg.Network.DisableSCIONEnvironment || !cfg.Network.Policy.Spec().LocalTargets {
			return nil, errors.New("backup requires matching foreground TEST identity without external credentials or SCION configuration")
		}
		dbPath = cfg.Database.Path
	}
	if originalDir != "" && dbPath != RoleDatabase(originalDir, role.Role) {
		return nil, errors.New("backup configuration references a database outside its managed state")
	}
	if destination == "" {
		return data, nil
	}
	var cfg map[string]any
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	database, ok := cfg["database"].(map[string]any)
	if !ok {
		return nil, errors.New("backup configuration has no database table")
	}
	database["path"] = RoleDatabase(destination, role.Role)
	data, err = toml.Marshal(cfg)
	if err == nil {
		err = fsutil.WriteFile(path, data, 0600)
	}
	return data, err
}

func checkBackupDB(ctx context.Context, path string, role storagecheck.Role) (version int64, err error) {
	db, err := sqlitedb.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, db.Close()) }()
	var busy, written, checkpointed int
	if err = db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &written, &checkpointed); err != nil {
		return 0, err
	}
	if busy != 0 {
		return 0, errors.New("backup WAL checkpoint is busy")
	}
	var mode string
	if err = db.QueryRowContext(ctx, "PRAGMA journal_mode=DELETE").Scan(&mode); err != nil {
		return 0, err
	}
	if mode != "delete" {
		return 0, errors.New("backup journal could not be finalized")
	}
	var integrity string
	if err = db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil {
		return 0, err
	}
	if integrity != "ok" {
		return 0, errors.New("backup database failed integrity check")
	}
	rows, err := db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return 0, err
	}
	bad := rows.Next()
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil {
		return 0, err
	}
	if bad {
		return 0, errors.New("backup database failed foreign key check")
	}
	policy, err := storagecheck.PolicyFor(storagecheck.Role(role))
	if err != nil {
		return 0, err
	}
	if err = policy.CheckDB(ctx, db); err != nil {
		return 0, err
	}
	err = db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version_id), 0) FROM goose_db_version WHERE is_applied != 0").Scan(&version)
	return version, err
}

func privateBackupDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("backup and state directories must be real mode-0700 directories")
	}
	return schemaParentOwned(info)
}
func backupStage(path, source string) (string, string, error) {
	destination, err := filepath.Abs(path)
	if err != nil || path == "" {
		return "", "", errors.New("an explicit new destination directory is required")
	}
	parent := filepath.Dir(destination)
	if err := privateBackupDir(parent); err != nil {
		return "", "", err
	}
	realParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", "", err
	}
	source, err = filepath.Abs(source)
	if err != nil {
		return "", "", err
	}
	realSource, err := filepath.EvalSymlinks(source)
	if err != nil {
		return "", "", err
	}
	rel, err := filepath.Rel(realSource, filepath.Join(realParent, filepath.Base(destination)))
	if err != nil {
		return "", "", err
	}
	if rel == "." || rel != ".." && !bytes.HasPrefix([]byte(rel), []byte(".."+string(filepath.Separator))) {
		return "", "", errors.New("destination must be separate from the source directory")
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		return "", "", errors.New("destination already exists or cannot be inspected; choose a new directory")
	}
	stage, err := os.MkdirTemp(parent, ".debuglet-backup-*")
	return destination, stage, err
}
func readBackupJSON(path string, value any) error {
	data, err := readRegularFile(path, 64<<10)
	if err != nil {
		return err
	}
	if err = artifact.CheckUniqueJSON(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}
func openBackupFile(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("backup input %s is not a regular file", filepath.Base(path))
	}
	if n, ok := FileNames(info); !ok || n != 1 {
		return nil, errors.New("backup input must have exactly one file name")
	}
	return os.Open(path)
}
func copyBackupFile(ctx context.Context, source, destination string) (err error) {
	from, err := openBackupFile(source)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, from.Close()) }()
	to, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, to.Close()) }()
	if _, err = copyBackupBytes(ctx, to, from); err != nil {
		return err
	}
	return to.Sync()
}
func hashBackupFile(ctx context.Context, path string) (result artifact.File, err error) {
	file, err := openBackupFile(path)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	hash := sha256.New()
	result.Bytes, err = copyBackupBytes(ctx, hash, file)
	result.SHA256 = hex.EncodeToString(hash.Sum(nil))
	return result, err
}
func copyBackupBytes(ctx context.Context, to io.Writer, from io.Reader) (int64, error) {
	var total int64
	buffer := make([]byte, 128<<10)
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, readErr := from.Read(buffer)
		if n > 0 {
			written, err := to.Write(buffer[:n])
			total += int64(written)
			if err != nil {
				return total, err
			}
			if written != n {
				return total, io.ErrShortWrite
			}
		}
		if readErr == io.EOF {
			return total, nil
		}
		if readErr != nil {
			return total, readErr
		}
	}
}
func publishBackup(ctx context.Context, stage, destination string) error {
	entries, err := os.ReadDir(stage)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := fsutil.SyncFile(filepath.Join(stage, entry.Name())); err != nil {
			return err
		}
	}
	if err := fsutil.SyncDir(stage); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := renameBackup(stage, destination); err != nil {
		return err
	}
	if err := fsutil.SyncDir(filepath.Dir(destination)); err != nil {
		return fmt.Errorf("published %s but directory sync failed; durability is unconfirmed: %w", destination, err)
	}
	return nil
}
