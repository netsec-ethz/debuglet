package demo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/connections"
	"github.com/netsec-ethz/debuglet/internal/readiness"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

// RoleEnvironment describes one independently running local service.
type RoleEnvironment struct {
	State        string `json:"state"`
	Role         string `json:"role"`
	Name         string `json:"name"`
	Endpoint     string `json:"endpoint"`
	GRPCAddress  string `json:"grpc_address,omitempty"`
	YamuxAddress string `json:"yamux_address,omitempty"`
	ExecutorID   string `json:"executor_id,omitempty"`
	StateDir     string `json:"state_dir"`
}

type RoleOptions struct {
	Name, StateDir string
	Port, GRPCPort int
	Dispatcher     connections.Profile
	Ready          func(RoleEnvironment) error
	Logs           LogOptions
}

// RoleState is the persistent identity of one managed role directory. It
// pins the installed version that created the directory, so a payload the
// databases were never served by cannot silently adopt them.
type RoleState struct {
	SchemaVersion int               `json:"schema_version"`
	Version       string            `json:"version"`
	SourceSHA     string            `json:"source_sha"`
	Identity      string            `json:"identity"`
	Role          storagecheck.Role `json:"role"`
	// EarlierIdentity is the key earlier builds wrote the identity under. It
	// is read when the file carries no identity value and is never written.
	EarlierIdentity string `json:"executor_id,omitempty"`
}

func DispatcherUp(ctx context.Context, assets Assets, options RoleOptions) error {
	return upRole(ctx, storagecheck.Dispatcher, assets, options, productionDependencies(), localStartupTimeout)
}

func ExecutorUp(ctx context.Context, assets Assets, options RoleOptions) error {
	return upRole(ctx, storagecheck.Executor, assets, options, productionDependencies(), localStartupTimeout)
}

// Each role owns only its own process, state lock and readiness file. Joining
// an executor never starts or stops the dispatcher it connects to.
func upRole(ctx context.Context, role storagecheck.Role, assets Assets, options RoleOptions, deps dependencies, startupTimeout time.Duration) (err error) {
	options.Logs, err = options.Logs.defaults()
	if err != nil {
		return err
	}

	if runtime.GOOS != "linux" {
		return errors.New("local services require Linux")
	}
	defer func() {
		if ctx.Err() == context.Canceled && localCancellationOnly(err) {
			err = nil
		}
	}()
	if role != storagecheck.Dispatcher && role != storagecheck.Executor {
		return errors.New("unknown local service role")
	}
	if err := connections.ValidateName(options.Name); err != nil {
		return err
	}
	if options.Port < 0 || options.Port > 65535 || options.GRPCPort < 0 || options.GRPCPort > 65535 {
		return errors.New("local ports must be between 0 and 65535")
	}
	supervisor := newSupervisor(ctx, deps)
	workCtx, cancelWork := supervisor.Context(), supervisor.Cancel
	defer supervisor.Quiesce()
	startupCtx, cancelStartup := context.WithTimeout(workCtx, startupTimeout)
	defer cancelStartup()
	if ctx.Err() != nil {
		if ctx.Err() == context.Canceled {
			return nil
		}
		return ctx.Err()
	}
	if role == storagecheck.Executor {
		if err := validateRoleEndpoint(options.Dispatcher.Endpoint); err != nil {
			return err
		}
	}
	assets, err = deps.resolveAssets(assets.CLI)
	if err != nil {
		return fmt.Errorf("verify installed service: %w", err)
	}
	dir := options.StateDir
	if dir == "" {
		base, err := DefaultLocalStateDir()
		if err != nil {
			return err
		}
		dir = filepath.Join(base, string(role)+"s", options.Name)
	}
	dir, unlock, err := prepareStateDir(dir, "service state")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	if err := removeLocalFile(filepath.Join(dir, OfflineStateFile)); err != nil {
		return err
	}
	state, err := readRoleState(dir, role, assets.Manifest)
	if err != nil {
		return err
	}
	// The dispatcher is contacted only after the local state is known to be
	// usable, so a local refusal does not depend on a dispatcher answering.
	if role == storagecheck.Executor {
		// Always refresh the metadata: cached profile ports are conveniences,
		// not authority to connect to an old or different control service.
		profile, err := connections.Discover(startupCtx, options.Dispatcher.Endpoint)
		if err != nil {
			return fmt.Errorf("dispatcher connection metadata unavailable; use a running local dispatcher with /connection support: %w", err)
		}
		if err := validateAddress(profile.GRPCAddress); err != nil {
			return fmt.Errorf("dispatcher gRPC metadata: %w", err)
		}
		if err := validateAddress(profile.YamuxAddress); err != nil {
			return fmt.Errorf("dispatcher yamux metadata: %w", err)
		}
		options.Dispatcher = profile
	}
	var child ChildProcess
	var log *rotatingLog
	defer func() {
		supervisor.Quiesce()
		if ctx.Err() == context.Canceled && localCancellationOnly(err) {
			err = nil
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		children, stopErr := supervisor.Close(cleanupCtx)
		cancel()
		err = errors.Join(err, stopErr)
		joined := child != nil && children.Joined && stopErr == nil
		if log != nil {
			err = errors.Join(err, log.Close())
		}
		err = errors.Join(err, removeLocalFile(filepath.Join(dir, "ready.json")), removeLocalFile(filepath.Join(dir, "child-ready.json")))
		if joined {
			err = errors.Join(err, recordStoppedState(dir, assets.Manifest))
		}
	}()
	for _, name := range []string{"ready.json", "child-ready.json", "service.toml"} {
		if err := removeLocalFile(filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	dbPath, _, err := deps.prepareRoleDatabase(startupCtx, role, dir)
	if err != nil {
		return err
	}
	config := DispatcherConfiguration(assets.Manifest.Version, dbPath)
	executable := assets.Dispatcher
	if role == storagecheck.Dispatcher {
		config["server"].(map[string]any)["http_port"] = options.Port
		config["server"].(map[string]any)["grpc_port"] = options.GRPCPort
	} else {
		executable = assets.Executor
		config = ExecutorConfiguration(assets.Manifest.Version, state.Identity, dbPath, readiness.Record{
			GRPCAddr: options.Dispatcher.GRPCAddress, HTTPAddr: options.Dispatcher.YamuxAddress,
		})
		config["tesla"].(map[string]any)["chain_length"] = 0
	}
	logPath := filepath.Join(dir, string(role)+".log")
	log, err = newRotatingLog(logPath, options.Logs, cancelWork)
	if err != nil {
		return err
	}
	id := ""
	if role == storagecheck.Executor {
		id = state.Identity
	}
	var record readiness.Record
	child, record, err = supervisor.StartRole(startupCtx, RoleProcess{
		Role: role, Directory: dir, Executable: executable,
		ConfigPath: filepath.Join(dir, "service.toml"), ReadyPath: filepath.Join(dir, "child-ready.json"),
		ExecutorID: id, Configuration: config, Stdout: log, Stderr: log,
	})
	if err != nil {
		return fmt.Errorf("%s readiness (see %s): %w", role, logPath, err)
	}
	ready := RoleEnvironment{State: "ready", Role: string(role), Name: options.Name, StateDir: dir, Endpoint: options.Dispatcher.Endpoint}
	if role == storagecheck.Dispatcher {
		ready.Endpoint = "http://" + record.HTTPAddr
		ready.GRPCAddress, ready.YamuxAddress = record.GRPCAddr, record.HTTPAddr
	} else {
		ready.ExecutorID = state.Identity
	}
	c, err := client.New(ready.Endpoint, client.Options{})
	if err != nil {
		return err
	}
	if err := awaitDiscovery(startupCtx, c, id); err != nil {
		return fmt.Errorf("service discovery: %w", err)
	}
	if err := startupCtx.Err(); err != nil {
		return context.Cause(startupCtx)
	}
	if err := writeLocalJSON(filepath.Join(dir, "ready.json"), ready); err != nil {
		return err
	}
	if options.Ready != nil {
		if err := options.Ready(ready); err != nil {
			return err
		}
	}
	cancelStartup()
	<-workCtx.Done()
	return context.Cause(workCtx)
}

func validateRoleEndpoint(endpoint string) error {
	if _, err := client.New(endpoint, client.Options{}); err != nil {
		return err
	}
	u, _ := url.Parse(endpoint)
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
		return errors.New("executor up currently requires a literal-loopback http dispatcher URL")
	}
	return nil
}

// EnsureRoleState reads, or on first use creates, the persistent identity of
// a role state directory. The caller owns the mode-0700 directory and keeps it
// under its own control for the duration of the call.
func EnsureRoleState(dir string, role storagecheck.Role, manifest Manifest) (RoleState, error) {
	return readRoleState(dir, role, manifest)
}

func readRoleState(dir string, role storagecheck.Role, manifest Manifest) (RoleState, error) {
	path := filepath.Join(dir, "role-state.json")
	data, err := readRegularFile(path, readyLimit)
	if err == nil {
		var state RoleState
		if err := json.Unmarshal(data, &state); err != nil {
			return state, fmt.Errorf("invalid service state; use another state directory or service name: %w", err)
		}
		if state.Identity == "" {
			state.Identity = state.EarlierIdentity
		}
		state.EarlierIdentity = ""
		id, parseErr := uuid.Parse(state.Identity)
		if state.SchemaVersion != 1 || state.Role != role || parseErr != nil || id == uuid.Nil || id.String() != state.Identity {
			return state, errors.New("state belongs to another role or has invalid identity; use another state directory or service name")
		}
		if state.Version != manifest.Version || state.SourceSHA != manifest.SourceSHA {
			return state, errors.New("state belongs to another installed version; use its original version, another state directory or another service name (automatic upgrades are not supported)")
		}
		return state, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return RoleState{}, err
	}
	for _, name := range []string{"dispatcher.sqlite", "executor.sqlite", "local-state.json"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			return RoleState{}, errors.New("existing state is not a managed service directory; use another state directory or service name")
		}
	}
	id, err := randomUUID()
	if err != nil {
		return RoleState{}, err
	}
	state := RoleState{SchemaVersion: 1, Version: manifest.Version, SourceSHA: manifest.SourceSHA, Identity: id, Role: role}
	return state, writeLocalJSON(path, state)
}
