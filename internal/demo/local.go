package demo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/fsutil"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

const localStartupTimeout = 30 * time.Second

// LocalEnvironment describes the currently running local services.
type LocalEnvironment struct {
	State      string `json:"state"`
	Endpoint   string `json:"endpoint"`
	ExecutorID string `json:"executor_id"`
	StateDir   string `json:"state_dir"`
}

type LocalOptions struct {
	StateDir string
	Port     int
	Ready    func(LocalEnvironment) error
}

type localState struct {
	SchemaVersion int    `json:"schema_version"`
	Version       string `json:"version"`
	SourceSHA     string `json:"source_sha"`
	ExecutorID    string `json:"executor_id"`
}

// DefaultLocalStateDir follows the XDG state convention without depending on
// the current working directory.
func DefaultLocalStateDir() (string, error) {
	if dir := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(dir) {
		return filepath.Join(dir, "debuglet"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find home directory; supply --state-dir: %w", err)
	}
	return filepath.Join(home, ".local", "state", "debuglet"), nil
}

// Up runs an installed loopback environment until cancellation. Databases and
// identity survive clean shutdown; environment.json exists only while ready.
// A canceled context means a normal stop, provided child cleanup succeeds.
func Up(ctx context.Context, assets Assets, options LocalOptions) error {
	return up(ctx, assets, options, productionDependencies(), localStartupTimeout)
}

func up(ctx context.Context, assets Assets, options LocalOptions, deps dependencies, startupTimeout time.Duration) (err error) {
	if runtime.GOOS != "linux" {
		return errors.New("local environment requires Linux")
	}
	if options.Port < 0 || options.Port > 65535 {
		return errors.New("local HTTP port must be between 0 and 65535")
	}
	if ctx.Err() != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil
		}
		return ctx.Err()
	}
	assets, err = deps.resolveAssets(assets.CLI)
	if err != nil {
		return fmt.Errorf("verify installed environment: %w", err)
	}
	dir := options.StateDir
	if dir == "" {
		dir, err = DefaultLocalStateDir()
		if err != nil {
			return err
		}
	}
	dir, unlock, err := prepareStateDir(dir, "local state")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	state, err := readLocalState(dir, assets.Manifest)
	if err != nil {
		return err
	}

	workCtx, cancelWork := context.WithCancelCause(ctx)
	watchCtx, cancelWatches := context.WithCancel(workCtx)
	startupCtx, cancelStartup := context.WithTimeout(workCtx, startupTimeout)
	defer cancelStartup()
	var watchers sync.WaitGroup
	var children []childProcess
	var logs []*os.File
	defer func() {
		cancelWatches()
		watchers.Wait()
		cancelWork(nil)
		if ctx.Err() == context.Canceled && localCancellationOnly(err) {
			err = nil
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		for i := len(children) - 1; i >= 0; i-- {
			phase, end := cleanupPhase(cleanupCtx, i+1)
			err = errors.Join(err, children[i].Stop(phase))
			end()
		}
		for _, child := range children {
			if !child.CleanupComplete() {
				err = errors.Join(err, child.Stop(cleanupCtx))
			}
			if !child.CleanupComplete() {
				err = errors.Join(err, errors.New("local child cleanup incomplete; inspect retained state before restarting"))
			}
		}
		for _, log := range logs {
			err = errors.Join(err, log.Close())
		}
		for _, name := range []string{"environment.json", "dispatcher-ready.json", "executor-ready.json"} {
			err = errors.Join(err, removeLocalFile(filepath.Join(dir, name)))
		}
	}()
	for _, name := range []string{"environment.json", "dispatcher-ready.json", "executor-ready.json", "dispatcher.toml", "executor.toml"} {
		if err := removeLocalFile(filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	for _, role := range []SchemaRole{DispatcherSchema, ExecutorSchema} {
		if _, _, err := deps.prepareRoleDatabase(startupCtx, role, dir); err != nil {
			return err
		}
	}
	start := func(name, executable string, config map[string]any) (childProcess, error) {
		configPath := filepath.Join(dir, name+".toml")
		if err := writeConfig(configPath, config); err != nil {
			return nil, err
		}
		log, err := os.OpenFile(filepath.Join(dir, name+".log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return nil, err
		}
		logs = append(logs, log)
		child, err := deps.startChild(ChildSpec{Path: executable, Dir: dir,
			Args: []string{"--config", configPath, "--ready-file", filepath.Join(dir, name+"-ready.json")},
			Env:  childEnvironment(dir), Stdout: log, Stderr: log})
		if err != nil {
			return nil, err
		}
		children = append(children, child)
		watchChild(watchCtx, &watchers, name, child, cancelWork)
		return child, nil
	}
	config := dispatcherConfiguration(assets.Manifest.Version, filepath.Join(dir, "dispatcher.sqlite"))
	config["server"].(map[string]any)["http_port"] = options.Port
	dispatcher, err := start("dispatcher", assets.Dispatcher, config)
	if err != nil {
		return fmt.Errorf("start dispatcher: %w", err)
	}
	record, err := awaitReady(startupCtx, filepath.Join(dir, "dispatcher-ready.json"), dispatcher.PID(), "")
	if err != nil {
		return fmt.Errorf("dispatcher readiness (see %s): %w", filepath.Join(dir, "dispatcher.log"), err)
	}
	endpoint := "http://" + record.HTTPAddr
	c, err := client.New(endpoint, client.Options{})
	if err != nil {
		return err
	}
	executor, err := start("executor", assets.Executor, executorConfiguration(assets.Manifest.Version, state.ExecutorID, filepath.Join(dir, "executor.sqlite"), record))
	if err != nil {
		return fmt.Errorf("start executor: %w", err)
	}
	if _, err := awaitReady(startupCtx, filepath.Join(dir, "executor-ready.json"), executor.PID(), state.ExecutorID); err != nil {
		return fmt.Errorf("executor readiness (see %s): %w", filepath.Join(dir, "executor.log"), err)
	}
	if err := awaitDiscovery(startupCtx, c, state.ExecutorID); err != nil {
		return fmt.Errorf("executor discovery: %w", err)
	}
	if err := startupCtx.Err(); err != nil {
		return context.Cause(startupCtx)
	}
	ready := LocalEnvironment{State: "ready", Endpoint: endpoint, ExecutorID: state.ExecutorID, StateDir: dir}
	if err := writeLocalJSON(filepath.Join(dir, "environment.json"), ready); err != nil {
		return err
	}
	if options.Ready != nil {
		if err := options.Ready(ready); err != nil {
			return fmt.Errorf("publish local readiness: %w", err)
		}
	}
	cancelStartup()
	<-workCtx.Done()
	return context.Cause(workCtx)
}

func readLocalState(dir string, manifest Manifest) (localState, error) {
	path := filepath.Join(dir, "local-state.json")
	data, err := readRegularFile(path, readyLimit)
	if err == nil {
		var state localState
		if err := json.Unmarshal(data, &state); err != nil {
			return state, fmt.Errorf("invalid local state metadata; choose a new --state-dir: %w", err)
		}
		id, parseErr := uuid.Parse(state.ExecutorID)
		if state.SchemaVersion != 1 || parseErr != nil || id == uuid.Nil || id.String() != state.ExecutorID {
			return state, errors.New("invalid local state identity; choose a new --state-dir")
		}
		if state.Version != manifest.Version || state.SourceSHA != manifest.SourceSHA {
			return state, errors.New("local state belongs to a different installed version; restart with its original version or choose a new --state-dir (automatic database upgrades are not supported)")
		}
		return state, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return localState{}, err
	}
	for _, name := range []string{"dispatcher.sqlite", "executor.sqlite"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			return localState{}, errors.New("existing database has no local state metadata; choose a new --state-dir")
		}
	}
	id, err := randomUUID()
	if err != nil {
		return localState{}, err
	}
	state := localState{SchemaVersion: 1, Version: manifest.Version, SourceSHA: manifest.SourceSHA, ExecutorID: id}
	return state, writeLocalJSON(path, state)
}

func writeLocalJSON(path string, value any) (err error) {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return fsutil.WriteFile(path, append(data, '\n'), 0600)
}

// prepareStateDir makes dir absolute, creates it when absent and then refuses
// anything but a real mode-0700 directory owned by this user, so retained
// databases and identities are never served out of state someone else can
// reach. The returned function releases the exclusive lock that keeps a second
// process off the same directory.
func prepareStateDir(dir, noun string) (string, func() error, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", nil, fmt.Errorf("create %s: %w", noun, err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", nil, err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return "", nil, fmt.Errorf("%s must be a real mode-0700 directory; choose a new --state-dir", noun)
	}
	if err := schemaParentOwned(info); err != nil {
		return "", nil, err
	}
	unlock, err := lockLocalState(dir)
	if err != nil {
		return "", nil, err
	}
	return dir, unlock, nil
}

func removeLocalFile(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Preserve a cleanup error joined with cancellation; only a plain cancellation
// (possibly annotated by a single wrapping error) is a successful signal stop.
func localCancellationOnly(err error) bool {
	for err != nil {
		if err == context.Canceled {
			return true
		}
		wrapped, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = wrapped.Unwrap()
	}
	return false
}
