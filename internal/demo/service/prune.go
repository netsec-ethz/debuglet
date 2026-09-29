package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/netsec-ethz/debuglet/internal/artifact"
	"github.com/netsec-ethz/debuglet/internal/demo"
)

// Prune removes one verified inactive administrator-owned system package.
// User-owned installation prefixes are not supported. Retained service records pin
// their payload even after uninstall, so recovery never loses its binary.
// The shared installer lock prevents a simultaneous install changing the CLI
// link. Operators must stop foreground roles before pruning their version.
func (i *Installer) Prune(ctx context.Context, prefix, version, component string, dryRun bool) (Report, error) {
	if os.Geteuid() != 0 {
		return Report{Operation: "prune", Version: version, State: "incomplete"}, errors.New("service prune requires administrator access and an administrator-owned system prefix; user-owned installation prefixes are not supported")
	}
	return i.prune(ctx, prefix, version, component, dryRun, "/proc")
}

func (i *Installer) prune(ctx context.Context, prefix, version, component string, dryRun bool, proc string) (report Report, err error) {
	report = Report{Operation: "prune", Version: version, State: "incomplete"}
	if component == "full" {
		component = ""
	}
	if artifact.PayloadModesFor(component) == nil {
		return report, errors.New("prune component must be full, cli, dispatcher or executor")
	}
	if !artifact.ValidVersion(version) || !filepath.IsAbs(prefix) || filepath.Clean(prefix) != prefix || prefix == "/" {
		return report, errors.New("prune requires an absolute installation prefix and one valid version")
	}
	// Check every prefix component before resolving any managed path.
	for path := prefix; path != filepath.Dir(path); path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() {
			return report, fmt.Errorf("installation prefix contains a missing or non-directory component: %s", path)
		}
	}
	managed := filepath.Join(prefix, "lib", "debuglet")
	for _, path := range []string{prefix, filepath.Join(prefix, "bin"), filepath.Join(prefix, "lib"), managed} {
		if err := ownedPackagePath(path, true); err != nil {
			return report, err
		}
	}
	componentRoot, command := managed, "dbl"
	if component != "" {
		componentRoot = filepath.Join(managed, component)
		if err := ownedPackagePath(componentRoot, true); err != nil {
			return report, err
		}
		if component != "cli" {
			command = "debuglet-" + component
		}
	}
	lock := filepath.Join(managed, ".install.lock")
	if err := os.Mkdir(lock, 0700); err != nil {
		return report, fmt.Errorf("cannot acquire installation lock; another install or prune may be running: %w", err)
	}
	defer func() { err = errors.Join(err, os.Remove(lock)) }()
	candidate := filepath.Join(componentRoot, version)
	if err := filepath.WalkDir(candidate, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return ownedPackagePath(path, entry.IsDir())
	}); err != nil {
		return report, err
	}
	manifest, err := artifact.Verify(candidate)
	if err != nil {
		return report, fmt.Errorf("refusing to prune unverified package: %w", err)
	}
	if manifest.Version != version || manifest.Component != component {
		return report, errors.New("package directory and manifest identity disagree")
	}
	if err := checkPackageLinks(prefix, candidate, command); err != nil {
		return report, err
	}
	if err := i.checkRetainedPackages(candidate); err != nil {
		return report, err
	}
	if err := checkExecutingPackage(proc, candidate); err != nil {
		return report, err
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	report.PackagePath = candidate
	if dryRun {
		report.State, report.Note = "retained", "inactive verified package; no files removed (dry run)"
		return report, nil
	}
	root, err := os.OpenRoot(componentRoot)
	if err != nil {
		return report, err
	}
	defer root.Close()
	if err := root.RemoveAll(version); err != nil {
		return report, err
	}
	report.State, report.Changed = "pruned", []string{"inactive package"}
	return report, nil
}

func checkPackageLinks(prefix, candidate, command string) error {
	bin := filepath.Join(prefix, "bin")
	entries, err := os.ReadDir(bin)
	if err != nil {
		return err
	}
	// A full package may still supply either daemon after its CLI is replaced
	// by a component package. Other command aliases must remain usable too.
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink == 0 {
			continue
		}
		path := filepath.Join(bin, entry.Name())
		target, err := filepath.EvalSymlinks(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("cannot inspect command link %s: %w", path, err)
		}
		if target == candidate || strings.HasPrefix(target, candidate+string(filepath.Separator)) {
			return fmt.Errorf("package is active through %s", path)
		}
	}
	link, err := os.Readlink(filepath.Join(bin, command))
	if err != nil {
		return fmt.Errorf("refusing to prune without a managed %s link: %w", command, err)
	}
	current := strings.TrimSuffix(strings.TrimPrefix(link, "../lib/debuglet/"), "/bin/"+command)
	parts := strings.Split(current, "/")
	component, version := "", parts[len(parts)-1]
	if len(parts) == 2 {
		component = parts[0]
	}
	matchingComponent := component == "cli" && command == "dbl" || component == "dispatcher" && command == "debuglet-dispatcher" || component == "executor" && command == "debuglet-executor"
	if len(parts) > 2 || !artifact.ValidVersion(version) || link != "../lib/debuglet/"+current+"/bin/"+command ||
		(len(parts) == 2 && !matchingComponent) {
		return fmt.Errorf("bin/%s is not a managed installation link", command)
	}
	root := filepath.Join(prefix, "lib", "debuglet", current)
	if component != "" {
		if err := ownedPackagePath(filepath.Dir(root), true); err != nil {
			return err
		}
	}
	if err := ownedPackagePath(root, true); err != nil {
		return err
	}
	manifest, err := artifact.Verify(root)
	if err != nil {
		return fmt.Errorf("active %s package is not intact: %w", command, err)
	}
	if manifest.Version != version || manifest.Component != component {
		return errors.New("active package directory and manifest identity disagree")
	}
	return nil
}

func ownedPackagePath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Uid) != uint64(os.Geteuid()) || info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("package path must be owned by this user and not writable by others: %s", path)
	}
	if directory {
		if !info.IsDir() {
			return fmt.Errorf("package directory is not a real directory: %s", path)
		}
	} else if names, known := demo.FileNames(info); !info.Mode().IsRegular() || !known || names != 1 {
		return fmt.Errorf("package file must be regular with one name: %s", path)
	}
	return nil
}

func (i *Installer) checkRetainedPackages(candidate string) error {
	entries, err := os.ReadDir(AdministrationDirectory(i.root))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(AdministrationDirectory(i.root), entry.Name())
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() > recordLimit {
			return fmt.Errorf("cannot establish package ownership from record %s", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var record Profile
		if err := json.Unmarshal(data, &record); err != nil || record.PayloadRoot == "" {
			return fmt.Errorf("cannot establish package ownership from record %s", path)
		}
		if filepath.Clean(record.PayloadRoot) == candidate {
			return fmt.Errorf("package retained by %s %s; keep it for reinstall or explicitly purge that role first", record.Role, record.Name)
		}
	}
	return nil
}

func checkExecutingPackage(proc, candidate string) error {
	return inspectExecutables(proc, 0, func(pid, exe string) error {
		if strings.HasPrefix(exe, candidate+string(filepath.Separator)) {
			return fmt.Errorf("package is executing in process %s; stop it before pruning", pid)
		}
		return nil
	})
}

// inspectExecutables shares the fail-closed procfs walk with enrollment adoption.
func inspectExecutables(proc string, ignorePID int, inspect func(pid, executable string) error) error {
	entries, err := os.ReadDir(proc)
	if err != nil {
		return fmt.Errorf("cannot check running executables: %w", err)
	}
	for _, entry := range entries {
		if entry.Name() == strconv.Itoa(ignorePID) {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil || !entry.IsDir() {
			continue
		}
		exe, err := os.Readlink(filepath.Join(proc, entry.Name(), "exe"))
		if errors.Is(err, os.ErrNotExist) {
			continue // Exited process or kernel thread without an executable.
		}
		if err != nil {
			return fmt.Errorf("cannot inspect process %s; run with administrator access after stopping foreground roles: %w", entry.Name(), err)
		}
		if err := inspect(entry.Name(), exe); err != nil {
			return err
		}
	}
	return nil
}
