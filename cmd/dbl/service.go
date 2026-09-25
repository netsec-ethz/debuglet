package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/netsec-ethz/debuglet/internal/demo"
	"github.com/netsec-ethz/debuglet/internal/demo/service"
)

const serviceUsage = `Usage:
  dbl service install (--role dispatcher|executor) [--name NAME] [--user debuglet]
      [--port 9000] [--grpc-port 9001] [--dispatcher 127.0.0.1:9001]
      [--dispatcher-http 127.0.0.1:9000] [--start=false] [--enable=false] [--root DIR]
  dbl service start|stop|status (--role ROLE) [--name NAME]
  dbl service uninstall (--role ROLE) [--name NAME] [--purge]

Install one verified role as a service the host's service manager supervises.
--root writes the same files below another directory to inspect them; a staged
tree drives no service manager, so it cannot be started, stopped or removed.
Installing is repeatable: the same payload and options change nothing the second
time, and a running daemon is never restarted as a side effect. The command
reports readiness only after the daemon published its own readiness record.
Administrator privileges and an existing service account are required; the
foreground commands (dbl up, dbl dispatcher up, dbl executor up) are unchanged.
`

// serviceDependencies is private so the command exposes no fault-injection
// switches. Tests supply a recorder in place of the host's service manager.
type serviceDependencies struct {
	executable func() (string, error)
	resolve    func(string) (demo.Assets, error)
	// manager supplies the service manager for the root the command parsed,
	// so the staging decision is made from the validated options and from
	// nowhere else.
	manager func(root string) (service.Manager, error)
	lookup  func(user, group string) (service.Account, error)
	chown   func(file *os.File, uid, gid int) error
	// root confines the file operations of a test to its own directory
	// while its supplied manager stands in for the host's. It is never set
	// by the command itself; an operator's --root is a staging root and
	// drives no service manager at all.
	root string
}

func productionServiceDependencies() serviceDependencies {
	return serviceDependencies{
		executable: os.Executable,
		resolve:    demo.ResolveAssets,
		manager:    productionServiceManager,
	}
}

// productionServiceManager chooses the manager for an operator's parsed --root.
// A staged tree never reaches the host's service manager, not even to read a
// unit state: the unit of that name there is the production one.
func productionServiceManager(root string) (service.Manager, error) {
	if root != "" {
		return service.StagingManager{}, nil
	}
	return service.NewSystemctl()
}

// serviceOptions are the flags every service subcommand shares.
type serviceOptions struct {
	Role, Name, Root, User, Group string
	Purge                         bool
	Request                       service.Request
	Start, Enable                 bool
}

func serviceCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer) int {
	return serviceCommandWith(ctx, args, options, stdout, stderr, productionServiceDependencies())
}

func serviceCommandWith(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer, deps serviceDependencies) int {
	if len(args) == 0 {
		return usageError("dbl service", serviceUsage, stderr, "missing subcommand")
	}
	subcommand := args[0]
	if subcommand == "--help" || subcommand == "-h" {
		fmt.Fprint(stdout, serviceUsage)
		return exitOK
	}
	switch subcommand {
	case "install", "start", "stop", "status", "uninstall":
	default:
		return usageError("dbl service", serviceUsage, stderr, "expected install, start, stop, status or uninstall")
	}
	name := "dbl service " + subcommand
	fs := newCommandFlagSet("service " + subcommand)
	var local serviceOptions
	serviceFlags(fs, &local, subcommand)
	if code, ok := parseCommandFlags(fs, args[1:], serviceUsage, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() != 0 {
		return usageError(name, serviceUsage, stderr, "unexpected positional arguments")
	}
	role, code, ok := serviceRole(name, &local, fs, options, stderr)
	if !ok {
		return code
	}
	if code, ok := checkStagingRoot(name, serviceUsage, local, fs, subcommand, stderr); !ok {
		return code
	}
	installer, code, ok := newInstaller(name, local, deps, stderr)
	if !ok {
		return code
	}
	var report service.Report
	var err error
	switch subcommand {
	case "install":
		var assets demo.Assets
		if local.Root != "" {
			local.Start, local.Enable = false, false
		}
		if assets, err = resolveServiceAssets(deps); err == nil {
			local.Request.Role, local.Request.Name = role, local.Name
			local.Request.User, local.Request.Group = local.User, local.Group
			report, err = installer.Install(ctx, local.Request, assets, local.Start, local.Enable)
		}
	case "start":
		report, err = installer.Start(ctx, role, local.Name)
	case "stop":
		report, err = installer.Stop(ctx, role, local.Name)
	case "status":
		report, err = installer.Status(ctx, role, local.Name)
	case "uninstall":
		report, err = installer.Uninstall(ctx, role, local.Name, local.Purge)
	}
	if report.Operation != "" {
		if code := emitReported(ctx, name, options.Output, stdout, stderr, report,
			func(w io.Writer) error { return writeServiceReport(w, report) }); code != exitOK {
			return code
		}
	}
	if err != nil {
		return reportFailure(ctx, name, stderr, err)
	}
	return exitOK
}

// serviceFlags registers the flags of one subcommand. Only install takes the
// options that describe a new installation; the other subcommands read the
// contract back from the installed record.
func serviceFlags(fs *flag.FlagSet, local *serviceOptions, subcommand string) {
	fs.StringVar(&local.Role, "role", "", "dispatcher or executor")
	fs.StringVar(&local.Name, "name", "", "name of this managed instance (default local for a dispatcher, worker for an executor)")
	fs.StringVar(&local.Root, "root", "", "stage every managed path below this directory instead of the system root")
	switch subcommand {
	case "install":
		fs.StringVar(&local.User, "user", service.DefaultAccount, "existing service account to run as")
		fs.StringVar(&local.Group, "group", "", "existing service group (default: the service account's own name)")
		fs.IntVar(&local.Request.HTTPPort, "port", service.DefaultHTTPPort, "dispatcher loopback HTTP port")
		fs.IntVar(&local.Request.GRPCPort, "grpc-port", service.DefaultGRPCPort, "dispatcher loopback control port")
		fs.StringVar(&local.Request.DispatcherGRPC, "dispatcher", "", "executor: dispatcher control address as host:port")
		fs.StringVar(&local.Request.DispatcherHTTP, "dispatcher-http", "", "executor: dispatcher HTTP address as host:port")
		fs.BoolVar(&local.Start, "start", true, "start the unit and observe its readiness record")
		fs.BoolVar(&local.Enable, "enable", true, "let the service manager start the unit at boot")
	case "uninstall":
		fs.BoolVar(&local.Purge, "purge", false, "also delete the state directory, its database, identity and retained results")
	}
}

// serviceRole validates the selected role and fills in the default instance
// name. Managed services take no dispatcher endpoint: they are local
// administration of this host, not a client of a remote one.
func serviceRole(name string, local *serviceOptions, fs *flag.FlagSet, options globalOptions, stderr io.Writer) (demo.SchemaRole, int, bool) {
	if options.EndpointSet || options.Dispatcher != "" {
		return "", usageError(name, serviceUsage, stderr, "managed service commands administer this host; they take no --endpoint or --dispatcher"), false
	}
	var role demo.SchemaRole
	switch local.Role {
	case string(demo.DispatcherSchema):
		role = demo.DispatcherSchema
	case string(demo.ExecutorSchema):
		role = demo.ExecutorSchema
	case "":
		return "", usageError(name, serviceUsage, stderr, "--role dispatcher or --role executor is required"), false
	default:
		return "", usageError(name, serviceUsage, stderr, "unknown --role %q", local.Role), false
	}
	blank := false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "name", "root", "user", "group", "dispatcher", "dispatcher-http":
			if strings.TrimSpace(f.Value.String()) == "" {
				blank = true
			}
		}
	})
	if blank {
		return "", usageError(name, serviceUsage, stderr, "explicit option values must not be blank"), false
	}
	if local.Name == "" {
		local.Name = defaultInstanceName(role)
	}
	return role, exitOK, true
}

// defaultInstanceName keeps the managed names the same as the foreground ones.
func defaultInstanceName(role demo.SchemaRole) string {
	if role == demo.DispatcherSchema {
		return "local"
	}
	return "worker"
}

// checkStagingRoot keeps a staged tree from reaching the host's one service
// manager. Only the units at their real paths are that manager's; a staged unit
// of the same name would name the production instance, and a staged unit's
// runtime directory is the real one either way.
func checkStagingRoot(name, usage string, local serviceOptions, fs *flag.FlagSet, subcommand string, stderr io.Writer) (int, bool) {
	if local.Root == "" {
		return exitOK, true
	}
	if subcommand != "install" && subcommand != "status" {
		return usageError(name, usage, stderr, "--root stages files only; %s acts on the host service manager and cannot be staged", subcommand), false
	}
	asked := ""
	fs.Visit(func(f *flag.Flag) {
		if (f.Name == "start" || f.Name == "enable") && f.Value.String() == "true" {
			asked = f.Name
		}
	})
	if asked != "" {
		return usageError(name, usage, stderr, "--root stages files only; --%s needs the host service manager", asked), false
	}
	return exitOK, true
}

func newInstaller(name string, local serviceOptions, deps serviceDependencies, stderr io.Writer) (*service.Installer, int, bool) {
	// The manager is chosen from the root the command parsed and validated, so
	// there is one reading of --root and a staged tree cannot be handed the
	// host's service manager. deps.root is a test's own file confinement and
	// names no staging root.
	manager, err := deps.manager(local.Root)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", name, err)
		return nil, exitFailure, false
	}
	root := local.Root
	if deps.root != "" {
		root = deps.root
	}
	installer, err := service.New(service.Options{
		Root: root, Manager: manager, LookupAccount: deps.lookup, Chown: deps.chown,
	})
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", name, err)
		return nil, exitFailure, false
	}
	return installer, exitOK, true
}

func resolveServiceAssets(deps serviceDependencies) (demo.Assets, error) {
	exe, err := deps.executable()
	if err != nil {
		return demo.Assets{}, err
	}
	return deps.resolve(exe)
}

// writeServiceReport renders the observation for a reader. The caller emits it
// once, whether or not the operation also failed: an operator has to see what
// state the host is in either way.
func writeServiceReport(stdout io.Writer, report service.Report) error {
	readiness := "not ready"
	if report.Ready {
		readiness = "ready"
	}
	if _, err := fmt.Fprintf(stdout, "%s %s %s: %s (%s)\n", report.Operation, report.Role, report.Name, report.State, readiness); err != nil {
		return err
	}
	for _, line := range []struct{ label, value string }{
		{"unit", report.Unit}, {"version", report.Version}, {"state directory", report.StateDir},
		{"unit file", report.UnitPath}, {"executor", report.ExecutorID}, {"endpoint", report.Endpoint},
		{"service manager", report.Active},
	} {
		if line.value == "" {
			continue
		}
		if _, err := fmt.Fprintf(stdout, "  %s: %s\n", line.label, line.value); err != nil {
			return err
		}
	}
	if len(report.Changed) > 0 {
		if _, err := fmt.Fprintf(stdout, "  changed: %s\n", strings.Join(report.Changed, ", ")); err != nil {
			return err
		}
	}
	if report.RestartRequired {
		if _, err := fmt.Fprintln(stdout, "  restart required to apply the change"); err != nil {
			return err
		}
	}
	if report.Note != "" {
		if _, err := fmt.Fprintf(stdout, "  note: %s\n", report.Note); err != nil {
			return err
		}
	}
	return nil
}
