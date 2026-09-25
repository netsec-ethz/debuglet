package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/demo"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := mainCommand(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
func mainCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("local-compatibility", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var manifestPath, root string
	var opts Options
	flags.StringVar(&manifestPath, "manifest", "", "")
	flags.StringVar(&root, "installed-root", "", "")
	flags.StringVar(&opts.ArchiveSHA256, "archive-sha256", "", "")
	flags.StringVar(&opts.EvidenceDir, "evidence-dir", "", "")
	flags.BoolVar(&opts.DryRun, "dry-run", false, "")
	if flags.Parse(args) != nil || flags.NArg() != 0 || manifestPath == "" || !filepath.IsAbs(root) {
		fmt.Fprintln(stderr, "local-compatibility: invalid arguments")
		return 2
	}
	var err error
	opts.Manifest, err = LoadManifest(manifestPath)
	if err == nil {
		opts.Assets, err = demo.ResolveAssets(filepath.Join(root, "bin", "dbl"))
	}
	if err != nil {
		fmt.Fprintln(stderr, "local-compatibility: invalid manifest or installation")
		return 2
	}
	ev, err := Run(ctx, opts)
	if json.NewEncoder(stdout).Encode(ev) != nil {
		return 1
	}
	switch {
	case err == nil:
		return 0
	case errors.Is(err, context.Canceled):
		return 130
	case errors.Is(err, context.DeadlineExceeded):
		return 124
	case errors.Is(err, errInvalidInput):
		return 2
	default:
		return 1
	}
}
