// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"errors"
	"flag"
	"io"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/netsec-ethz/debuglet/internal/ipmetadata"
	"github.com/netsec-ethz/debuglet/internal/ipmetadata/ris"
)

// Only refusals are exercised: a build would contact RIPE.
func TestASNBuildFlagsAreExclusive(t *testing.T) {
	parse := func(args ...string) (*flag.FlagSet, string, int, time.Duration) {
		fs := flag.NewFlagSet("dispatcher", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		output := fs.String("build-asn-database", "", "")
		peers := fs.Int("ris-min-peers", ris.DefaultMinPeers, "")
		age := fs.Duration("ris-max-age", ris.DefaultMaxAge, "")
		fs.String("config", "", "")
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		return fs, *output, *peers, *age
	}
	if handled, err := runASNBuild(parse("-config", "x.toml")); handled || err != nil {
		t.Fatalf("an ordinary start was taken for a build: %t %v", handled, err)
	}
	for args, want := range map[string]string{
		"-ris-min-peers 5":                       "only valid with",
		"-build-asn-database x -config y":        "cannot be combined",
		"-build-asn-database x extra":            "cannot be combined",
		"-build-asn-database=":                   "needs the path",
		"-build-asn-database x -ris-min-peers 0": "at least 1",
		"-build-asn-database x -ris-max-age 0s":  "must be positive",
	} {
		handled, err := runASNBuild(parse(strings.Fields(args)...))
		if !handled || err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %t %v", args, handled, err)
		}
	}
}

func TestMetadataReloadIsLogged(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)
	logMetadataReload(logger, ipmetadata.Reloaded{Kind: "asn", Path: "/x", Source: "database:A@1"})
	logMetadataReload(logger, ipmetadata.Reloaded{Kind: "asn", Path: "/x", Source: "database:A@1", Err: errors.New("bad")})
	entries := logs.All()
	if len(entries) != 2 || entries[0].Level != zap.InfoLevel || entries[1].Level != zap.WarnLevel || entries[1].ContextMap()["source"] != "database:A@1" {
		t.Fatalf("logs %+v", entries)
	}
}
