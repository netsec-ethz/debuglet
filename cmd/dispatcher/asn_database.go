// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/netsec-ethz/debuglet/internal/ipmetadata"
	"github.com/netsec-ethz/debuglet/internal/ipmetadata/ris"
)

// runASNBuild serves -build-asn-database. It reports whether the flags asked
// for a build (or misused its options), so that nothing else runs.
func runASNBuild(fs *flag.FlagSet, output string, minPeers int, maxAge time.Duration) (bool, error) {
	requested, options, others := false, false, false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "build-asn-database":
			requested = true
		case "ris-min-peers", "ris-max-age":
			options = true
		default:
			others = true
		}
	})
	switch {
	case !requested && !options:
		return false, nil
	case !requested:
		return true, errors.New("-ris-min-peers and -ris-max-age are only valid with -build-asn-database")
	case others || fs.NArg() != 0:
		return true, errors.New("-build-asn-database cannot be combined with flags other than -ris-min-peers and -ris-max-age, or with arguments")
	case output == "":
		return true, errors.New("-build-asn-database needs the path of the database to replace")
	case minPeers < 1:
		return true, errors.New("-ris-min-peers must be at least 1")
	case maxAge <= 0:
		return true, errors.New("-ris-max-age must be positive")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	summary, err := ris.Build(ctx, ris.Options{Output: output, MinPeers: minPeers, MaxAge: maxAge})
	if err != nil {
		return true, fmt.Errorf("build ASN database %s: %w", output, err)
	}
	s := summary.Stats
	verb := "replaced"
	if !summary.Replaced {
		verb = "kept; it is already as recent as the RIS dumps"
	}
	fmt.Printf("ASN database %s %s: %s (RIS dumps of %s; %d IPv4 and %d IPv6 prefixes seen by at least %d peers, %d with several origins; %d AS names; skipped %d rows below the threshold, %d AS sets, %d reserved origins, %d non-global prefixes)\n",
		output, verb, summary.Source, summary.Generated.Format(time.RFC3339), s.IPv4, s.IPv6, minPeers, s.MOAS, summary.ASNames,
		s.BelowThreshold, s.ASSets, s.ReservedOrigin, s.Unroutable)
	return true, nil
}

// metadataReloadInterval is how often the dispatcher checks whether a
// configured metadata database was replaced. Replacing it does not drop any
// executor connection; executors registering afterwards are looked up in the
// new file.
const metadataReloadInterval = time.Minute

func logMetadataReload(logger *zap.Logger, r ipmetadata.Reloaded) {
	fields := []zap.Field{zap.String("database", r.Kind), zap.String("path", r.Path), zap.String("source", r.Source)}
	if r.Err != nil {
		logger.Warn("Refused a replaced IP metadata database; the previous one stays in use", append(fields, zap.Error(r.Err))...)
		return
	}
	logger.Info("Loaded a replaced IP metadata database", fields...)
}
