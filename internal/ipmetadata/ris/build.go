// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package ris

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// The published inputs.
const (
	IPv4DumpURL = "https://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz"
	IPv6DumpURL = "https://www.ris.ripe.net/dumps/riswhoisdump.IPv6.gz"
	ASNamesURL  = "https://ftp.ripe.net/ripe/asnames/asn.txt"

	// DefaultMaxAge refuses dumps RIS has not regenerated for three days.
	DefaultMaxAge = 72 * time.Hour

	// Download bounds, several times today's sizes (about 6, 2 and 7 MB;
	// 35 MB decompressed for IPv4).
	maxCompressed   = 64 << 20
	maxDecompressed = 512 << 20
	maxASNames      = 64 << 20
)

// Options configures Build. Zero values select the defaults.
type Options struct {
	Output   string // the database path the dispatcher reads
	MinPeers int
	MaxAge   time.Duration

	// Minimum sizes of a usable build; zero selects MinIPv4Prefixes,
	// MinIPv6Prefixes and MinASNames.
	MinIPv4, MinIPv6, MinNames int

	IPv4URL, IPv6URL, ASNamesURL string
	Client                       *http.Client
	Now                          func() time.Time
}

// Summary describes a build.
type Summary struct {
	Source    string // database:<type>@<epoch> of the database now at Output
	Replaced  bool   // false when Output already held this build or a newer one
	Generated time.Time
	Stats     Stats
	ASNames   int
}

// Build downloads the RIS dumps and AS names, selects routes, writes the
// database to a staging file next to Output, verifies it with the
// dispatcher's own loader and renames it over Output. Output is replaced only
// by a complete, verified file and never by an older build. The build epoch is
// the generation time of the older of the two dumps, so a rebuild from the
// same dumps yields the same source.
func Build(ctx context.Context, opts Options) (Summary, error) {
	if opts.Output == "" {
		return Summary{}, errors.New("no output path")
	}
	if opts.MinPeers == 0 {
		opts.MinPeers = DefaultMinPeers
	}
	if opts.MinPeers < 1 {
		return Summary{}, errors.New("the RIS peer threshold must be at least 1")
	}
	if opts.MaxAge == 0 {
		opts.MaxAge = DefaultMaxAge
	}
	opts.MinIPv4 = cmp.Or(opts.MinIPv4, MinIPv4Prefixes)
	opts.MinIPv6 = cmp.Or(opts.MinIPv6, MinIPv6Prefixes)
	opts.MinNames = cmp.Or(opts.MinNames, MinASNames)
	if opts.IPv4URL == "" {
		opts.IPv4URL = IPv4DumpURL
	}
	if opts.IPv6URL == "" {
		opts.IPv6URL = IPv6DumpURL
	}
	if opts.ASNamesURL == "" {
		opts.ASNamesURL = ASNamesURL
	}
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: 10 * time.Minute}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	var dumps [2]Dump
	for i, url := range []string{opts.IPv4URL, opts.IPv6URL} {
		compressed, err := fetch(ctx, opts.Client, url, maxCompressed)
		if err != nil {
			return Summary{}, fmt.Errorf("%s: %w", url, err)
		}
		text, err := gunzip(compressed)
		if err != nil {
			return Summary{}, fmt.Errorf("%s: %w", url, err)
		}
		if dumps[i], err = ParseDump(bytes.NewReader(text), i == 1); err != nil {
			return Summary{}, fmt.Errorf("%s: %w", url, err)
		}
		now := opts.Now()
		if age := now.Sub(dumps[i].Generated); age > opts.MaxAge || age < -time.Hour {
			return Summary{}, fmt.Errorf("%s was generated at %s, outside the accepted age of %s", url, dumps[i].Generated.Format(time.RFC3339), opts.MaxAge)
		}
	}
	text, err := fetch(ctx, opts.Client, opts.ASNamesURL, maxASNames)
	if err == nil {
		err = requireFinalNewline(text)
	}
	if err != nil {
		return Summary{}, fmt.Errorf("%s: %w", opts.ASNamesURL, err)
	}
	names, err := ParseASNames(bytes.NewReader(text))
	if err != nil {
		return Summary{}, fmt.Errorf("%s: %w", opts.ASNamesURL, err)
	}

	generated := dumps[0].Generated
	if dumps[1].Generated.Before(generated) {
		generated = dumps[1].Generated
	}
	routes, stats := Select(append(dumps[0].Rows, dumps[1].Rows...), opts.MinPeers)
	dumps = [2]Dump{} // release the rows before the tree is built
	summary := Summary{Generated: generated, Stats: stats, ASNames: len(names)}
	switch {
	case stats.IPv4 < opts.MinIPv4:
		err = fmt.Errorf("only %d IPv4 prefixes are seen by at least %d RIS peers, fewer than %d", stats.IPv4, opts.MinPeers, opts.MinIPv4)
	case stats.IPv6 < opts.MinIPv6:
		err = fmt.Errorf("only %d IPv6 prefixes are seen by at least %d RIS peers, fewer than %d", stats.IPv6, opts.MinPeers, opts.MinIPv6)
	case len(names) < opts.MinNames:
		err = fmt.Errorf("only %d AS names, fewer than %d", len(names), opts.MinNames)
	}
	if err != nil {
		return summary, fmt.Errorf("refusing a near-empty database: %w", err)
	}

	epoch := generated.Unix()
	summary.Source = "database:" + DatabaseType + "@" + fmt.Sprint(epoch)
	if current, ok := currentEpoch(opts.Output); ok && current >= uint64(epoch) {
		summary.Source = "database:" + DatabaseType + "@" + fmt.Sprint(current)
		return summary, nil
	}
	if err := install(opts.Output, func(w io.Writer) error {
		return Write(w, routes, names, epoch, opts.MinPeers)
	}, func(path string) error {
		return Verify(path, routes, names, epoch)
	}); err != nil {
		return summary, err
	}
	summary.Replaced = true
	return summary, nil
}

func fetch(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// The files are taken byte for byte, without transparent decoding, so
	// that their length can be checked against the announced one.
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "debuglet-dispatcher (+https://github.com/netsec-ethz/debuglet)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}
	if resp.ContentLength < 0 || resp.ContentLength > limit {
		return nil, fmt.Errorf("refusing a response of unknown or excessive length (%d bytes)", resp.ContentLength)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) != resp.ContentLength {
		return nil, fmt.Errorf("received %d of %d bytes", len(body), resp.ContentLength)
	}
	return body, nil
}

// gunzip checks the gzip trailer's CRC-32 and length, which a truncated or
// corrupted download fails.
func gunzip(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	out, err := io.ReadAll(io.LimitReader(r, maxDecompressed+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxDecompressed {
		return nil, fmt.Errorf("decompresses to more than %d bytes", maxDecompressed)
	}
	return out, r.Close()
}

// currentEpoch reads the build epoch of an existing database of this type.
func currentEpoch(path string) (uint64, bool) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return 0, false
	}
	defer db.Close()
	return uint64(db.Metadata.BuildEpoch), db.Metadata.DatabaseType == DatabaseType
}

// install writes a staging file in the output's directory, syncs it, verifies
// it and renames it over the output, then syncs the directory. A failed
// build leaves the output untouched and removes the staging file.
func install(output string, write func(io.Writer) error, verify func(string) error) (err error) {
	dir := filepath.Dir(output)
	staging, err := os.CreateTemp(dir, "."+filepath.Base(output)+".*.staging")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = staging.Close()
			_ = os.Remove(staging.Name())
		}
	}()
	if err = staging.Chmod(0o644); err != nil {
		return err
	}
	if err = write(staging); err != nil {
		return err
	}
	if err = staging.Sync(); err != nil {
		return err
	}
	if err = staging.Close(); err != nil {
		return err
	}
	if err = verify(staging.Name()); err != nil {
		return fmt.Errorf("the written database failed verification: %w", err)
	}
	if err = os.Rename(staging.Name(), output); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
