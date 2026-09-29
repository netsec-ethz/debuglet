// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/client"
)

const verifyUsage = `Usage:
  dbl verify CAPTURE|EVIDENCE.json [--at TIME] [--offline] [--output text|json]
             [--evidence FILE]

Checks which Debuglet run, if any, sent the packets of a pcap or pcapng
capture. Packets are grouped by source address and epoch; each group is
verified, invalid, pending, missing or unsupported. No account is needed:
the runs and disclosed keys come from the dispatcher's public attribution
history, and the tags are checked here (offline). Packets are never uploaded.

An offline verdict shows that a run sent the packets only if they were
captured before its key was disclosed, which rests on the capture's own
timestamps. It says nothing about whether the measurement was consented to or
whether its conclusions are sound.

Options:
  --at TIME         take TIME (RFC 3339) as the capture time of every packet
  --offline         never upload packets (server-assisted checks are not
                    available yet, so every check is offline today)
  --output FORMAT   text (default) or json
  --evidence FILE   write an evidence bundle that repeats the check without
                    the capture or the dispatcher

Passing an evidence bundle instead of a capture checks it again, offline.

Exit status: 0 every group verified; 1 usage, read or network error;
2 some group invalid; 3 none invalid, but some pending, missing or
unsupported.
`

// Exit codes of dbl verify (docs/verification.md#command).
const (
	verifyExitVerified     = 0
	verifyExitError        = 1
	verifyExitInvalid      = 2
	verifyExitInconclusive = 3
)

// verifyCommandTimeout bounds dbl verify: lookups are rate limited.
const verifyCommandTimeout = 5 * time.Minute

func verifyCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer) int {
	const name = "dbl verify"
	var at, output, evidencePath string
	var offline bool
	fs := newCommandFlagSet("verify")
	fs.StringVar(&at, "at", "", "")
	fs.BoolVar(&offline, "offline", false, "")
	fs.StringVar(&output, "output", "", "")
	fs.StringVar(&evidencePath, "evidence", "", "")
	positional, err := parseInterspersed(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stdout, verifyUsage)
		return verifyExitVerified
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "%s: %s\n", name, fmt.Sprintf(format, a...))
		return verifyExitError
	}
	usage := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "%s: %s\n", name, fmt.Sprintf(format, a...))
		fmt.Fprint(stderr, verifyUsage)
		return verifyExitError
	}
	if err != nil {
		return usage("%v", err)
	}
	switch output {
	case "":
		output = "text"
		if options.Output == outputJSON {
			output = "json"
		}
	case "text", "human":
		output = "text"
	case "json":
	default:
		return usage("invalid --output %q: want text or json", output)
	}
	if len(positional) != 1 {
		return usage("want one capture or evidence file, got %d arguments", len(positional))
	}
	var opts client.VerifyOptions
	opts.Offline = offline
	if at != "" {
		t, err := time.Parse(time.RFC3339Nano, at)
		if err != nil {
			return usage("invalid --at %q: want an RFC 3339 time such as 2026-09-29T10:14:00Z", at)
		}
		opts.At = t
	}

	data, err := readVerifyInput(positional[0])
	if err != nil {
		return fail("%v", err)
	}
	var rep client.VerifyReport
	var bundle *client.Evidence
	if client.IsEvidence(data[:min(len(data), 64)]) {
		if at != "" || evidencePath != "" {
			return usage("--at and --evidence apply to a capture, not to an evidence bundle")
		}
		ev, err := client.ReadEvidence(bytes.NewReader(data))
		if err != nil {
			return fail("%v", err)
		}
		bundle = &ev
		rep, err = client.VerifyEvidence(ctx, ev)
		if err != nil {
			return fail("%v", err)
		}
	} else {
		pkts, err := client.ReadCapture(bytes.NewReader(data))
		if err != nil {
			return fail("%v", err)
		}
		if len(pkts) == 0 {
			return fail("%s holds no IP packets", positional[0])
		}
		// The attribution routes are public: no credential is read or sent.
		c, _, _, ok := connectProfileWithoutCredential(name, options, stderr)
		if !ok {
			return verifyExitError
		}
		rep, err = c.Verify(ctx, pkts, opts)
		if err != nil {
			if errors.Is(err, client.ErrNoAttributionHistory) {
				fmt.Fprintf(stderr, "%s: %v\n%s: this dispatcher predates API 1.11; ask its operator to upgrade, or use tools/verify_pcap.py against its older routes\n", name, err, name)
				return verifyExitError
			}
			if ctx.Err() != nil {
				return fail("stopped before every group was checked: %v", err)
			}
			return fail("%v", err)
		}
		if evidencePath != "" {
			ev := rep.Evidence()
			ev.Tool = client.EvidenceTool{Name: "dbl", Version: orUnknown(localVersion().Version)}
			if err := writeEvidenceFile(evidencePath, ev); err != nil {
				return fail("write evidence: %v", err)
			}
		}
	}

	if output == "json" {
		if err := writeJSON(stdout, rep); err != nil {
			return fail("%v", err)
		}
	} else if err := writeVerifyText(stdout, rep, bundle, evidencePath); err != nil {
		return fail("%v", err)
	}
	switch {
	case rep.Counts.Invalid > 0:
		return verifyExitInvalid
	case rep.Counts.Pending+rep.Counts.Missing+rep.Counts.Unsupported > 0:
		return verifyExitInconclusive
	}
	return verifyExitVerified
}

// parseInterspersed parses flags given before or after the positional
// arguments, as the command synopsis writes them.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return positional, nil
		}
		if args[0] == "--" {
			return append(positional, args[1:]...), nil
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

// readVerifyInput reads a capture or bundle of at most the bundle limit.
func readVerifyInput(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, client.MaxEvidenceBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > client.MaxEvidenceBytes {
		return nil, fmt.Errorf("%s exceeds %d MiB", path, client.MaxEvidenceBytes>>20)
	}
	return data, nil
}

func writeEvidenceFile(path string, ev client.Evidence) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if err := client.WriteEvidence(f, ev); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// shortRun abbreviates a run ID for the one-line view; the summary names it
// in full.
func shortRun(id string) string {
	if len(id) > 8 {
		return id[:8] + "…"
	}
	return id
}

func minuteUTC(t time.Time) string { return t.UTC().Format("2006-01-02T15:04Z") }

func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// groupLine is the one-line view of a group (docs/verification.md#command).
func groupLine(g client.VerifyGroup) string {
	packets := plural(len(g.Packets), "packet")
	source := g.Source
	if source == "" {
		source = "(no IP)"
	}
	switch g.Verdict {
	case client.VerdictVerified:
		return fmt.Sprintf("verified     run %s  executor %s  %s  %s  %s  via %s",
			shortRun(g.RunID), g.ExecutorID, source, minuteUTC(g.Time), packets, g.Method)
	case client.VerdictPending:
		until := "later"
		if g.PendingUntil != nil {
			until = minuteUTC(g.PendingUntil.Add(time.Minute - time.Nanosecond))
		}
		return fmt.Sprintf("pending      %s  %s  %s  until %s", source, minuteUTC(g.Time), packets, until)
	case client.VerdictMissing:
		return fmt.Sprintf("missing      %s  %s  %s  no history retained for that time", source, minuteUTC(g.Time), packets)
	case client.VerdictUnsupported:
		return fmt.Sprintf("unsupported  %s  %s  %s", source, packets, reasonPhrase(g.Reason))
	}
	return fmt.Sprintf("%-12s %s  %s  %s  %s", g.Verdict, source, minuteUTC(g.Time), packets, g.Reason)
}

// reasonPhrase is the short text of an unsupported reason.
func reasonPhrase(reason string) string {
	switch reason {
	case client.ReasonIPv6:
		return "IPv6 is not tagged"
	case client.ReasonNotIPv4:
		return "not an IP packet"
	case client.ReasonTooShort:
		return "truncated packet (snap length below 64 bytes)"
	case client.ReasonMalformed:
		return "malformed IPv4 header"
	case client.ReasonFragment:
		return "IPv4 fragment (never tagged)"
	case client.ReasonLinkType:
		return "unknown link type"
	case client.ReasonTagSpec:
		return "unknown tag spec"
	case client.ReasonDisclosureDelay:
		return "executor disclosure delay below 2 epochs"
	case client.ReasonSchedule:
		return "unusable key schedule"
	case client.ReasonBadKey:
		return "served key does not match the chain"
	case client.ReasonNoSigningKey:
		return "no signing key at that time"
	case client.ReasonKeyPublic:
		return "key may already have been public at capture time"
	case client.ReasonAmbiguous:
		return "ambiguous: several runs match"
	case client.ReasonTooManyCandidates:
		return "too many candidates"
	case client.ReasonWorkCap:
		return "over a work cap"
	}
	return reason
}

// nextStep is what to do about groups with a reason, once per reason.
func nextStep(g client.VerifyGroup) string {
	switch g.Reason {
	case "":
		return ""
	case client.ReasonTagMismatch:
		return "invalid (tag_mismatch): some packets carry no valid tag of any run active from their address. They were not sent by Debuglet, or were changed on the way (NAT, segmentation offload); capture with GRO/LRO off."
	case client.ReasonNoRun:
		return "invalid (no_run): no Debuglet run was active from these addresses at that time, so Debuglet did not send those packets. Filter the capture to the probe traffic you want to check (for example tcpdump src host ADDRESS)."
	case client.ReasonMixedRuns:
		return "invalid (mixed_runs): packets of one address and epoch carry tags of different runs; verify each destination's traffic separately."
	case client.ReasonNotDisclosed:
		return "" // summarized with the retry time
	case client.ReasonNotRetained, client.ReasonKeysMissing:
		return "missing: the dispatcher no longer holds (or never received) the history for that time. This is no evidence either way."
	case client.ReasonTooShort:
		return "unsupported (truncated packet): capture with a snap length of at least 64 bytes past the IP header, for example tcpdump -s 128."
	case client.ReasonAmbiguous:
		return "unsupported (ambiguous): several runs reproduce every tag; capture more packets of the flow."
	case client.ReasonWorkCap:
		return "unsupported (work cap): the capture needs more work than one verification allows; split it or filter it to the probe traffic."
	}
	if g.Verdict == client.VerdictUnsupported {
		return fmt.Sprintf("unsupported (%s): %s.", g.Reason, strings.TrimSuffix(g.Detail, "."))
	}
	return ""
}

func writeVerifyText(w io.Writer, rep client.VerifyReport, bundle *client.Evidence, evidencePath string) error {
	var b strings.Builder
	if bundle != nil {
		fmt.Fprintf(&b, "Evidence bundle created %s by %s %s: the packet digest matches, every key hashes to its chain anchor, and the recorded verdicts recompute.\n\n",
			bundle.CreatedAt.UTC().Format(time.RFC3339), orUnknown(bundle.Tool.Name), orUnknown(bundle.Tool.Version))
	}
	for _, g := range rep.Groups {
		b.WriteString(groupLine(g))
		b.WriteByte('\n')
	}
	c := rep.Counts
	var parts []string
	for _, p := range []struct {
		n    int
		name string
	}{{c.Verified, "verified"}, {c.Invalid, "invalid"}, {c.Pending, "pending"}, {c.Missing, "missing"}, {c.Unsupported, "unsupported"}} {
		if p.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", p.n, p.name))
		}
	}
	source := "offline"
	if rep.Dispatcher != "" {
		source = "offline against the history of " + rep.Dispatcher
	}
	fmt.Fprintf(&b, "\n%s: %s (%s, tag spec %s, checked %s).\n",
		plural(len(rep.Groups), "group"), strings.Join(parts, ", "), plural(rep.Packets, "packet"), rep.TagSpec, source)
	if rep.At != nil {
		fmt.Fprintf(&b, "Every packet was taken as captured at %s (--at).\n", rep.At.UTC().Format(time.RFC3339))
	}

	runs := map[string]string{}
	var order []string
	var latestDisclosure time.Time
	for _, g := range rep.Groups {
		if g.Verdict != client.VerdictVerified {
			continue
		}
		if _, ok := runs[g.RunID]; !ok {
			order = append(order, g.RunID)
		}
		runs[g.RunID] = g.ExecutorID
		if g.DisclosedAt != nil && g.DisclosedAt.After(latestDisclosure) {
			latestDisclosure = *g.DisclosedAt
		}
	}
	for _, run := range order {
		fmt.Fprintf(&b, "- verified (offline): packets carry valid tags of run %s on executor %s.\n", run, runs[run])
	}
	if len(order) > 0 {
		fmt.Fprintf(&b, "  Offline verification proves this only if the packets were captured before their keys were disclosed (the latest at %s). It relies on this capture's timestamps, and says nothing about whether the measurement was consented to or is sound.\n",
			latestDisclosure.UTC().Format(time.RFC3339))
	}
	seen := map[string]bool{}
	var retry time.Time
	for _, g := range rep.Groups {
		if g.PendingUntil != nil && g.PendingUntil.After(retry) {
			retry = *g.PendingUntil
		}
		step := nextStep(g)
		if step == "" || seen[step] {
			continue
		}
		seen[step] = true
		fmt.Fprintf(&b, "- %s\n", step)
	}
	if !retry.IsZero() {
		// Round up: a key is disclosed on the executor's first heartbeat
		// after its scheduled time.
		r := retry.UTC().Add(time.Minute - time.Nanosecond).Truncate(time.Minute)
		fmt.Fprintf(&b, "- pending: the keys of %s are not disclosed yet. Retry after %s UTC (%s), or keep an evidence bundle now with --evidence.\n",
			plural(c.Pending, "group"), r.Format("15:04"), r.Format("2006-01-02"))
	}
	if evidencePath != "" {
		fmt.Fprintf(&b, "Evidence written to %s; check it again with: dbl verify %s\n", evidencePath, evidencePath)
	}
	_, err := io.WriteString(w, b.String())
	return err
}
