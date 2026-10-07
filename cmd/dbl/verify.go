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
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/client"
)

const verifyUsage = `Usage:
  dbl verify CAPTURE|EVIDENCE.json [--at TIME] [--offline] [--output text|json]
             [--evidence FILE] [--source ADDRESS[/BITS],...]

Checks which Debuglet run, if any, sent the packets of a pcap or pcapng
capture. Packets are grouped by source address and epoch; each group is
verified, invalid, pending, missing or unsupported; a group whose packets
reproduce different runs (two measurements toward one recipient at once) is
split into an entry per run. No account is needed:
the runs and disclosed keys come from the dispatcher's public attribution
history, and the tags are checked here (offline). A group whose key is not
disclosed yet is sent to the dispatcher (the first 64 bytes of each packet),
whose executor confirms or rejects the tags before disclosure (server); the
dispatcher signs a receipt of the answer, which is checked here and kept in
the evidence bundle. Each group line names the method, and a server verdict
the receipt key ID.

An offline verdict shows that a run sent the packets only if they were
captured before its key was disclosed, which rests on the capture's own
timestamps. A server verdict rests on the dispatcher's receipt: it shows what
was asked and answered when, not when the packets were captured. Neither says
anything about whether the measurement was consented to or whether its
conclusions are sound.

Options:
  --at TIME         take TIME (RFC 3339) as the capture time of every packet
  --offline         never upload packets: groups whose key is not disclosed
                    yet stay pending
  --output FORMAT   text (default) or json
  --evidence FILE   write an evidence bundle that repeats the check without
                    the capture or the dispatcher
  --source LIST     check only packets from these addresses or prefixes
                    (comma-separated, repeatable); other packets are skipped
                    before any lookup. Use it on captures with unrelated
                    traffic: each other address costs a history lookup per
                    second of traffic, and one check makes at most 1024

Passing an evidence bundle instead of a capture checks it again, offline,
including the signature of every receipt under the key the bundle embeds;
compare the key IDs with GET /attribution/receipt-keys of the dispatcher.

Exit status: 0 every group verified; 1 usage, read or network error
(including usage errors in the global options: 2 is never a usage error
here); 2 some group invalid; 3 none invalid, but some pending, missing or
unsupported; 124 the command timed out; 130 interrupted.
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
	var sources []netip.Prefix
	fs := newCommandFlagSet("verify")
	fs.Func("source", "", func(value string) error {
		for _, item := range strings.Split(value, ",") {
			p, err := parseSourcePrefix(strings.TrimSpace(item))
			if err != nil {
				return err
			}
			sources = append(sources, p)
		}
		return nil
	})
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
	skipped := 0
	if client.IsEvidence(data[:min(len(data), 64)]) {
		if at != "" || evidencePath != "" || len(sources) > 0 {
			return usage("--at, --evidence and --source apply to a capture, not to an evidence bundle")
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
		if len(sources) > 0 {
			if pkts, skipped = filterSources(pkts, sources); len(pkts) == 0 {
				return fail("%s holds no packets from --source %s (%s skipped)", positional[0], prefixList(sources), plural(skipped, "packet"))
			}
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
				fmt.Fprintf(stderr, "%s: stopped before every group was checked; filter the capture with --source to check fewer addresses\n", name)
				return reportFailure(ctx, name, stderr, err)
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
	} else if err := writeVerifyText(stdout, rep, bundle, evidencePath, skipped, sources); err != nil {
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

// parseSourcePrefix parses an address or a prefix of --source.
func parseSourcePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid --source %q: want an IP address or prefix", s)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid --source %q: want an IP address or prefix", s)
	}
	a = a.WithZone("").Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// filterSources keeps the packets whose IP source address is in one of the
// prefixes, and counts the others.
func filterSources(pkts []client.CapturedPacket, sources []netip.Prefix) ([]client.CapturedPacket, int) {
	kept := make([]client.CapturedPacket, 0, len(pkts))
	for _, p := range pkts {
		addr, ok := packetSource(p.Data)
		if ok && slices.ContainsFunc(sources, func(s netip.Prefix) bool { return s.Contains(addr) }) {
			kept = append(kept, p)
		}
	}
	return kept, len(pkts) - len(kept)
}

// packetSource is the source address of an IPv4 or IPv6 packet.
func packetSource(data []byte) (netip.Addr, bool) {
	switch {
	case len(data) >= 20 && data[0]>>4 == 4:
		return netip.AddrFrom4([4]byte(data[12:16])), true
	case len(data) >= 40 && data[0]>>4 == 6:
		return netip.AddrFrom16([16]byte(data[8:24])).Unmap(), true
	}
	return netip.Addr{}, false
}

func prefixList(sources []netip.Prefix) string {
	parts := make([]string, len(sources))
	for i, s := range sources {
		if s.IsSingleIP() {
			parts[i] = s.Addr().String()
		} else {
			parts[i] = s.String()
		}
	}
	return strings.Join(parts, ",")
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
	if g.Split != nil {
		// A split group: say how much of the address and epoch it is.
		packets = fmt.Sprintf("%d of %s", len(g.Packets), plural(g.Split.Packets, "packet"))
	}
	source := g.Source
	if source == "" {
		source = "(no IP)"
	}
	switch g.Verdict {
	case client.VerdictVerified:
		line := fmt.Sprintf("verified     run %s  executor %s  %s  %s  %s  via %s",
			shortRun(g.RunID), g.ExecutorID, source, minuteUTC(g.Time), packets, g.Method)
		if g.ReceiptKeyID != "" {
			line += "  receipt key " + g.ReceiptKeyID
		}
		return line
	case client.VerdictPending:
		until := "later"
		if g.PendingUntil != nil {
			until = minuteUTC(g.PendingUntil.Add(time.Minute - time.Nanosecond))
		}
		return fmt.Sprintf("pending      %s  %s  %s  until %s", source, minuteUTC(g.Time), packets, until)
	case client.VerdictMissing:
		return fmt.Sprintf("missing      %s  %s  %s  no history retained for that time", source, minuteUTC(g.Time), packets)
	case client.VerdictUnsupported:
		line := fmt.Sprintf("unsupported  %s  %s  %s", source, packets, reasonPhrase(g.Reason))
		if g.Method == client.VerifyMethodServer {
			line += "  via server"
		}
		return line
	}
	line := fmt.Sprintf("%-12s %s  %s  %s  %s", g.Verdict, source, minuteUTC(g.Time), packets, g.Reason)
	if g.Method == client.VerifyMethodServer {
		line += "  via server"
	}
	return line
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
	case client.ReasonUnmatched:
		return "unmatched: no run's tag, unlike the rest of their group"
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
		return "invalid (no_run): no Debuglet run was active from these addresses at that time, so Debuglet did not send those packets. Filter the capture to the probe traffic you want to check with --source ADDRESS."
	case client.ReasonUnmatched:
		return "unsupported (unmatched): some packets carry no valid tag of any run active from their address, while others of the same address and epoch do. They are attributed to no run: they were changed on the way (NAT, segmentation offload; capture with GRO/LRO off) or sent by other software from that address."
	case client.ReasonNotDisclosed:
		return "" // summarized with the retry time
	case client.ReasonNotRetained, client.ReasonKeysMissing:
		return "missing: the dispatcher no longer holds (or never received) the history for that time. This is no evidence either way."
	case client.ReasonTooShort:
		return "unsupported (truncated packet): capture with a snap length of at least 64 bytes past the IP header, for example tcpdump -s 128."
	case client.ReasonAmbiguous:
		return "unsupported (ambiguous): several runs reproduce every tag; capture more packets of the flow."
	case client.ReasonWorkCap:
		return "unsupported (work cap): the capture needs more work than one verification allows (at most 1024 history lookups: one per address and epoch, one per second for an address without a run). Filter it to the probe traffic with --source ADDRESS, or split it."
	}
	if g.Verdict == client.VerdictUnsupported {
		return fmt.Sprintf("unsupported (%s): %s.", g.Reason, strings.TrimSuffix(g.Detail, "."))
	}
	return ""
}

func writeVerifyText(w io.Writer, rep client.VerifyReport, bundle *client.Evidence, evidencePath string, skipped int, sources []netip.Prefix) error {
	var b strings.Builder
	if bundle != nil {
		fmt.Fprintf(&b, "Evidence bundle created %s by %s %s: the packet digest matches, every key hashes to its chain anchor, and the recorded verdicts recompute.\n",
			bundle.CreatedAt.UTC().Format(time.RFC3339), orUnknown(bundle.Tool.Name), orUnknown(bundle.Tool.Version))
		if len(bundle.Receipts) > 0 {
			var ids []string
			for _, r := range bundle.Receipts {
				if !slices.Contains(ids, r.KeyID) {
					ids = append(ids, r.KeyID)
				}
			}
			fmt.Fprintf(&b, "%s checked: signed by receipt key %s, which the bundle embeds; compare it with GET /attribution/receipt-keys of the dispatcher.\n",
				plural(len(bundle.Receipts), "receipt"), strings.Join(ids, ", "))
		}
		b.WriteByte('\n')
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
	for _, g := range rep.Groups {
		if g.Method == client.VerifyMethodServer {
			source += ", with the executor's answers before disclosure"
			break
		}
	}
	fmt.Fprintf(&b, "\n%s: %s (%s, tag spec %s, checked %s).\n",
		plural(len(rep.Groups), "group"), strings.Join(parts, ", "), plural(rep.Packets, "packet"), rep.TagSpec, source)
	if skipped > 0 {
		fmt.Fprintf(&b, "Skipped %s not from --source %s.\n", plural(skipped, "packet"), prefixList(sources))
	}
	if rep.At != nil {
		fmt.Fprintf(&b, "Every packet was taken as captured at %s (--at).\n", rep.At.UTC().Format(time.RFC3339))
	}

	runs := map[string]string{}
	var order []string
	var latestDisclosure time.Time
	server := map[string]string{}
	var serverOrder []string
	for _, g := range rep.Groups {
		if g.Verdict != client.VerdictVerified {
			continue
		}
		if g.Method == client.VerifyMethodServer {
			if _, ok := server[g.RunID]; !ok {
				serverOrder = append(serverOrder, g.RunID)
			}
			server[g.RunID] = g.ExecutorID + " (receipt key " + g.ReceiptKeyID + ")"
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
	for _, run := range serverOrder {
		fmt.Fprintf(&b, "- verified (server): the executor confirmed before disclosure that the packets carry valid tags of run %s on executor %s.\n", run, server[run])
	}
	if len(serverOrder) > 0 {
		b.WriteString("  A server verdict rests on the dispatcher's signed receipt: it shows what was asked and answered when, not when the packets were captured. Check the receipt key against GET /attribution/receipt-keys.\n")
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
