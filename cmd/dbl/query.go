package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/netsec-ethz/debuglet/internal/buildinfo"
	"github.com/netsec-ethz/debuglet/pkg/client"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

const (
	nodesUsage = `Usage:
  dbl nodes [--protocol NAME ...] [--enforcement ebpf|fallback] [--min-capacity-bps N]
            [--isd-as ISD-AS] [--asn NUMBER] [--country CODE]
            [--address-family ipv4|ipv6] [--reachable-listener tcp|udp|scion]
  dbl nodes --status connected,disconnected,abandoned,never_connected

Filters return ready matching executors only. Unknown capability reports and an
unknown ISD-AS do not match. Capacity means advertised total bandwidth, not free
admission capacity. NAME is the dispatcher operator's label; LOCATION prefers
operator location and otherwise shows approximate database location with its source;
ISD_AS is the executor's own report. ADDRESS_V4 and ADDRESS_V6 are the addresses
the dispatcher last observed, "private" when the executor withholds them. --output
json also carries admission, the operator's network label, the reported listener
transports and each address family's prefix, ASN and observation time.

--status (API 1.17) lists executors by status instead: connected, disconnected,
abandoned (disconnected for more than 30 days) or never_connected (enrolled,
never registered); comma-separated or repeated. It cannot be combined with the
filters, which select ready executors. STATUS and TAGS show each executor's
status and its host and system tags.

Lists the dispatcher's registered executors. JSON output is always an array.
`
	statusUsage = `Usage:
  dbl status ID

Reports the debuglet's state. The command completes (exit 0) whenever the
dispatcher answered, including for a debuglet that failed.
`
	cancelUsage = `Usage:
  dbl cancel [--status] ID

--status inspects the durable request without sending another cancellation (API
1.9 or newer). Older dispatchers support cancel without this optional flag.

Looks up the debuglet's executor, then asks the dispatcher to abort it. A
success is an acknowledgement only, not proof that execution stopped. A
server or transport failure leaves the cancellation unconfirmed; check
dbl cancel --status ID (or dbl status ID on older dispatchers).
`
	versionUsage = `Usage:
  dbl version [--server]

Options:
  --server    also query the dispatcher's version (the default makes no request)
`
)

func nodesCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer) int {
	fs := newCommandFlagSet("nodes")
	var filter client.ExecutorFilter
	capabilityFlags(fs, &filter)
	var statuses []string
	fs.Func("status", "executor status: connected, disconnected, abandoned or never_connected; comma-separated or repeatable", func(value string) error {
		for _, status := range strings.Split(value, ",") {
			if !slices.Contains(wire.ProbeStatuses, status) {
				return fmt.Errorf("unknown status %q", status)
			}
			statuses = append(statuses, status)
		}
		return nil
	})
	if code, ok := parseCommandFlags(fs, args, nodesUsage, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() > 0 {
		return usageError("dbl nodes", nodesUsage, stderr, "unexpected arguments %q", fs.Args())
	}
	if err := filter.Validate(); err != nil {
		return usageError("dbl nodes", nodesUsage, stderr, "%v", err)
	}
	if len(statuses) > 0 && !filter.Empty() {
		return usageError("dbl nodes", nodesUsage, stderr, "--status cannot be combined with filters, which select ready executors")
	}
	c, code, ok := connect(ctx, "dbl nodes", options, false, stderr)
	if !ok {
		return code
	}
	var nodes []client.Node
	var err error
	if len(statuses) > 0 {
		nodes, err = c.Probes(ctx, statuses...)
	} else if filter.Empty() {
		nodes, err = c.Nodes(ctx)
	} else {
		nodes, err = c.DiscoverExecutors(ctx, filter)
	}
	if err != nil {
		return reportFailure(ctx, "dbl nodes", stderr, err)
	}
	if nodes == nil {
		nodes = []client.Node{}
	}
	return emit("dbl nodes", options.Output, stdout, stderr, nodes, func(w io.Writer) error {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tREADY\tNAME\tLOCATION\tISD_AS\tASN\tADDRESS_V4\tADDRESS_V6\tLOCATION_SOURCE\tLAST_SEEN\tVERSION\tPRICE_PER_BW\tCURRENCY\tPROTOCOLS\tENFORCEMENT\tCAPACITY_BPS\tATTRIBUTION\tIPV4\tIPV6\tTCP_LISTENER\tUDP_LISTENER\tSTATUS\tTAGS")
		for _, n := range nodes {
			location := n.Display
			location.City, location.Country = n.Location()
			lastSeen := "-"
			if n.LastSeen > 0 {
				lastSeen = time.Unix(n.LastSeen, 0).UTC().Format(time.RFC3339)
			}
			protocols, enforcement, capacity, attribution := "unknown", "unknown", "unknown", "unknown"
			if report := n.Capabilities; report != nil && report.SchemaVersion == 1 {
				protocols = strings.Join(report.Protocols, ",")
				if report.EnforcementMode != "" {
					enforcement = report.EnforcementMode
				}
				if report.AdvertisedCapacityBPS != nil {
					capacity = strconv.FormatInt(*report.AdvertisedCapacityBPS, 10)
				}
				attribution = attributionColumn(report.Attribution)
			}
			connectivity := n.Connectivity
			if connectivity == nil {
				connectivity = &wire.Connectivity{}
			}
			fmt.Fprintf(tw, "%s\t%t\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", n.ID, n.Ready,
				labelText(n.Display.DisplayName), nodeLocation(location), observedText(n.SCIONISDAS), nodeASN(n.IPMetadata),
				addressColumn(n.AddressV4, n.IsPublic), addressColumn(n.AddressV6, n.IsPublic), locationSource(location),
				lastSeen, n.Version, n.PricePerBw, n.Currency, protocols, enforcement, capacity, attribution, reachabilityColumn(connectivity.IPv4), reachabilityColumn(connectivity.IPv6), reachabilityColumn(connectivity.TCPListener), reachabilityColumn(connectivity.UDPListener),
				statusColumn(n.Status), tagsColumn(n.Tags))
		}
		return tw.Flush()
	})
}

// addressColumn shows an observed address, "private" when a private executor's
// address is withheld and "-" when none is known. A value that is not an
// address is not printed.
func addressColumn(address *string, public *bool) string {
	if address == nil {
		if public != nil && !*public {
			return "private"
		}
		return "-"
	}
	ip, err := netip.ParseAddr(*address)
	if err != nil {
		return "invalid"
	}
	return ip.String()
}

// statusColumn shows a documented status; an older dispatcher reports none.
func statusColumn(status *wire.ProbeStatusName) string {
	if status == nil {
		return "unknown"
	}
	if !slices.Contains(wire.ProbeStatuses, status.Name) {
		return "invalid"
	}
	return status.Name
}

// tagsColumn joins the tags, leaving out any that is not a plain tag name so
// that a server cannot write control characters to the terminal.
func tagsColumn(tags []string) string {
	shown := []string{}
	for _, tag := range tags {
		if tag != "" && strings.Trim(tag, "abcdefghijklmnopqrstuvwxyz0123456789-") == "" {
			shown = append(shown, tag)
		}
	}
	if len(shown) == 0 {
		return "-"
	}
	return strings.Join(shown, ",")
}

func reachabilityColumn(r wire.Reachability) string {
	if r.Stale || r.ExpiresAt != nil && time.Now().Unix() >= *r.ExpiresAt {
		return "stale"
	}
	if r.State == "" {
		return "unknown"
	}
	return r.State
}

// Operator labels are optional: "-" is not configured, not unknown.
func labelText(label wire.LabelledString) string {
	if label.Value == nil || *label.Value == "" {
		return "-"
	}
	return *label.Value
}

func nodeLocation(display wire.ExecutorDisplay) string {
	parts := []string{}
	for _, label := range []wire.LabelledString{display.City, display.Country} {
		if text := labelText(label); text != "-" {
			parts = append(parts, text)
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ",")
}

func observedText(value wire.ObservedString) string {
	if value.Value == nil {
		return "unknown"
	}
	return *value.Value
}

// attributionColumn renders available, unavailable(reason) or unknown. Only the
// documented vocabulary is printed; the JSON output carries the refresh details.
func attributionColumn(a *wire.AttributionState) string {
	switch {
	case a == nil:
		return "unknown"
	case a.State == "available" && a.Reason == "":
		return "available"
	case a.State != "unavailable":
		return "unknown"
	}
	switch a.Reason {
	case "epoch_zero", "chain_exhausted", "refresh_failing", "disclosure_held", "clock_unready", "clock_drift":
		return "unavailable(" + a.Reason + ")"
	}
	return "unavailable"
}

// statusDocument is `status`'s JSON: the State plus the queried ID.
type statusDocument struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	Error      string `json:"error"`
	ExecutorID string `json:"executor_id"`
}

func statusCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer) int {
	fs := newCommandFlagSet("status")
	if code, ok := parseCommandFlags(fs, args, statusUsage, stdout, stderr); !ok {
		return code
	}
	id, msg := singleID(fs)
	if msg != "" {
		return usageError("dbl status", statusUsage, stderr, "%s", msg)
	}
	c, code, ok := connect(ctx, "dbl status", options, false, stderr)
	if !ok {
		return code
	}
	st, err := c.Status(ctx, id)
	if err != nil {
		return reportFailure(ctx, "dbl status", stderr, err)
	}
	doc := statusDocument{ID: id, State: st.State, Error: st.Error, ExecutorID: st.ExecutorID}
	return emit("dbl status", options.Output, stdout, stderr, doc, func(w io.Writer) error {
		_, err := fmt.Fprintf(w, "id: %s\nstate: %s\nexecutor_id: %s\n", doc.ID, doc.State, doc.ExecutorID)
		if err == nil && doc.Error != "" {
			_, err = fmt.Fprintf(w, "error: %s\n", doc.Error)
		}
		return err
	})
}

// cancelAcknowledgement is `cancel`'s JSON on success.
type cancelAcknowledgement struct {
	ID           string `json:"id"`
	Acknowledged bool   `json:"acknowledged"`
}

func cancelCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer) int {
	fs := newCommandFlagSet("cancel")
	inspect := fs.Bool("status", false, "inspect the recorded cancellation without retrying")
	if code, ok := parseCommandFlags(fs, args, cancelUsage, stdout, stderr); !ok {
		return code
	}
	id, msg := singleID(fs)
	if msg != "" {
		return usageError("dbl cancel", cancelUsage, stderr, "%s", msg)
	}
	c, code, ok := connect(ctx, "dbl cancel", options, false, stderr)
	if !ok {
		return code
	}
	if *inspect {
		doc, err := c.Cancellation(ctx, id)
		if err != nil {
			return reportFailure(ctx, "dbl cancel: inspection", stderr, err)
		}
		return emit("dbl cancel", options.Output, stdout, stderr, doc, func(w io.Writer) error {
			_, err := fmt.Fprintf(w, "request_id: %s\ndisposition: %s\nreason: %s\nstate: %s\n", doc.RequestID, doc.Disposition, doc.Reason, doc.State)
			return err
		})
	}
	st, err := c.Status(ctx, id)
	if err != nil {
		return reportFailure(ctx, "dbl cancel: status lookup", stderr, err)
	}
	if err := c.Cancel(ctx, id, st.ExecutorID); err != nil {
		fmt.Fprintf(stderr, "Inspect the recorded request with dbl cancel --status %s (API 1.9 or newer).\n", id)
		return reportFailure(ctx, cancelFailureName(err), stderr, err)
	}
	return emit("dbl cancel", options.Output, stdout, stderr, cancelAcknowledgement{ID: id, Acknowledged: true},
		func(w io.Writer) error { _, err := fmt.Fprintln(w, "Cancellation acknowledged"); return err })
}

// cancelFailureName names a failed cancellation: a server failure (5xx) or a
// transport failure, including the command's deadline, leaves open whether the
// dispatcher received it, whether the executor acknowledged it and whether its
// result was recorded, so it is unconfirmed; a refusal by the server and any
// other failure is a rejection.
func cancelFailureName(err error) string {
	var httpErr *client.HTTPError
	if client.IsTransportError(err) || errors.As(err, &httpErr) && httpErr.StatusCode >= http.StatusInternalServerError {
		return "dbl cancel: cancellation not confirmed"
	}
	return "dbl cancel: cancellation rejected"
}

// versionInfo is `version`'s JSON. Unavailable strings are empty; Server is
// present only with --server. Future versions may add keys without removing them.
type versionInfo struct {
	Module   string                `json:"module"`
	Version  string                `json:"version"`
	Revision string                `json:"revision"`
	Modified bool                  `json:"modified"`
	Server   *client.ServerVersion `json:"server,omitempty"`
}

// localVersion reads the binary's own build metadata.
func localVersion() versionInfo {
	var v versionInfo
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return v
	}
	v.Module = info.Main.Path
	v.Version = info.Main.Version
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			v.Revision = s.Value
		case "vcs.modified":
			v.Modified = s.Value == "true"
		}
	}
	if buildinfo.Version != "" {
		v.Version = buildinfo.Version
	}
	if buildinfo.Revision != "" {
		v.Revision = buildinfo.Revision
	}
	return v
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func versionCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer) int {
	var server bool
	fs := newCommandFlagSet("version")
	fs.BoolVar(&server, "server", false, "")
	if code, ok := parseCommandFlags(fs, args, versionUsage, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() > 0 {
		return usageError("dbl version", versionUsage, stderr, "unexpected arguments %q", fs.Args())
	}
	v := localVersion()
	if server {
		c, code, ok := connect(ctx, "dbl version", options, false, stderr)
		if !ok {
			return code
		}
		sv, err := c.Version(ctx)
		if err != nil {
			return reportFailure(ctx, "dbl version", stderr, err)
		}
		v.Server = &sv
	}
	return emit("dbl version", options.Output, stdout, stderr, v, func(w io.Writer) error {
		_, err := fmt.Fprintf(w, "module: %s\nversion: %s\nrevision: %s\nmodified: %t\n",
			orUnknown(v.Module), orUnknown(v.Version), orUnknown(v.Revision), v.Modified)
		if err == nil && v.Server != nil {
			_, err = fmt.Fprintf(w, "server: %s\n", orUnknown(v.Server.Version))
		}
		return err
	})
}

func nodeASN(m *wire.IPMetadata) string {
	if m == nil {
		return "unknown"
	}
	values := []string{}
	for _, r := range []wire.IPLookup[wire.ASInfo]{m.Observed.ASN, m.Advertised.ASN} {
		if r.Value == nil {
			continue
		}
		v := "AS" + strconv.FormatUint(uint64(r.Value.Number), 10)
		if len(values) == 0 || values[0] != v {
			values = append(values, v)
		}
	}
	if len(values) == 0 {
		return "unknown"
	}
	return strings.Join(values, ",")
}
func locationSource(d wire.ExecutorDisplay) string {
	for _, v := range []wire.LabelledString{d.Country, d.City} {
		if v.Source != nil {
			return *v.Source
		}
	}
	return "unknown"
}
