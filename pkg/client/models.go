// Package client is the native Go HTTP client for a Debuglet dispatcher. It
// runs on the researcher's machine, talks to the dispatcher's existing HTTP
// API and supports TEST-funded submissions only. It never imports server
// internals; it shares the dispatcher's HTTP types through pkg/wire.
//
// The guest-side WASI SDK is the separate package pkg/debuglet.
package client

import (
	"net/http"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

// Options configures a Client. The zero value is valid for a loopback
// endpoint: a fresh HTTP client, a 10 s per-request timeout and no remote
// TEST submissions.
type Options struct {
	// HTTPClient supplies transport settings. It is cloned, never mutated,
	// and redirects are always rejected. nil uses a fresh client.
	HTTPClient *http.Client
	// RequestTimeout bounds each request including its body read. Zero
	// defaults to 10 s; a negative value is invalid.
	RequestTimeout time.Duration
	// AllowRemoteTEST permits TEST submissions to endpoints other than a
	// literal loopback IP. It is an accident guard, not server authorization:
	// an SSH-forwarded loopback endpoint is still an operator-selected remote
	// service.
	AllowRemoteTEST bool
	// Credential is the session token this client presents on every request,
	// as an Authorization bearer header. It is obtained from Login and belongs
	// to exactly one dispatcher: a Client is bound to one origin and refuses
	// redirects, so a credential never travels to another one. It is never
	// written to a log, an error message or a returned diagnostic. Empty makes
	// unauthenticated requests, which a dispatcher serving the local
	// development profile still accepts.
	Credential string
}

// Account is one account together with the credentials an issuing operation
// returned for it. AccountKey and RecoveryCode are shown by the dispatcher
// exactly once, at the operation that minted them, and cannot be read back.
// Treat both as secrets: store them with owner-only permissions and keep them
// out of logs, command output and receipts.
type Account struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Role         string `json:"role"`
	AccountKey   string `json:"account_key"`
	RecoveryCode string `json:"recovery_code"`
}

// Session is an issued session. Token is the bearer credential to put in
// Options.Credential. CSRFToken is only of interest to a browser client that
// received the session as a cookie; a native client never needs it. ExpiresAt
// is Unix seconds.
type Session struct {
	Token     string `json:"token"`
	CSRFToken string `json:"csrf_token"`
	ExpiresAt int64  `json:"expires_at"`
	ID        string `json:"id"`
	Name      string `json:"name"`
	Role      string `json:"role"`
}

// User is the account a request authenticated as, as reported by GET me.
type User = wire.User

// Request describes one debuglet in a batch. Wasm holds the guest bytes and
// encoding/json transmits it as base64.
type Request = wire.Request[[]byte]

// Policy is the network policy requested for a debuglet.
type Policy = wire.Policy

// Node is one executor as reported by GET executors.
type Node = wire.Executor

// Submission is the result of an accepted TEST submission. IDs are in batch
// order. No auth key is exposed.
type Submission struct {
	IDs           []string `json:"ids"`
	TransactionID string   `json:"transaction_id"`
}

// State is a debuglet's reported state. Unknown state strings are preserved.
type State = wire.State

// StateExited is the terminal state string reported by the dispatcher. An
// exited debuglet with an empty Error succeeded; a nonempty Error is a
// workload failure.
const StateExited = "RunStateExited"

// LogOptions selects a log page. After is a cursor (entry ID) that must be
// >= 0; Limit zero defaults to 100, otherwise it must be within 1..1000.
type LogOptions struct {
	After int64
	Limit int64
}

// LogPage is one page of guest output.
type LogPage = wire.LogPage[[]byte]

// OutputStatus records output finality; missing metadata from older servers is unknown.
type OutputStatus = wire.OutputStatus

// LogEntry is one stored output chunk. Output holds the exact guest bytes;
// Timestamp is the server's opaque string.
type LogEntry = wire.LogEntry[[]byte]

// ServerVersion reports the dispatcher's independent version identities.
// Every field beyond Version is empty for older dispatchers.
type ServerVersion = wire.Version

// PreparedBatch is an immutable, validated batch produced by Prepare. The
// same serialized debuglets array is sent for the payment intent and the
// submission, so the server's request hash check sees identical values. A
// zero or nil PreparedBatch is invalid.
type PreparedBatch struct {
	debuglets []byte
	count     int
}
