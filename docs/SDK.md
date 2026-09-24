# Go client SDK (`pkg/client`)

`github.com/netsec-ethz/debuglet/pkg/client` is the native Go HTTP client for a Debuglet dispatcher. It uses only the standard library and supports the local alpha's TEST payment method. The guest-side WASI SDK that a debuglet itself imports is the separate package [`pkg/debuglet`](../pkg/debuglet). Client and server no longer have to come from the same revision: they agree on the published [HTTP API contract](API.md), and `client.APIVersion` is the contract version this SDK is written against.


## Add the dependency

From your application's Go module, choose a reviewed commit from the public `hardening` branch (or `dev` after integration):

```sh
DEBUGLET_REVISION='<commit-sha>'
go get "github.com/netsec-ethz/debuglet/pkg/client@$DEBUGLET_REVISION"
```

Import `github.com/netsec-ethz/debuglet/pkg/client`. Public fetching needs no credentials or `GOPRIVATE` setting. The existing `v0.1.0` tag predates this client; use an alpha commit rather than assuming that tag contains it.

## Surface

```go
func New(endpoint string, options Options) (*Client, error)
func Prepare(requests []Request) (*PreparedBatch, error)
func (c *Client) SubmitTEST(ctx context.Context, batch *PreparedBatch) (Submission, error)
func (c *Client) Nodes(ctx context.Context) ([]Node, error)
func (c *Client) Status(ctx context.Context, id string) (State, error)
func (c *Client) Logs(ctx context.Context, id string, options LogOptions) (LogPage, error)
func (c *Client) Cancel(ctx context.Context, id, executorID string) error
func (c *Client) Version(ctx context.Context) (ServerVersion, error)
func (c *Client) Connection(ctx context.Context) (ConnectionInfo, error)

func (c *Client) CreateAccount(ctx context.Context, name string) (Account, error)
func (c *Client) Login(ctx context.Context, accountKey string) (Session, error)
func (c *Client) Logout(ctx context.Context) error
func (c *Client) Recover(ctx context.Context, recoveryCode string) (Account, error)
func (c *Client) Whoami(ctx context.Context) (User, error)
func (c *Client) WithCredential(token string) (*Client, error)
```

Types mirror the dispatcher's JSON keys (`order_id`, `executor_id`, `floor_bw`, `timeout_ms`, `tesla_anchor_key`, `has_more`, ...). `State.State` is an opaque string; `client.StateExited` (`RunStateExited`) is the terminal value. An exited debuglet with an empty `Error` succeeded; a nonempty `Error` is a workload failure such as `debuglet exited with code 7`.

## API contract version

Every request announces `Debuglet-API-Version: 1.2`, the contract version in `client.APIVersion`. A dispatcher that cannot serve it answers HTTP 400 with an explicit incompatibility error, which reaches the caller as an ordinary `*HTTPError`; `Version` and the contract document itself always answer, so a rejected client can still read what the dispatcher speaks. A dispatcher written before contract versioning ignores the header, so this SDK also works against an older one. [docs/API.md](API.md) states what a minor version may change and what requires a major one; the SDK ignores unknown response fields accordingly.

## Credentials

A dispatcher authenticates every request that is not public. `Options.Credential` is the session token the client presents, as an `Authorization: Bearer` header, on every request it makes:

```go
account, err := anonymous.CreateAccount(ctx, "researcher") // returns the credentials once
session, err := anonymous.Login(ctx, account.AccountKey)
c, err := anonymous.WithCredential(session.Token)          // same endpoint, now authenticated
```

- `CreateAccount` returns `Account{AccountKey, RecoveryCode}`. The dispatcher stores only their digests and cannot produce them again. Both are secrets: store them with owner-only permissions and keep them out of logs and command output.
- `Login` exchanges an account key for a `Session`. `Session.Token` goes in `Options.Credential`; `Session.ExpiresAt` is Unix seconds, 12 hours after issuance, and is not extended by use. `Session.CSRFToken` matters only to a browser client that received the session as a cookie.
- `Logout` revokes the presented session immediately. `Recover` exchanges a recovery code for replacement credentials and revokes every session of that account.
- `Whoami` reports the account a credential authenticates as, and is the cheapest way to tell a working credential from an expired or revoked one.
- `WithCredential` returns a copy of the client bound to the same origin and base path. A credential therefore cannot be attached to another dispatcher by reusing a client: a different dispatcher means a different `Client`.

An expired, revoked or absent credential answers `*HTTPError` with `StatusCode` 401 and `Code` `client.CodeUnauthorized`; the action behind it is to log in again. `client.CodeForbidden` (403) is an authenticated account that may not perform the operation, which logging in again does not change. A run or payment order belonging to another account answers 404 `client.CodeNotFound`, the same as one that does not exist.

The credential is never written to an error, a diagnostic or a returned value the caller did not ask for: it is added to the values this package redacts, so a server that echoes it back, and a transport failure that quotes the request, both produce a diagnostic with it removed.

A dispatcher serving the local development profile also answers without a credential; `Login` with an empty account key asks such a dispatcher for a credential for its own local account, and every other dispatcher refuses that with 401.

## Endpoint rules

- The endpoint is an explicit absolute base URL. A path prefix such as `https://host/api` is preserved on every route; the client never guesses or appends `/api`. Userinfo, query strings, fragments and schemes other than `http`/`https` are rejected.
- Plaintext `http` is accepted only for literal loopback IPs (`127.0.0.0/8`, `::1`). Any other host, including the name `localhost`, requires `https` with ordinary certificate verification. There is no insecure option.
- TEST submission to an endpoint that is not a literal loopback IP additionally requires `Options.AllowRemoteTEST`. Read-only calls do not. An SSH-forwarded loopback endpoint is still an operator-selected remote service; this check is an accident guard, not server authorization.
- Redirects are rejected, also on a caller-supplied `http.Client`, so a submission cannot silently move to another origin and a credential cannot follow one. The supplied client is cloned and never mutated; no cookie jar is added, and the credential is sent as a header rather than as ambient cookie authority, so a browser-only cookie assumption never gets in a native client's way.

## Submitting

`Prepare` validates the batch (nonempty batch, WASM and executor ID; unique order IDs; positive `TimeoutMS` at most `MaxInt64/int64(time.Millisecond)`; `0 <= FloorBW <= CeilBW`; encoded intent envelope at most 32 MiB) and serializes the debuglets array once. Bandwidth values are bits per second. That frozen array is sent unchanged for both steps of `SubmitTEST`: `PUT payment/intent` with `payment_method: "TEST"`, then `PUT debuglet` with the returned transaction ID and auth key (empty for the current TEST server). Because the dispatcher hashes the decoded request values, the identical bytes pass its hash check; mutating the caller's requests after `Prepare` changes nothing.

Both complete request bodies have a 32 MiB limit. The actual submission body is checked after the server supplies its opaque transaction ID and auth key, before sending the second request. A batch can pass `Prepare` and exceed this second bound. That failure retains the known transaction ID and reports a definite pre-send failure; the intent already exists, but no submission is attempted. Metadata has no separate arbitrary length limit.

`SubmitTEST` returns the job IDs in batch order and the transaction ID. It never retries, never polls payment status and never invents a transaction ID. Failures are `*SubmissionError{Stage, TransactionID, OutcomeUnknown, Err}`:

| Situation | Stage | TransactionID | OutcomeUnknown |
| --- | --- | --- | --- |
| Validation or remote-TEST guard before sending | `intent` | empty | false |
| Intent rejected (4xx) or a transport/connection failure while requesting the intent | `intent` | empty | false |
| Intent answered with a malformed or inconsistent success body, or a 5xx | `intent` | empty | true |
| Submission validation/size or canceled context detected before sending | `submit` | known | false |
| Submission rejected (4xx) | `submit` | known | false |
| Transport or read failure after attempting submission, malformed or inconsistent success body, unexpected 2xx, 5xx | `submit` | known | true |

`OutcomeUnknown` means the server may have accepted the request although no valid response was observed. It is uncertainty, not acceptance; inspect available transaction/job state before considering resubmission. A transport failure while requesting the intent sets this flag to false because no submission was attempted; an intent 5xx or malformed intent response is reported as unknown because the intent's server bookkeeping may exist. An unexpected submission 201/202 is still an HTTP protocol error, but cannot establish rejection. Neither case triggers an automatic retry.

## Reading results

- `Status` requires a canonical UUID and returns the reported state, error and executor ID. Unknown state strings are preserved.
- `Logs` returns one page after the cursor `After` with `Limit` entries (zero defaults to 100, otherwise 1–1000). `Output` holds the exact guest bytes. Each page is validated against the requested cursor: entry IDs strictly increase and exceed the cursor, a nonempty page's `After` is its last ID, an empty page's `After` equals the request cursor, and an empty page cannot report `HasMore`. A full page may report `HasMore` although no later entry exists; the following page is then empty.
- `Cancel` sends the dispatcher's cancellation and returns `nil` on the server's acknowledgement (HTTP 204), which says that the cancellation is recorded as the job's result, or that the job already had one. Acknowledgement does not certify remote termination. The current server also acknowledges cancellation of a job that has already finished, and it never rewrites a recorded terminal result: `Status` afterwards reports the server's own error (`cancelled via API` for a job cancelled while nonterminal, or the earlier exit error), which the client preserves verbatim. A 500 `internal_error` saying the cancellation was acknowledged but its result was not recorded means the executor may be stopping the job while its recorded state does not show the cancellation: read `Status` before deciding, and repeat `Cancel` to record it. Not-found, refused and other server-reported cancellation errors are `*HTTPError` values.
- `Version` reports the dispatcher's separate identities: `Version` (its configured string), `APIVersion` and `APIVersions` (the HTTP contract it serves), `BinaryVersion` and `BinaryRevision` (the build), and `ProtocolVersion` (the executor control protocol, which no HTTP client speaks). A dispatcher written before the contract was versioned answers with `Version` only and leaves the rest empty.
- `Connection` reads optional local executor-join metadata: `SchemaVersion`, `Mode`, `GRPCAddress`, and `YamuxAddress`. Current metadata has schema version 1 and mode `local-test`. This is not a dispatcher directory or authenticated enrollment. Ordinary submission and result queries need only the HTTP endpoint; older servers can lack this route and return a typed HTTP error.

Every other status, including other 2xx codes, is an `*HTTPError{Method, Path, StatusCode, Code, Message}`. `Code` is the dispatcher's stable failure code (`client.CodeCapacityExhausted`, `client.CodeNotFound`, ... ; see [docs/API.md](API.md)): branch on it instead of matching on `Message`. It is empty when the server sent no documented envelope or a code that is not a bounded lowercase identifier, so a code can never smuggle response text. `(*SubmissionError).Code()` reaches the same value for a failed submission without changing `OutcomeUnknown`, which remains the only statement about whether the submission may have been accepted. Safe Echo `message` values, JSON-string errors and plaintext messages are retained. Unrecognized JSON envelopes/arrays and malformed or truncated JSON-shaped error bodies produce a generic diagnostic; the client does not print the whole response as a fallback. Recognized structured `auth_key` values are removed before messages are derived, and a known nonempty submission key is redacted from response diagnostics. This also covers decoded intent-validation errors and the public `HTTPError.Message` field. Arbitrary server text can contain information the client cannot identify as secret.

Successful JSON bodies are bounded to 4 MiB and error bodies to 8 KiB; oversized, malformed or trailing successful JSON is an error rather than a truncated success. Formatted transport/read errors also redact a known submission key, including one quoted by the HTTP response parser. Context cancellation/deadlines and underlying error types remain available through `errors.Is`/`errors.As`; explicitly unwrapping a transport error exposes the original error rather than sanitized copies of all its fields. Request bodies and WASM are excluded from SDK-generated diagnostics.

## Example

```go
c, err := client.New("http://127.0.0.1:9000", client.Options{})
if err != nil { ... }
batch, err := client.Prepare([]client.Request{{
	OrderID:    0,
	ExecutorID: "executor-id",
	Args:       []string{"127.0.0.1:8080"},
	Wasm:       wasmBytes,
	Policy:     client.Policy{FloorBW: 1_000_000, CeilBW: 1_000_000, TimeoutMS: 10_000, Addresses: []string{"127.0.0.1"}},
}})
if err != nil { ... }
sub, err := c.SubmitTEST(ctx, batch)
if err != nil { ... }
state, err := c.Status(ctx, sub.IDs[0])
```

## Limitations

TEST only; no wallet, chain payment, retry or idempotency. The dispatcher's hash check protects intent/submission identity, not authorization: authorization is the credential, and a payment order may only be spent by the account that created it. This package stores no credential of its own and refreshes none; obtaining, keeping and renewing one is the caller's job, which is what the `dbl` profile store in [docs/CLI.md](CLI.md) does. Output pages reflect stored logs, not a delivery guarantee. Requests are bounded by the caller's context and the per-request timeout; the server's job budget is `TimeoutMS`.

## Run the complete example

Start `dbl dispatcher up` and `dbl executor up --dispatcher http://127.0.0.1:9000`
in separate terminals, or use the combined `dbl up`. In a
source checkout with Go 1.25.11, build a guest and run the
[complete client example](../examples/client/main.go):

```sh
make wasm SAMPLE_DIR=local/wasm_samples/go/hello-local
go run -mod=readonly ./examples/client --wasm local/wasm_samples/go/hello-local/debuglet.wasm
```

The example discovers the sole ready executor, submits the guest with TEST
bookkeeping, and prints its stored output. Use `--executor ID` when multiple
executors are ready, or `--endpoint URL` for a different local port. It uses only
the public `pkg/client` API, so you can copy it into your own module after adding
the dependency above. Arguments following `--` go to the guest.

The same example reaches a dispatcher on another host with three more flags: `--register NAME` creates an account and logs in for the rest of the run, `--allow-remote-test` sets `Options.AllowRemoteTEST`, and `--allow HOST[,HOST]` fills the request's address allowlist. It prints the account id and neither the account key nor the session token, as in `go run -mod=readonly ./examples/client --endpoint https://HOST:PORT --register researcher --allow-remote-test --allow example.com --wasm GUEST.wasm -- -addr example.com:80 -count 3`. The [cross-host quickstart](quickstart-remote.md) has the dispatcher and executor side of that setup.

The SDK does not read the CLI's saved profiles or start daemons. Pass the printed
HTTP URL to `client.New` (or the example's `--endpoint`). This keeps application
configuration independent of the operator's selected CLI connection. A native
client application needs neither the full daemon package nor a wallet.
