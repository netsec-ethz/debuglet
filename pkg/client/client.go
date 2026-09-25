package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// defaultRequestTimeout bounds one request and its body read when
// Options.RequestTimeout is zero.
const defaultRequestTimeout = 10 * time.Second

// Route names relative to the explicit base URL. The client never appends a
// guessed prefix such as /api; the caller's base path is preserved verbatim.
const (
	routeIntent    = "payment/intent"
	routeDebuglet  = "debuglet"
	routeExecutors = "executors"
	routeVersion   = "version"
	routeLogin     = "auth/login"
	routeLogout    = "auth/logout"
	routeRecover   = "auth/recover"
	routeUser      = "user"
	routeMe        = "me"
)

const (
	// APIVersion is the dispatcher HTTP contract version this SDK is written
	// against, as major.minor. It is announced on every request so that a
	// server implementing an incompatible contract rejects the request
	// explicitly instead of answering a shape the client cannot read. A server
	// written before the contract was versioned ignores the header.
	APIVersion = "1.2"
	// apiVersionHeader carries APIVersion on requests and the server's
	// implemented contract version on responses.
	apiVersionHeader = "Debuglet-API-Version"
)

// Client talks to one dispatcher endpoint. Create it with New.
type Client struct {
	options Options

	// http is a private copy of the caller's client with redirects rejected.
	http *http.Client
	// origin is scheme://host[:port]; basePath is the normalised explicit
	// prefix ("" or "/segment[/segment...]" without a trailing slash).
	origin   string
	basePath string
	timeout  time.Duration
	// loopback records whether the endpoint host is a literal loopback IP.
	loopback bool
	// credential is the session token presented on every request. It is kept
	// out of every error this package builds, and it is redacted from a
	// server diagnostic that happens to repeat it.
	credential string
}

// New validates endpoint and options and returns a Client. The endpoint is an
// explicit base URL, optionally with a path prefix that is preserved on every
// route; plaintext HTTP is accepted only for literal loopback IPs.
func New(endpoint string, options Options) (*Client, error) {
	if options.RequestTimeout < 0 {
		return nil, errors.New("client: negative request timeout")
	}
	origin, basePath, loopback, err := parseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	timeout := options.RequestTimeout
	if timeout == 0 {
		timeout = defaultRequestTimeout
	}
	// Clone the caller's configuration (Transport, Timeout, Jar) by value and
	// override only redirect handling; the supplied client is never mutated
	// and no cookie jar is installed.
	hc := &http.Client{}
	if options.HTTPClient != nil {
		copied := *options.HTTPClient
		hc = &copied
	}
	hc.CheckRedirect = rejectRedirect
	credential := strings.TrimSpace(options.Credential)
	if credential != options.Credential {
		return nil, errors.New("client: credential must not be padded with spaces")
	}
	return &Client{
		options:    options,
		http:       hc,
		origin:     origin,
		basePath:   basePath,
		timeout:    timeout,
		loopback:   loopback,
		credential: credential,
	}, nil
}

// WithCredential returns a copy of this client that presents the given session
// token. The endpoint, transport and timeouts are unchanged, so a credential
// obtained from one dispatcher cannot be attached to another by accident: a
// different dispatcher means a different Client.
func (c *Client) WithCredential(token string) (*Client, error) {
	if c == nil || c.http == nil {
		return nil, errors.New("client: Client must be created with New")
	}
	options := c.options
	options.Credential = token
	options.HTTPClient = c.http
	return New(c.origin+c.basePath, options)
}

// Login exchanges an account key for a session. An empty account key asks a
// dispatcher that serves the local development profile for a credential for
// its own local account; every other dispatcher refuses it. The returned
// Session.Token is what Options.Credential takes.
func (c *Client) Login(ctx context.Context, accountKey string) (Session, error) {
	body, err := marshalJSON(struct {
		AccountKey string `json:"account_key"`
	}{AccountKey: accountKey})
	if err != nil {
		return Session{}, err
	}
	data, err := c.do(ctx, http.MethodPost, routeLogin, nil, body, http.StatusOK, accountKey)
	if err != nil {
		return Session{}, err
	}
	var session Session
	if err := c.decode(http.MethodPost, routeLogin, data, &session); err != nil {
		return Session{}, err
	}
	if strings.TrimSpace(session.Token) == "" {
		return Session{}, c.protocolErr(http.MethodPost, routeLogin, "missing token")
	}
	return session, nil
}

// Logout revokes the session this client presents. The token is refused from
// then on, before its own expiry. A client without a credential logs nothing
// out and reports the dispatcher's authentication failure.
func (c *Client) Logout(ctx context.Context) error {
	_, err := c.do(ctx, http.MethodPost, routeLogout, nil, []byte("{}"), http.StatusNoContent)
	return err
}

// CreateAccount registers an account and returns its first credentials. They
// are returned exactly once: the dispatcher stores only their digests. The
// caller is responsible for storing them where only its user can read them.
func (c *Client) CreateAccount(ctx context.Context, name string) (Account, error) {
	if strings.TrimSpace(name) == "" {
		return Account{}, errors.New("client: blank account name")
	}
	body, err := marshalJSON(struct {
		Name string `json:"name"`
	}{Name: name})
	if err != nil {
		return Account{}, err
	}
	data, err := c.do(ctx, http.MethodPut, routeUser, nil, body, http.StatusOK)
	if err != nil {
		return Account{}, err
	}
	var account Account
	if err := c.decode(http.MethodPut, routeUser, data, &account); err != nil {
		return Account{}, err
	}
	if strings.TrimSpace(account.AccountKey) == "" {
		return Account{}, c.protocolErr(http.MethodPut, routeUser, "missing account_key")
	}
	return account, nil
}

// Recover consumes a recovery code and returns the replacement credentials of
// the one account that code belongs to. Every session of that account is
// revoked by the dispatcher first. A recovery code can name no other account,
// so recovering never grants ownership of somebody else's.
func (c *Client) Recover(ctx context.Context, recoveryCode string) (Account, error) {
	body, err := marshalJSON(struct {
		RecoveryCode string `json:"recovery_code"`
	}{RecoveryCode: recoveryCode})
	if err != nil {
		return Account{}, err
	}
	data, err := c.do(ctx, http.MethodPost, routeRecover, nil, body, http.StatusOK, recoveryCode)
	if err != nil {
		return Account{}, err
	}
	var account Account
	if err := c.decode(http.MethodPost, routeRecover, data, &account); err != nil {
		return Account{}, err
	}
	if strings.TrimSpace(account.AccountKey) == "" {
		return Account{}, c.protocolErr(http.MethodPost, routeRecover, "missing account_key")
	}
	return account, nil
}

// Whoami reports the account this client's credential authenticates as. It is
// the cheapest way to tell a working credential from an expired or revoked
// one: the latter answers an *HTTPError with CodeUnauthorized.
func (c *Client) Whoami(ctx context.Context) (User, error) {
	data, err := c.do(ctx, http.MethodGet, routeMe, nil, nil, http.StatusOK)
	if err != nil {
		return User{}, err
	}
	var user User
	if err := c.decode(http.MethodGet, routeMe, data, &user); err != nil {
		return User{}, err
	}
	if strings.TrimSpace(user.ID) == "" {
		return User{}, c.protocolErr(http.MethodGet, routeMe, "missing id")
	}
	return user, nil
}

// rejectRedirect stops the HTTP client from following any redirect: the 3xx
// response is returned unchanged and then reported as an *HTTPError, so a
// submission can never silently move to another origin.
func rejectRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// parseEndpoint validates the endpoint URL and splits it into origin, base
// path and loopback flag.
func parseEndpoint(endpoint string) (origin, basePath string, loopback bool, err error) {
	if strings.TrimSpace(endpoint) == "" {
		return "", "", false, errors.New("client: endpoint must be an absolute http or https URL")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		// Never echo the raw endpoint: it may carry credentials.
		return "", "", false, errors.New("client: endpoint is not a valid URL")
	}
	if u.Scheme == "" || u.Opaque != "" {
		return "", "", false, errors.New("client: endpoint must be an absolute http or https URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", "", false, fmt.Errorf("client: endpoint: unsupported scheme %q (use http or https)", u.Scheme)
	}
	if u.User != nil {
		return "", "", false, errors.New("client: endpoint: userinfo is not allowed")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return "", "", false, errors.New("client: endpoint: query string is not allowed")
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return "", "", false, errors.New("client: endpoint: fragment is not allowed")
	}
	host := u.Hostname()
	if host == "" {
		return "", "", false, errors.New("client: endpoint: host is required")
	}
	loopback = isLiteralLoopback(host)
	if u.Scheme == "http" && !loopback {
		return "", "", false, errors.New("client: endpoint: plaintext http is only allowed for literal loopback IP hosts (127.0.0.0/8 or ::1); use https")
	}
	// An explicit base path is permitted; exactly one trailing slash is
	// normalised away and every segment must be a plain nonempty name.
	if p := strings.TrimSuffix(u.Path, "/"); p != "" {
		if !strings.HasPrefix(p, "/") {
			return "", "", false, errors.New("client: endpoint: base path must start with /")
		}
		for _, segment := range strings.Split(p[1:], "/") {
			if segment == "" || segment == "." || segment == ".." {
				return "", "", false, fmt.Errorf("client: endpoint: invalid base path segment %q", segment)
			}
		}
	}
	basePath = strings.TrimSuffix(u.EscapedPath(), "/")
	origin = u.Scheme + "://" + u.Host
	return origin, basePath, loopback, nil
}

// isLiteralLoopback reports whether host is a literal IP in 127.0.0.0/8 or
// the IPv6 loopback ::1. Names such as "localhost" are not literal IPs.
func isLiteralLoopback(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 127
	}
	return ip.Equal(net.IPv6loopback)
}

// Nodes lists the dispatcher's registered executors.
func (c *Client) Nodes(ctx context.Context) ([]Node, error) {
	data, err := c.do(ctx, http.MethodGet, routeExecutors, nil, nil, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var nodes []Node
	if err := c.decode(http.MethodGet, routeExecutors, data, &nodes); err != nil {
		return nil, err
	}
	if nodes == nil {
		nodes = []Node{}
	}
	return nodes, nil
}

// Status returns the state of one debuglet.
func (c *Client) Status(ctx context.Context, id string) (State, error) {
	if err := validateJobID(id); err != nil {
		return State{}, err
	}
	route := routeDebuglet + "/" + id + "/state"
	data, err := c.do(ctx, http.MethodGet, route, nil, nil, http.StatusOK)
	if err != nil {
		return State{}, err
	}
	var state State
	if err := c.decode(http.MethodGet, route, data, &state); err != nil {
		return State{}, err
	}
	if strings.TrimSpace(state.State) == "" {
		return State{}, c.protocolErr(http.MethodGet, route, "missing state")
	}
	if strings.TrimSpace(state.ExecutorID) == "" {
		return State{}, c.protocolErr(http.MethodGet, route, "missing executor_id")
	}
	return state, nil
}

// Logs returns one page of a debuglet's stored output.
func (c *Client) Logs(ctx context.Context, id string, options LogOptions) (LogPage, error) {
	if err := validateJobID(id); err != nil {
		return LogPage{}, err
	}
	if options.After < 0 {
		return LogPage{}, errors.New("client: log cursor must not be negative")
	}
	limit := options.Limit
	if limit == 0 {
		limit = 100
	}
	if limit < 1 || limit > 1000 {
		return LogPage{}, errors.New("client: log limit must be within 1..1000")
	}
	route := routeDebuglet + "/" + id + "/logs"
	query := url.Values{
		"after": {strconv.FormatInt(options.After, 10)},
		"limit": {strconv.FormatInt(limit, 10)},
	}
	data, err := c.do(ctx, http.MethodGet, route, query, nil, http.StatusOK)
	if err != nil {
		return LogPage{}, err
	}
	var page LogPage
	if err := c.decode(http.MethodGet, route, data, &page); err != nil {
		return LogPage{}, err
	}
	if strings.TrimSpace(page.State) == "" {
		return LogPage{}, c.protocolErr(http.MethodGet, route, "missing state")
	}
	if page.Logs == nil {
		page.Logs = []LogEntry{}
	}
	previous := options.After
	for i, entry := range page.Logs {
		if entry.ID <= previous {
			return LogPage{}, c.protocolErr(http.MethodGet, route,
				fmt.Sprintf("log entry %d has id %d, expected an id above %d", i, entry.ID, previous))
		}
		previous = entry.ID
	}
	if len(page.Logs) == 0 {
		if page.HasMore {
			return LogPage{}, c.protocolErr(http.MethodGet, route, "empty page reports has_more")
		}
		if page.After != options.After {
			return LogPage{}, c.protocolErr(http.MethodGet, route,
				fmt.Sprintf("empty page cursor %d does not equal requested cursor %d", page.After, options.After))
		}
	} else if page.After != previous {
		return LogPage{}, c.protocolErr(http.MethodGet, route,
			fmt.Sprintf("page cursor %d does not equal last entry id %d", page.After, previous))
	}
	return page, nil
}

// Cancel asks the dispatcher to abort a debuglet on the given executor. A nil
// error is an acknowledgement, not proof that execution stopped.
func (c *Client) Cancel(ctx context.Context, id, executorID string) error {
	if err := validateJobID(id); err != nil {
		return err
	}
	if strings.TrimSpace(executorID) == "" {
		return errors.New("client: blank executor id")
	}
	body, err := marshalJSON(struct {
		DebugletID string `json:"debuglet_id"`
		ExecutorID string `json:"executor_id"`
	}{DebugletID: id, ExecutorID: executorID})
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodDelete, routeDebuglet, nil, body, http.StatusNoContent)
	return err
}

// Version reports the dispatcher's version identities. It is a report, not an
// ABI negotiation: the request itself carries APIVersion, and a server that
// cannot serve it rejects the request. A server written before the contract
// was versioned answers with Version only, leaving the other fields empty.
func (c *Client) Version(ctx context.Context) (ServerVersion, error) {
	data, err := c.do(ctx, http.MethodGet, routeVersion, nil, nil, http.StatusOK)
	if err != nil {
		return ServerVersion{}, err
	}
	var version ServerVersion
	if err := c.decode(http.MethodGet, routeVersion, data, &version); err != nil {
		return ServerVersion{}, err
	}
	return version, nil
}
