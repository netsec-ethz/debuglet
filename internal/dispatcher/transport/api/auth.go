package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// Credentials of this API are server-issued, unpredictable and stored hashed.
// A credential is a public selector and a secret verifier, printed as
//
//	<prefix>_<selector>.<verifier>
//
// where selector and verifier are unpadded base64url of 16 and 32 random
// bytes. The selector is the lookup key; only the SHA-256 digest of the
// verifier is stored, and it is compared in constant time. The prefix names
// what the credential is for, so a credential of one kind can never be
// presented as another.
const (
	// accountPrefix marks the long-lived account key. It is the credential a
	// native client exchanges for a session; it is not a session itself.
	accountPrefix = "dba"
	// recoveryPrefix marks the one-time recovery code of an account. Using it
	// issues a new account key, a new recovery code and a fresh session, and
	// revokes every session the account had.
	recoveryPrefix = "dbr"
	// sessionPrefix marks an issued session token. It is what a request
	// presents, as a bearer token or in the session cookie.
	sessionPrefix = "dbs"
)

// Credential kinds as stored in user_credentials.
const (
	credentialAccount  = "account"
	credentialRecovery = "recovery"
)

// Account roles. A role is a property of the account, never of the request.
const (
	// RoleUser is an ordinary submitter: it reaches its own runs and nothing
	// else.
	RoleUser = "user"
	// RoleOperator additionally reaches the dispatcher-wide administration
	// operations listed in docs/API.md. No HTTP route grants this role; it is
	// held by the account the local development mode bootstraps.
	RoleOperator = "operator"
)

const (
	// SessionLifetime is how long an issued session stays valid. It is not
	// extended by use: a client logs in again, which issues a new session.
	SessionLifetime = 12 * time.Hour
	// sessionCookieName carries a session token for browser clients. Its value
	// is a session token, never a user identifier.
	sessionCookieName = "session_token"
	// csrfCookieName carries the session's CSRF token. It is readable by the
	// console's own script, which repeats it in csrfHeaderName.
	csrfCookieName = "session_csrf"
	// csrfHeaderName carries the CSRF token of a cookie-authenticated
	// state-changing request. A bearer token is not ambient authority and
	// needs no such proof.
	csrfHeaderName = "X-Debuglet-CSRF"
	// maxCredentialLength bounds a presented credential before it is parsed,
	// so an arbitrarily long request value is rejected without inspection.
	maxCredentialLength = 128
	// selectorBytes and verifierBytes size the two halves of a credential.
	selectorBytes = 16
	verifierBytes = 32
)

// localDevelopmentAccount is the fixed account the local development mode
// issues credentials for. It is created on first use and holds RoleOperator so
// that the wallet-free local flow reaches the administration operations. It
// exists only in a deployment that explicitly enabled local development.
var localDevelopmentAccount = uuid.MustParse("b8f0f3b1-5a7f-4e2f-9a52-0f4a5d6c7e81")

// localDevelopmentAccountName is the name that account is created with.
const localDevelopmentAccountName = "local development"

// callerKey is the context key under which the authenticated caller is stored.
const callerKey = "debuglet.caller"

// caller is the outcome of authenticating one request.
type caller struct {
	// UserUUID and Name identify the account a verified credential named.
	UserUUID uuid.UUID
	Name     string
	// Role is the account's role; Operator is its decision for this request.
	Role     string
	Operator bool
	// Authenticated reports that a credential was presented and verified.
	Authenticated bool
	// Local reports that the local development bypass admitted a request that
	// presented no credential at all.
	Local bool
	// Session is the selector of the verified session, used by logout.
	Session string
	// Cookie reports that the credential arrived in the session cookie, which
	// is the only case that needs CSRF proof.
	Cookie bool
	// Failure is the rejection a presented credential earned. Public routes
	// ignore it; every protected route returns it.
	Failure error
}

// encodeSecret prints one random half of a credential.
func encodeSecret(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// newSecret mints one unpredictable secret and the digest that is stored for
// it. The secret itself is never written anywhere.
func newSecret() (secret string, digest []byte, err error) {
	raw := make([]byte, verifierBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	secret = encodeSecret(raw)
	sum := sha256.Sum256([]byte(secret))
	return secret, sum[:], nil
}

// newCredential mints a credential of the given kind and returns the printed
// value, its selector and the digest of its verifier. The printed value is the
// only time the secret exists outside the caller's hands.
func newCredential(prefix string) (token, selector string, digest []byte, err error) {
	raw := make([]byte, selectorBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", "", nil, err
	}
	selector = encodeSecret(raw)
	verifier, digest, err := newSecret()
	if err != nil {
		return "", "", nil, err
	}
	return prefix + "_" + selector + "." + verifier, selector, digest, nil
}

// parseCredential splits a presented credential of the expected kind. A value
// of another kind, a malformed one or an oversized one is rejected without
// touching the database.
func parseCredential(prefix, presented string) (selector, verifier string, ok bool) {
	if presented == "" || len(presented) > maxCredentialLength {
		return "", "", false
	}
	rest, found := strings.CutPrefix(presented, prefix+"_")
	if !found {
		return "", "", false
	}
	selector, verifier, found = strings.Cut(rest, ".")
	if !found || selector == "" || verifier == "" {
		return "", "", false
	}
	if _, err := base64.RawURLEncoding.DecodeString(selector); err != nil {
		return "", "", false
	}
	if _, err := base64.RawURLEncoding.DecodeString(verifier); err != nil {
		return "", "", false
	}
	return selector, verifier, true
}

// verifierMatches compares a presented verifier against a stored digest in
// constant time.
func verifierMatches(stored []byte, verifier string) bool {
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare(stored, sum[:]) == 1
}

// unauthorized is the single rejection every failed credential earns. Missing,
// malformed, unknown, expired and revoked credentials are not distinguished:
// the difference is only useful to someone probing the server.
func unauthorized() *echo.HTTPError {
	return apiError(http.StatusUnauthorized, CodeUnauthorized, "authentication required")
}

// AuthMiddleware verifies the credential a request presents and records the
// caller it establishes. Unlike the identity cookie it replaces, it never
// accepts a user identifier as a credential and never lets a rejected
// credential continue as an anonymous request on a protected route.
//
// localDevelopment admits a request that presents no credential at all as the
// local operator, which is the documented development bypass. It is off unless
// the deployment explicitly asked for it.
func AuthMiddleware(db *sql.DB, localDevelopment bool) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if healthRoutes[c.Path()] {
				// A health probe establishes no caller: it reaches nothing
				// that belongs to anybody, and verifying a credential for it
				// would spend the very database connection it reports on.
				return next(c)
			}
			presented, fromCookie := presentedCredential(c)
			if presented == "" {
				// A request with no credential carries the local operator's
				// authority only where the bypass is on. Everywhere else it
				// carries none at all, not even a role that some later route
				// might read without checking Local first.
				anonymous := &caller{Local: localDevelopment, Operator: localDevelopment}
				if localDevelopment {
					anonymous.Role = RoleOperator
				}
				c.Set(callerKey, anonymous)
				return next(c)
			}
			established, err := authenticate(c, db, presented, fromCookie)
			if err != nil {
				c.Set(callerKey, &caller{Failure: err})
				return next(c)
			}
			c.Set(callerKey, established)
			return next(c)
		}
	}
}

// presentedCredential reads the session token a request carries. The bearer
// header is preferred: a native client sends it deliberately, while a cookie
// is ambient browser authority.
func presentedCredential(c echo.Context) (token string, fromCookie bool) {
	header := strings.TrimSpace(c.Request().Header.Get(echo.HeaderAuthorization))
	if header != "" {
		value, found := strings.CutPrefix(header, "Bearer ")
		if !found {
			// Another scheme is not a Debuglet credential. Reporting it as an
			// empty credential keeps the route's own policy in charge.
			return "", false
		}
		return strings.TrimSpace(value), false
	}
	cookie, err := c.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return "", false
	}
	return cookie.Value, true
}

// authenticate verifies a presented session token against the stored session.
func authenticate(c echo.Context, db *sql.DB, presented string, fromCookie bool) (*caller, error) {
	selector, verifier, ok := parseCredential(sessionPrefix, presented)
	if !ok {
		return nil, unauthorized()
	}
	if db == nil {
		return nil, unauthorized()
	}
	row, err := database.New(db).GetSessionBySelector(c.Request().Context(), selector)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, unauthorized()
		}
		return nil, apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to read the session", err)
	}
	if !verifierMatches(row.VerifierHash, verifier) || row.Revoked != 0 {
		return nil, unauthorized()
	}
	if !time.Now().UTC().Before(row.ExpiresAt.Time) {
		return nil, unauthorized()
	}
	if fromCookie && !safeMethod(c.Request().Method) {
		if !verifierMatches(row.CsrfHash, strings.TrimSpace(c.Request().Header.Get(csrfHeaderName))) {
			return nil, apiError(http.StatusForbidden, CodeForbidden,
				"cookie-authenticated requests must repeat the session CSRF token")
		}
	}
	return &caller{
		UserUUID:      row.Uuid,
		Name:          row.Name,
		Role:          row.Role,
		Operator:      row.Role == RoleOperator,
		Authenticated: true,
		Session:       selector,
		Cookie:        fromCookie,
	}, nil
}

// safeMethod reports whether a method only reads, and so needs no CSRF proof.
func safeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

// requestCaller returns the caller AuthMiddleware established. A handler
// reached without the middleware is treated as unauthenticated.
func requestCaller(c echo.Context) *caller {
	if established, ok := c.Get(callerKey).(*caller); ok {
		return established
	}
	return &caller{}
}

// requireCaller admits a request that may act at all: one with a verified
// credential, or one the local development bypass admits. It is the first
// thing every protected route does.
func requireCaller(c echo.Context) (*caller, error) {
	established := requestCaller(c)
	if established.Failure != nil {
		return nil, established.Failure
	}
	if !established.Authenticated && !established.Local {
		return nil, unauthorized()
	}
	return established, nil
}

// requireAccount admits a request that acts as a named account. The local
// development bypass does not name one, so a route that reports or lists an
// account's own data requires a credential even there.
func requireAccount(c echo.Context) (*caller, error) {
	established, err := requireCaller(c)
	if err != nil {
		return nil, err
	}
	if !established.Authenticated {
		return nil, unauthorized()
	}
	return established, nil
}

// requireOperator admits a request that may act on the dispatcher rather than
// on its own objects. An authenticated account without the role is refused
// with 403: the route's existence is public, only the operation is restricted.
func requireOperator(c echo.Context) (*caller, error) {
	established, err := requireCaller(c)
	if err != nil {
		return nil, err
	}
	if !established.Operator {
		return nil, apiError(http.StatusForbidden, CodeForbidden, "this operation requires an operator account")
	}
	return established, nil
}

// unrestricted reports whether the caller is the local development bypass,
// which acts on every object of its own dispatcher. A request that presented a
// credential is never unrestricted, even in local development.
func (a *caller) unrestricted() bool {
	return a.Local && !a.Authenticated
}

// owner returns the account a new run or payment order is recorded for, and
// whether there is one. The local development bypass names no account, so its
// runs stay ownerless exactly as they were before authentication existed.
func (a *caller) owner() (uuid.UUID, bool) {
	if !a.Authenticated {
		return uuid.UUID{}, false
	}
	return a.UserUUID, true
}

// authorizeDebuglet decides whether the caller may act on one run, before the
// run's state, output or executor is read or changed. A run owned by another
// account, a run recorded before ownership existed and a run that does not
// exist are answered alike, so the response is no existence oracle.
func (h *Handler) authorizeDebuglet(c echo.Context, id uuid.UUID) error {
	established, err := requireCaller(c)
	if err != nil {
		return err
	}
	if established.unrestricted() {
		return nil
	}
	owner, err := database.New(h.db).GetDebugletOwnerUUID(c.Request().Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return debugletNotFound()
		}
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to read the run owner", err)
	}
	if owner != established.UserUUID {
		return debugletNotFound()
	}
	return nil
}

// authorizeTransactionOwner decides whether one caller may use one payment
// order. Another account's transaction, and one recorded before orders had an
// owner, earn the refusal the route already gives an unknown transaction, so
// neither is distinguishable from one that does not exist.
func (h *Handler) authorizeTransactionOwner(c echo.Context, established *caller, transactionID string, refusal *echo.HTTPError) error {
	if established.unrestricted() {
		return nil
	}
	owner, err := database.New(h.db).GetTransactionOwnerUUID(c.Request().Context(), transactionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return refusal
		}
		return apiErrorFrom(http.StatusInternalServerError, CodeInternal, "failed to read the transaction owner", err)
	}
	if owner != established.UserUUID {
		return refusal
	}
	return nil
}

// debugletNotFound is the single answer to a run the caller may not see.
func debugletNotFound() *echo.HTTPError {
	return apiError(http.StatusNotFound, CodeNotFound, "debuglet not found")
}

// transactionNotFound is the single answer to a payment order the caller may
// not see.
func transactionNotFound() *echo.HTTPError {
	return apiError(http.StatusNotFound, CodeNotFound, "transaction not found")
}

// issueSession stores a new session for one account and returns the printed
// token together with its CSRF token and expiry.
func issueSession(ctx context.Context, queries *database.Queries, userID int64) (token, csrf string, expires time.Time, err error) {
	now := time.Now().UTC()
	// Housekeeping at the one moment a session is created keeps the table from
	// growing without a separate scheduled job.
	if err := queries.DeleteExpiredSessions(ctx, models.NewUTCTime(now.Add(-SessionLifetime))); err != nil {
		return "", "", time.Time{}, err
	}
	token, selector, digest, err := newCredential(sessionPrefix)
	if err != nil {
		return "", "", time.Time{}, err
	}
	// The CSRF token is a second, independent secret of the same session. It
	// is not a credential on its own: presenting it without the session token
	// authenticates nothing.
	csrf, csrfDigest, err := newSecret()
	if err != nil {
		return "", "", time.Time{}, err
	}
	expires = now.Add(SessionLifetime)
	if err := queries.CreateSession(ctx, database.CreateSessionParams{
		Selector:     selector,
		VerifierHash: digest,
		CsrfHash:     csrfDigest,
		UserID:       userID,
		CreatedAt:    models.NewUTCTime(now),
		ExpiresAt:    models.NewUTCTime(expires),
	}); err != nil {
		return "", "", time.Time{}, err
	}
	return token, csrf, expires, nil
}

// issueAccountCredentials mints and stores a fresh account key and recovery
// code for one account, replacing whatever it had.
func (h *Handler) issueAccountCredentials(ctx context.Context, userID int64) (accountKey, recoveryCode string, err error) {
	// One transaction, so an account never ends up with a new account key and
	// the recovery code of the credentials it replaced.
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback()
	accountKey, recoveryCode, err = storeAccountCredentials(ctx, database.New(tx), userID)
	if err != nil {
		return "", "", err
	}
	if err := tx.Commit(); err != nil {
		return "", "", err
	}
	return accountKey, recoveryCode, nil
}

// storeAccountCredentials replaces both credentials within the caller's transaction.
func storeAccountCredentials(ctx context.Context, queries *database.Queries, userID int64) (accountKey, recoveryCode string, err error) {
	now := models.NewUTCTime(time.Now().UTC())
	for _, credential := range []struct {
		prefix string
		kind   string
		out    *string
	}{
		{accountPrefix, credentialAccount, &accountKey},
		{recoveryPrefix, credentialRecovery, &recoveryCode},
	} {
		token, selector, digest, err := newCredential(credential.prefix)
		if err != nil {
			return "", "", err
		}
		if err := queries.UpsertUserCredential(ctx, database.UpsertUserCredentialParams{
			UserID:     userID,
			Kind:       credential.kind,
			Selector:   selector,
			SecretHash: digest,
			CreatedAt:  now,
		}); err != nil {
			return "", "", err
		}
		*credential.out = token
	}
	return accountKey, recoveryCode, nil
}

// lookupCredential verifies a presented account key or recovery code. The
// account it names is the only account it can ever name.
func lookupCredential(ctx context.Context, queries *database.Queries, prefix, kind, presented string) (database.GetUserCredentialRow, bool) {
	selector, verifier, ok := parseCredential(prefix, presented)
	if !ok {
		return database.GetUserCredentialRow{}, false
	}
	row, err := queries.GetUserCredential(ctx, database.GetUserCredentialParams{
		Selector: selector,
		Kind:     kind,
	})
	if err != nil || !verifierMatches(row.SecretHash, verifier) {
		return database.GetUserCredentialRow{}, false
	}
	return row, true
}

// writeSessionCookies installs the session and CSRF cookies of a browser
// client. The session cookie is HttpOnly and SameSite=Strict; the CSRF cookie
// is deliberately readable, because the console has to repeat its value in a
// request header.
//
// Secure comes from what this dispatcher knows about its own transport, never
// from the request: X-Forwarded-Proto and its relatives are set by whoever
// sent the request, so a request cannot be trusted to describe its own scheme.
// See CookieSecure.
func (h *Handler) writeSessionCookies(c echo.Context, token, csrf string, expires time.Time) {
	c.SetCookie(&http.Cookie{
		Name: sessionCookieName, Value: token, Path: "/", Expires: expires,
		HttpOnly: true, Secure: h.cookieSecure, SameSite: http.SameSiteStrictMode,
	})
	c.SetCookie(&http.Cookie{
		Name: csrfCookieName, Value: csrf, Path: "/", Expires: expires,
		HttpOnly: false, Secure: h.cookieSecure, SameSite: http.SameSiteStrictMode,
	})
}

// clearSessionCookies removes both cookies of a logged-out browser client.
func (h *Handler) clearSessionCookies(c echo.Context) {
	for _, name := range []string{sessionCookieName, csrfCookieName} {
		c.SetCookie(&http.Cookie{
			Name: name, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: name == sessionCookieName, Secure: h.cookieSecure, SameSite: http.SameSiteStrictMode,
		})
	}
}
