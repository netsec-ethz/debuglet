package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/netsec-ethz/debuglet/internal/connections"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

const loginUsage = `Usage:
  dbl [--dispatcher NAME] login [--account-key-file FILE] [--register NAME]
      [--recovery-file FILE]
  dbl [--dispatcher NAME] logout

Obtain a session for the selected dispatcher and store it for that connection.
Without --account-key-file, the key is read from the DEBUGLET_ACCOUNT_KEY
environment variable; with neither, a dispatcher serving the local development
profile issues a credential for its own local account.

--register NAME first creates an account on the selected dispatcher. Its two
credentials are written, never printed, to owner-only files that must not exist
yet: the account key to --account-key-file (default account-key-PROFILE.txt
beside the connections file) and the recovery code to --recovery-file (default
recovery-PROFILE.txt). Keep both; the dispatcher cannot show either again.

Only the session is stored, in credentials.json beside the connections file,
mode 0600, and it is only ever sent to the endpoint it was issued for. logout
revokes the session at the dispatcher and forgets it locally.
`

// accountKeyEnv names the environment variable an account key may be supplied
// in, so that it does not appear in the process arguments of this machine.
const accountKeyEnv = "DEBUGLET_ACCOUNT_KEY"

// maxAccountKeyFile bounds the account key file that is read.
const maxAccountKeyFile = 4096

func loginCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer) int {
	fs := newCommandFlagSet("login")
	keyFile := fs.String("account-key-file", "", "file holding the account key, or receiving it with --register")
	register := fs.String("register", "", "create an account with this name first")
	recoveryFile := fs.String("recovery-file", "", "file the new account's recovery code is written to")
	if code, ok := parseCommandFlags(fs, args, loginUsage, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() != 0 {
		return usageError("dbl login", loginUsage, stderr, "login takes no positional arguments; supply a key with --account-key-file")
	}
	if *recoveryFile != "" && *register == "" {
		return usageError("dbl login", loginUsage, stderr, "--recovery-file only applies to --register")
	}

	c, profile, code, ok := connectProfileWithoutCredential("dbl login", options, stderr)
	if !ok {
		return code
	}
	if profile.Name == "" {
		return usageError("dbl login", loginUsage, stderr,
			"login stores a credential for a saved connection; run dbl connect URL first, or select one with --dispatcher NAME")
	}
	// Validate the store before issuing a new session. Endpoint mismatch does
	// not matter here, but invalid JSON or unsafe permissions must not turn a
	// successful remote login into an avoidable local persistence failure.
	if _, err := connections.LoadCredentials(options.ConfigPath); err != nil {
		return reportFailure(ctx, "dbl login: read credential store", stderr, err)
	}

	accountKey := ""
	switch {
	case *register != "":
		keyDestination, err := reserveIssuedCredential(options.ConfigPath, "account-key-"+profile.Name+".txt", *keyFile)
		if err != nil {
			return reportFailure(ctx, "dbl login: reserve account key", stderr, err)
		}
		recoveryDestination, err := reserveIssuedCredential(options.ConfigPath, "recovery-"+profile.Name+".txt", *recoveryFile)
		if err != nil {
			keyDestination.discard()
			return reportFailure(ctx, "dbl login: reserve recovery code", stderr, err)
		}
		account, err := c.CreateAccount(ctx, *register)
		if err != nil {
			keyDestination.discard()
			recoveryDestination.discard()
			return reportFailure(ctx, "dbl login: create account", stderr, err)
		}
		// Both issued credentials go to owner-only files the command names.
		// Neither is printed, and neither is kept in the credential store: a
		// copy of that store must not be permanent access to the account.
		keyPath, err := keyDestination.write(account.AccountKey)
		if err != nil {
			recoveryDestination.discard()
			return reportFailure(ctx, "dbl login: store account key", stderr, err)
		}
		recoveryPath, err := recoveryDestination.write(account.RecoveryCode)
		if err != nil {
			return reportFailure(ctx, "dbl login: store recovery code", stderr,
				fmt.Errorf("account was created and its account key is available at %s, but the recovery code could not be stored: %w", keyPath, err))
		}
		accountKey = account.AccountKey
		notice := stdout
		if options.Output == outputJSON {
			notice = stderr
		}
		if _, err := fmt.Fprintf(notice, "Account %s created. Account key written to %s and recovery code to %s; keep both, neither is shown again.\n",
			account.Name, keyPath, recoveryPath); err != nil {
			return reportFailure(ctx, "dbl login", stderr, err)
		}
	case *keyFile != "":
		key, err := readAccountKey(*keyFile)
		if err != nil {
			return reportFailure(ctx, "dbl login: read account key", stderr, err)
		}
		accountKey = key
	default:
		accountKey = strings.TrimSpace(os.Getenv(accountKeyEnv))
	}

	session, err := c.Login(ctx, accountKey)
	if err != nil {
		return reportFailure(ctx, "dbl login", stderr, loginHint(err))
	}
	if err := connections.SaveCredential(options.ConfigPath, profile.Name, connections.Credential{
		Endpoint:  profile.Endpoint,
		Token:     session.Token,
		ExpiresAt: session.ExpiresAt,
	}); err != nil {
		return reportFailure(ctx, "dbl login: store credential", stderr, err)
	}
	// Nothing printed here is a credential: the session token and the account
	// key stay in the owner-only credential file.
	return emitReported(ctx, "dbl login", options.Output, stdout, stderr, map[string]any{
		"dispatcher": profile.Name,
		"endpoint":   profile.Endpoint,
		"account":    session.Name,
		"role":       session.Role,
		"expires_at": session.ExpiresAt,
	}, func(w io.Writer) error {
		_, err := fmt.Fprintf(w, "Logged in to %s (%s) as %s.\nTry: dbl executor list\n", profile.Name, profile.Endpoint, session.Name)
		return err
	})
}

func logoutCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer) int {
	fs := newCommandFlagSet("logout")
	if code, ok := parseCommandFlags(fs, args, loginUsage, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() != 0 {
		return usageError("dbl logout", loginUsage, stderr, "logout takes no arguments")
	}
	profile, err := selectedProfile(options)
	if err != nil {
		return reportFailure(ctx, "dbl logout", stderr, err)
	}
	if profile.Name == "" {
		return usageError("dbl logout", loginUsage, stderr,
			"logout ends the session of a saved connection; select one with --dispatcher NAME")
	}
	credential, err := connections.CredentialFor(options.ConfigPath, profile.Name, profile.Endpoint)
	mismatched := errors.Is(err, connections.ErrCredentialEndpointMismatch)
	if err != nil && !mismatched {
		return reportFailure(ctx, "dbl logout", stderr, err)
	}
	c, err := newClient(profile.Endpoint, client.Options{RequestTimeout: options.Timeout, Credential: credential.Token})
	if err != nil {
		return usageError("dbl logout", loginUsage, stderr, "%v", err)
	}
	// The local credential is forgotten whatever the dispatcher answers: a
	// session that cannot be revoked remotely must not stay on this machine.
	var revokeErr error
	if !mismatched && credential.Token != "" {
		revokeErr = c.Logout(ctx)
	}
	if err := connections.RemoveCredential(options.ConfigPath, profile.Name); err != nil {
		return reportFailure(ctx, "dbl logout: forget credential", stderr, err)
	}
	if revokeErr != nil && !alreadyUnauthenticated(revokeErr) {
		return reportFailure(ctx, "dbl logout", stderr, revokeErr)
	}
	return emitReported(ctx, "dbl logout", options.Output, stdout, stderr,
		map[string]any{"dispatcher": profile.Name, "endpoint": profile.Endpoint, "logged_out": true},
		func(w io.Writer) error { _, err := fmt.Fprintf(w, "Logged out of %s.\n", profile.Endpoint); return err })
}

// authenticationRequired reports the dispatcher's authentication failure, the
// one a client answers by obtaining a credential.
func authenticationRequired(err error) bool {
	var httpErr *client.HTTPError
	if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusUnauthorized {
		return true
	}
	var submission *client.SubmissionError
	return errors.As(err, &submission) && errors.As(submission.Err, &httpErr) && httpErr.StatusCode == http.StatusUnauthorized
}

// alreadyUnauthenticated reports a logout that found no session to revoke,
// which is the state logout asks for rather than a failure.
func alreadyUnauthenticated(err error) bool {
	var httpErr *client.HTTPError
	return errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusUnauthorized
}

// loginHint turns the dispatcher's authentication failure into the action its
// operator has to take. The SDK's diagnostic is kept; nothing is added that
// could carry a credential.
func loginHint(err error) error {
	var httpErr *client.HTTPError
	if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("%w\nsupply an account key with --account-key-file or %s, or create one with --register NAME", err, accountKeyEnv)
	}
	return err
}

// readAccountKey reads a key from a file the operator named, so that it never
// appears in this machine's process arguments.
func readAccountKey(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > maxAccountKeyFile {
		return "", errors.New("account key file must be a regular file no larger than 4 KiB")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	key := strings.TrimSpace(string(data))
	if key == "" {
		return "", errors.New("account key file is empty")
	}
	return key, nil
}

// writeIssuedCredential stores one just-issued credential where only its owner
// can read it, rather than printing it into a terminal, a shell history or a CI
// log. Exclusive creation with owner-only permissions keeps it from being world
// readable for an instant, or from overwriting credentials still in use.
type issuedCredentialDestination struct {
	path string
	file *os.File
}

func reserveIssuedCredential(configPath, defaultName, chosen string) (*issuedCredentialDestination, error) {
	path := chosen
	if path == "" {
		connectionsFile := configPath
		if connectionsFile == "" {
			resolved, err := connections.DefaultPath()
			if err != nil {
				return nil, err
			}
			connectionsFile = resolved
		}
		path = filepath.Join(filepath.Dir(connectionsFile), defaultName)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, connections.CredentialFileMode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("%s already exists; name another file or move the credentials it holds", path)
		}
		return nil, err
	}
	return &issuedCredentialDestination{path: path, file: file}, nil
}

func (d *issuedCredentialDestination) write(secret string) (string, error) {
	if d == nil || d.file == nil {
		return "", errors.New("credential destination is not reserved")
	}
	file := d.file
	d.file = nil
	_, writeErr := file.WriteString(secret + "\n")
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		_ = os.Remove(d.path)
		return "", err
	}
	return d.path, nil
}

func (d *issuedCredentialDestination) discard() {
	if d == nil {
		return
	}
	if d.file != nil {
		_ = d.file.Close()
		d.file = nil
	}
	_ = os.Remove(d.path)
}

func writeIssuedCredential(configPath, defaultName, chosen, secret string) (string, error) {
	destination, err := reserveIssuedCredential(configPath, defaultName, chosen)
	if err != nil {
		return "", err
	}
	path, err := destination.write(secret)
	if err != nil {
		destination.discard()
		return "", err
	}
	return path, nil
}
