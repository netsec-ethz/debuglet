package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/internal/connections"
	"github.com/netsec-ethz/debuglet/pkg/client"
)

const whoamiUsage = `Usage:
  dbl [--dispatcher NAME] whoami

Report the account ID, name and role of the selected saved session.
`

func whoamiCommand(ctx context.Context, args []string, options globalOptions, stdout, stderr io.Writer) int {
	fs := newCommandFlagSet("whoami")
	if code, ok := parseCommandFlags(fs, args, whoamiUsage, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() != 0 {
		return usageError("dbl whoami", whoamiUsage, stderr, "whoami takes no arguments")
	}
	profile, err := selectedProfile(options)
	if err != nil {
		return reportFailure(ctx, "dbl whoami", stderr, err)
	}
	credential, err := connections.CredentialFor(options.ConfigPath, profile.Name, profile.Endpoint)
	if err != nil {
		return reportFailure(ctx, "dbl whoami", stderr, err)
	}
	if credential.Token == "" {
		return reportFailure(ctx, "dbl whoami", stderr, errors.New("no saved credential; run dbl login"))
	}
	if credential.ExpiresAt > 0 && credential.ExpiresAt <= time.Now().Unix() {
		return reportFailure(ctx, "dbl whoami", stderr, errors.New("saved session has expired; run dbl login"))
	}
	c, err := newClient(profile.Endpoint, client.Options{RequestTimeout: options.Timeout, Credential: credential.Token})
	if err != nil {
		return reportFailure(ctx, "dbl whoami", stderr, err)
	}
	user, err := c.Whoami(ctx)
	if err != nil {
		if authenticationRequired(err) {
			err = errors.New("saved session has expired or been revoked; run dbl login")
		}
		return reportFailure(ctx, "dbl whoami", stderr, err)
	}
	if strings.Contains(user.ID+user.Name+user.Role, credential.Token) {
		return reportFailure(ctx, "dbl whoami", stderr, errors.New("dispatcher returned credential material in the account identity"))
	}
	return emitReported(ctx, "dbl whoami", options.Output, stdout, stderr, user, func(w io.Writer) error {
		_, err := fmt.Fprintf(w, "id: %s\nname: %s\nrole: %s\n", user.ID, user.Name, user.Role)
		return err
	})
}
