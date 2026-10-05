// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/api"
	"github.com/netsec-ethz/debuglet/internal/fsutil"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	"github.com/netsec-ethz/debuglet/internal/storagecheck"
)

func validateRecoveryFlags(flags *flag.FlagSet, recover, revoke, reference, output string) error {
	if (recover == "") == (revoke == "") || reference == "" || (recover != "") != (output != "") {
		return errors.New("use either -recover-unmapped-account UUID -recovery-case CASE -recovery-output FILE, or -revoke-account-recovery UUID -recovery-case CASE")
	}
	var invalid string
	flags.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "config", "recover-unmapped-account", "revoke-account-recovery", "recovery-case", "recovery-output":
		default:
			invalid = f.Name
		}
	})
	if invalid != "" || flags.NArg() != 0 {
		return errors.New("account recovery cannot be combined with other administration flags or arguments")
	}
	return nil
}

// administerAccountRecovery changes access to one existing account, never its
// ownership. The host administrator must independently verify the requester;
// the case reference records that decision, it does not prove identity itself.
func administerAccountRecovery(ctx context.Context, cfg *config.DispatcherConfig, account, reference, output string, revoke bool) (err error) {
	id, err := uuid.Parse(account)
	if err != nil {
		return fmt.Errorf("account identifier is not a UUID: %w", err)
	}
	if strings.TrimSpace(reference) != reference || reference == "" || len(reference) > 256 || strings.IndexFunc(reference, unicode.IsControl) >= 0 {
		return errors.New("recovery case must be a nonempty reference of at most 256 bytes without control characters")
	}
	if err := storagecheck.Check(ctx, storagecheck.Dispatcher, cfg.Database.Path); err != nil {
		return err
	}
	db, err := sqlitedb.Open(cfg.Database.Path)
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	queries := database.New(tx)
	changed, err := queries.LockAccountForRecovery(ctx, id)
	if err != nil {
		return err
	}
	if changed == 0 {
		return errors.New("account does not exist")
	}
	if revoke {
		selector, err := queries.RevokeAdminAccountRecovery(ctx, database.RevokeAdminAccountRecoveryParams{
			RevokedByUid: sql.NullInt64{Int64: int64(os.Geteuid()), Valid: true}, RevocationReference: reference, Uuid: id,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("account has no unused administrator recovery to revoke")
		}
		if err != nil {
			return err
		}
		if err := queries.DeleteAdminRecoveryCredential(ctx, selector); err != nil {
			return err
		}
		return tx.Commit()
	}
	user, err := queries.GetUnmappedAccountForRecovery(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("account already has credentials, a provider identity or a pending administrator recovery; ordinary recovery or explicit revocation is required")
	}
	if err != nil {
		return err
	}
	token, selector, digest, err := api.NewRecoveryCredential()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if err := queries.RecordAdminAccountRecovery(ctx, database.RecordAdminAccountRecoveryParams{
		Selector: selector, UserID: user.ID, CaseReference: reference, IssuedByUid: int64(os.Geteuid()),
		IssuedAt: now.Unix(), ExpiresAt: now.Add(24 * time.Hour).Unix(),
	}); err != nil {
		return fmt.Errorf("record recovery approval (case references must be unique): %w", err)
	}
	if err := queries.UpsertUserCredential(ctx, database.UpsertUserCredentialParams{
		UserID: user.ID, Kind: "recovery", Selector: selector, SecretHash: digest, CreatedAt: models.NewUTCTime(now),
	}); err != nil {
		return err
	}
	if err := queries.RevokeUserSessions(ctx, id); err != nil {
		return err
	}
	// Publish and sync the private file before committing a usable code. A
	// failure or crash before commit leaves no valid new credential in SQLite.
	if err := publishRecoveryCode(output, token); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("recovery commit did not confirm success: %w; private output retained at %s; inspect the audit and use -revoke-account-recovery %s before retrying with a new case", err, output, account)
	}
	return nil
}

func publishRecoveryCode(path, code string) (err error) {
	if !filepath.IsAbs(path) {
		return errors.New("recovery output must be an absolute path")
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("recovery output requires a real mode-0700 parent directory")
	}
	if err := recoveryDirectoryOwned(info); err != nil {
		return err
	}
	f, err := os.CreateTemp(parent, ".account-recovery-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, writeErr := fmt.Fprintln(f, code)
	if err := errors.Join(writeErr, f.Chmod(0600), f.Sync(), f.Close()); err != nil {
		return err
	}
	// Link publishes complete bytes without replacing an existing file or
	// following an output symlink. The parent stays under the operator's control.
	if err := os.Link(f.Name(), path); err != nil {
		return fmt.Errorf("publish recovery file: %w", err)
	}
	if err := fsutil.SyncDir(parent); err != nil {
		return errors.Join(err, os.Remove(path))
	}
	return nil
}
