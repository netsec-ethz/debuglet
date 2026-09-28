package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// A retained installation record alone does not own a replacement unit.
func (i *Installer) verifyRemoval(ctx context.Context, p Profile) error {
	info, err := os.Lstat(p.UnitPath)
	if err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("refusing to remove replaced unit %s: not a regular file", p.UnitPath)
		}
		want, err := Unit(p)
		if err != nil {
			return err
		}
		if info.Size() != int64(len(want)) {
			return fmt.Errorf("refusing to stop or remove modified unit %s; restore the managed definition first", p.UnitPath)
		}
		got, err := os.ReadFile(p.UnitPath)
		if err != nil {
			return err
		}
		if string(got) != want {
			return fmt.Errorf("refusing to stop or remove modified unit %s; restore the managed definition first", p.UnitPath)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	state, err := i.manager.State(ctx, p.Unit)
	if err != nil {
		return err
	}
	if state.Loaded && (state.FragmentPath != p.UnitPath || state.DropInPaths != "") {
		return fmt.Errorf("refusing to remove %s: the manager loaded another definition or unit overrides", p.Unit)
	}
	if !state.Stopped() && info == nil {
		return fmt.Errorf("refusing to stop %s without its managed unit file", p.Unit)
	}
	// RemoveAll does not follow the final symlink, but an earlier symlink
	// could redirect deletion into another role's directory.
	for path := p.StateDir; path != p.Root && path != filepath.Dir(path); path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("refusing removal through non-directory %s", path)
		}
	}
	return nil
}
