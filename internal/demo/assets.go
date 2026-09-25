package demo

import (
	"errors"
	"path/filepath"

	"github.com/netsec-ethz/debuglet/internal/artifact"
)

// ResolveAssets follows the entry-point symlink once, then verifies the exact
// installed payload. Neither PATH nor the current directory supplies assets.
func ResolveAssets(executable string) (Assets, error) {
	var assets Assets
	if !filepath.IsAbs(executable) {
		return assets, errors.New("installed executable path must be absolute")
	}
	real, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return assets, err
	}
	if filepath.Base(real) != "dbl" || filepath.Base(filepath.Dir(real)) != "bin" {
		return assets, errors.New("dbl is not in an installed bin directory")
	}
	root := filepath.Dir(filepath.Dir(real))
	manifest, err := artifact.Verify(root)
	if err != nil {
		return assets, err
	}
	return Assets{Root: root, CLI: real, Dispatcher: filepath.Join(root, "bin", "debuglet-dispatcher"), Executor: filepath.Join(root, "bin", "debuglet-executor"), Guest: filepath.Join(root, "share", "debuglet", "demo.wasm"), Manifest: manifest}, nil
}
