package demo

import (
	"errors"
	"io"
)

type ChildSpec struct {
	Path, Dir      string
	Args, Env      []string
	Stdout, Stderr io.Writer
}

// ErrForcedKill distinguishes cleanup that required SIGKILL from graceful exit.
var ErrForcedKill = errors.New("demo child required forced termination")
