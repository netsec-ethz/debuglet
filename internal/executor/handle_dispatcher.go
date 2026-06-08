package executor

import (
	"debuglet/internal/executor/transport"
)

func (e *Executor) HandleUpload(upload transport.Upload) error {
	return e.storage.Insert(upload)
}
