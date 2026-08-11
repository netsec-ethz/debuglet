package api

import (
	"bytes"
	"crypto/md5"
	"encoding/gob"
	"encoding/hex"
)

func hashDebugletRequest(debuglets []DebugletRequest) string {
	var b bytes.Buffer
	gob.NewEncoder(&b).Encode(debuglets)
	hash := md5.Sum(b.Bytes())
	return hex.EncodeToString(hash[:])
}
