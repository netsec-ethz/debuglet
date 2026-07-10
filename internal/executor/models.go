package executor

import (
	"debuglet/internal/executor/ratelimit/app"

	"go.uber.org/zap/zapcore"
)

type Update struct {
	Address string
	Limit   app.Bitrate
}

func (l Update) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("address", l.Address)
	enc.AddString("limit", l.Limit.String())
	return nil
}
