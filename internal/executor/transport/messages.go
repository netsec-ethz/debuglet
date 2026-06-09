package transport

import (
	"debuglet/pkg/tesla"
	pb "debuglet/protocol"
	"time"

	"go.uber.org/zap"
)

func (c *ControlClient) SendHeartbeat(schedule *tesla.KeySchedule) error {
	now := time.Now()
	epoch, key, _ := schedule.DisclosedKey(now)
	c.logger.Debug("Sending heartbeat", zap.Time("timestamp", now), zap.Int64("epoch", epoch))
	return c.Send(&pb.ExecutorControlMessage{
		Msg: &pb.ExecutorControlMessage_Heartbeat{Heartbeat: &pb.ExecutorHeartbeat{
			TimestampNs:   now.UnixNano(),
			TeslaKeyEpoch: epoch,
			TeslaKey:      key,
		}},
	})
}

func (c *ControlClient) SendHello(h Hello) error {
	c.logger.Debug("Sending 'hello'", zap.String("id", h.ExecutorID))
	return c.Send(&pb.ExecutorControlMessage{
		Msg: &pb.ExecutorControlMessage_Hello{Hello: &pb.ExecutorHello{
			ExecutorId:             h.ExecutorID,
			Version:                h.Version,
			SourceIp:               h.SourceIP,
			TeslaDelaySec:          int64(h.TeslaDelay.Seconds()),
			TeslaAnchorTimestampNs: h.TeslaAnchorTimestamp.UnixNano(),
			TeslaAnchorKey:         h.TeslaAnchorKey,
		}},
	})
}

func (c *ControlClient) SendError(debugletID *string, err error) error {
	c.logger.Debug("Sending 'error'", zap.Stringp("id", debugletID), zap.Error(err))
	return c.Send(&pb.ExecutorControlMessage{
		Msg: &pb.ExecutorControlMessage_Error{
			Error: &pb.ExecutorError{
				DebugletId: debugletID,
				Error:      err.Error(),
			},
		}},
	)
}
