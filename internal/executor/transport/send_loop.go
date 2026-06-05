package transport

import (
	pb "debuglet/protocol"
	"sync"
)

// ensures concurrent messages are sent synchronously over the stream
func (c *ControlClient) sendLoop() {
	defer close(c.done)
	for msg := range c.sendCh {
		if err := c.stream.Send(msg); err != nil {
			c.closeSendCh()
			return
		}
	}
}

func (c *ControlClient) Send(msg *pb.ExecutorControlMessage) error {
	select {
	case <-c.stream.Context().Done():
		return c.stream.Context().Err()
	case c.sendCh <- msg:
		return nil
	}
}

func (c *ControlClient) closeSendCh() {
	sync.OnceFunc(func() {
		close(c.sendCh)
	})
}

func (c *ControlClient) Close() {
	c.closeSendCh()
	<-c.done
}
