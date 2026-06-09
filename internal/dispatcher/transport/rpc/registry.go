package rpc

import (
	"context"
	pb "debuglet/protocol"
	"sync"
)

type StreamRegistry struct {
	mu      sync.RWMutex
	streams map[string]*ExecutorConn
}

func (r *StreamRegistry) Register(id string, s pb.DispatcherService_ControlStreamServer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	conn := ExecutorConn{
		stream: s,
		sendCh: make(chan *pb.DispatcherControlMessage, 32),
		done:   make(chan struct{}),
	}
	old, exists := r.streams[id]
	if exists {
		old.Close()
	}

	r.streams[id] = &conn
	go conn.sendLoop()
}

func (r *StreamRegistry) Unregister(id string) {
	r.mu.Lock()
	conn, exists := r.streams[id]
	delete(r.streams, id)
	r.mu.Unlock()
	if exists {
		conn.Close()
	}
}

func (r *StreamRegistry) Get(id string) (*ExecutorConn, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.streams[id]
	return c, ok
}

// ExecutorConn manages an executor stream connection and ensures messages
// are sent while avoiding race-conditions
type ExecutorConn struct {
	stream    pb.DispatcherService_ControlStreamServer
	sendCh    chan *pb.DispatcherControlMessage
	done      chan struct{}
	closeOnce sync.Once
}

func (c *ExecutorConn) sendLoop() {
	defer close(c.done)
	for msg := range c.sendCh {
		if err := c.stream.Send(msg); err != nil {
			c.closeSendCh()
			return
		}
	}
}

func (c *ExecutorConn) Send(ctx context.Context, msg *pb.DispatcherControlMessage) error {
	select {
	case <-c.stream.Context().Done():
		return c.stream.Context().Err()
	case <-ctx.Done():
		return ctx.Err()
	case c.sendCh <- msg:
		return nil
	}
}

func (c *ExecutorConn) closeSendCh() {
	c.closeOnce.Do(func() {
		close(c.sendCh)
	})
}

func (c *ExecutorConn) Close() {
	c.closeSendCh()
	<-c.done
}
