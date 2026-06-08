package transport

import (
	"context"
	"crypto/tls"
	"debuglet/internal/executor/config"
	pb "debuglet/protocol"
	"fmt"
	"io"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type ControlClient struct {
	client     pb.DispatcherServiceClient
	stream     grpc.BidiStreamingClient[pb.ExecutorControlMessage, pb.DispatcherControlMessage]
	logger     *zap.Logger
	handler    ControlHandler
	streamOpen chan struct{}

	// handles concurrent sending of messages
	sendCh chan *pb.ExecutorControlMessage
	done   chan struct{}
}

func NewControlClient(cfg *config.Config, l *zap.Logger, h ControlHandler) (*ControlClient, error) {
	creds, err := getClientCredentials(cfg)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(cfg.DispatcherAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}
	l.Info("Connected to dispatcher", zap.String("address", cfg.DispatcherAddr))
	client := pb.NewDispatcherServiceClient(conn)

	return &ControlClient{
		client:     client,
		logger:     l,
		handler:    h,
		streamOpen: make(chan struct{}, 1),
		sendCh:     make(chan *pb.ExecutorControlMessage, 32),
		done:       make(chan struct{}),
	}, nil
}

// Wait blocks until the stream has successfully opened
func (c *ControlClient) Wait(ctx context.Context) error {
	if c.stream != nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-c.streamOpen:
	}
	return nil
}

func getClientCredentials(cfg *config.Config) (credentials.TransportCredentials, error) {
	// Load client certificate
	cert, err := tls.LoadX509KeyPair(
		cfg.Credentials.ClientCert,
		cfg.Credentials.ClientKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // skip server cert verification - insecure! TODO: server authentication
		// RootCAs:      nil,
		// ClientCAs:  nil,
		// ClientAuth: tls.RequireAndVerifyClientCert,
		// MinVersion: tls.VersionTLS13,
	}

	creds := credentials.NewTLS(tlsConfig)
	return creds, nil
}

func (c *ControlClient) Listen(ctx context.Context) error {
	stream, err := c.client.ControlStream(ctx)
	if err != nil {
		return err
	}
	c.stream = stream
	go c.sendLoop()
	c.streamOpen <- struct{}{}

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			c.logger.Info("Control stream closed", zap.Error(err))
			return nil
		}
		if err != nil {
			c.logger.Error("Error receiving", zap.Error(err))
			return err
		}

		switch m := msg.GetMsg().(type) {
		case *pb.DispatcherControlMessage_Upload:
			debuglet := m.Upload
			var startTime *time.Time
			if st := debuglet.GetStartTime(); st != nil {
				tmp := st.AsTime()
				startTime = &tmp
			}
			// TODO: return error
			go c.handler.HandleUpload(Upload{
				DebugletID: debuglet.GetId(),
				StartTime:  startTime,
				Wasm:       debuglet.GetWasm(),
				Policy: DebugletPolicy{
					FloorBW:   debuglet.Policy.GetFloorBw(),
					CeilBW:    debuglet.Policy.GetCeilBw(),
					Timeout:   time.Duration(debuglet.Policy.GetTimeoutMs()) * time.Millisecond,
					Addresses: debuglet.Policy.GetAddresses(),
				},
			})
		case nil:
			c.logger.Warn("received control message with empty msg")
		default:
			c.logger.Warn("unknown control message type", zap.Any("type", m))
		}

	}
}
