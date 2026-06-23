package rpc

import (
	"context"
	"crypto/tls"
	"debuglet/internal/executor/config"
	"debuglet/internal/executor/ratelimit/app"
	pb "debuglet/protocol"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type ControlClient struct {
	client  pb.DispatcherServiceClient
	stream  pb.DispatcherService_ControlStreamClient
	logger  *zap.Logger
	handler ExecutorControlHandler

	streamReady chan struct{} // Closed when stream is listening

	// handles concurrent sending of messages
	sendCh    chan *pb.ExecutorControlMessage
	done      chan struct{}
	closeOnce sync.Once
}

func NewControlClient(cfg *config.Config, l *zap.Logger, h ExecutorControlHandler) (*ControlClient, error) {
	var grpcOpts []grpc.DialOption
	if cfg.DisableTLS {
		l.Info("TLS disabled, using insecure connection to dispatcher")
		grpcOpts = append(grpcOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		creds, err := getClientCredentials(cfg)
		if err != nil {
			return nil, err
		}
		grpcOpts = append(grpcOpts, grpc.WithTransportCredentials(creds))
	}
	grpcOpts = append(grpcOpts,
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(32*1024*1024),
			grpc.MaxCallSendMsgSize(32*1024*1024),
		),
	)
	conn, err := grpc.NewClient(cfg.DispatcherAddr, grpcOpts...)
	if err != nil {
		return nil, err
	}

	l.Info("Connected to dispatcher", zap.String("address", cfg.DispatcherAddr))
	client := pb.NewDispatcherServiceClient(conn)

	return &ControlClient{
		client:      client,
		logger:      l,
		handler:     h,
		streamReady: make(chan struct{}),
		sendCh:      make(chan *pb.ExecutorControlMessage, 32),
		done:        make(chan struct{}),
	}, nil
}

func (c *ControlClient) GRPCClient() *pb.DispatcherServiceClient {
	return &c.client
}

// Ready returns a channel which is closed and falls through when the client has opened the stream and is listening
func (c *ControlClient) Ready() <-chan struct{} {
	return c.streamReady
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
	close(c.streamReady)

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			c.logger.Info("Control stream closed", zap.Error(err))
			return nil
		}
		if err != nil {
			if ctx.Err() != nil {
				return context.Cause(ctx)
			}
			c.logger.Error("Error receiving", zap.Error(err))
			return err
		}

		c.logger.Debug("Received control message", zap.String("messageType", reflect.TypeOf(msg.GetMsg()).String()))

		switch m := msg.GetMsg().(type) {
		case *pb.DispatcherControlMessage_Upload:
			debuglet := m.Upload
			var startTime *time.Time
			if st := debuglet.GetStartTime(); st != nil {
				tmp := st.AsTime().UTC()
				startTime = &tmp
			}
			go c.handler.HandleUpload(ctx, Spec{
				DebugletID: debuglet.GetId(),
				StartTime:  startTime,
				Args:       debuglet.GetArgs(),
				Wasm:       debuglet.GetWasm(),
				Policy: Policy{
					FloorBW:   debuglet.Policy.GetFloorBw(),
					CeilBW:    debuglet.Policy.GetCeilBw(),
					Timeout:   time.Duration(debuglet.Policy.GetTimeoutMs()) * time.Millisecond,
					Addresses: debuglet.Policy.GetAddresses(),
				},
			})
		case *pb.DispatcherControlMessage_Abort:
			go c.handler.HandleAbort(ctx, m.Abort.GetDebugletId(), m.Abort.GetReason())
		case *pb.DispatcherControlMessage_Updates:
			var updates []Update
			for _, up := range msg.GetUpdates().GetLimits() {
				updates = append(updates, Update{Address: up.GetAddress(), Limit: app.Bitrate(up.GetBitsLimit())})
			}
			go c.handler.HandleUpdate(ctx, updates)
		case nil:
			c.logger.Warn("received control message with empty msg")
		default:
			c.logger.Warn("unknown control message type", zap.Any("type", m))
		}

	}
}
