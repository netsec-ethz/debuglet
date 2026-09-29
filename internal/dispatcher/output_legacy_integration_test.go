// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/testpeer"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type outputVersionPeer struct {
	pb.UnimplementedExecutorServiceServer
	version uint32
}

func (p *outputVersionPeer) Hello(context.Context, *pb.HelloRequest) (*pb.HelloResponse, error) {
	return &pb.HelloResponse{ExecutorId: "output-executor", Version: "frame-test", Currency: "TEST", PricePerBwS: 1, OutputVersion: p.version}, nil
}

func TestOutputStreamLegacyFrameCompatibility(t *testing.T) {
	payload := bytes.Repeat([]byte{0, 1, 127, 255}, 8192)
	for _, tc := range []struct {
		name    string
		version uint32
		cap     string
		want    codes.Code
	}{
		{name: "legacy 32 KiB"},
		{name: "v1 32 KiB", version: pb.OutputVersion, want: codes.InvalidArgument},
		{name: "legacy run cap", cap: "run", want: codes.ResourceExhausted},
		{name: "legacy account cap", cap: "account", want: codes.ResourceExhausted},
		{name: "legacy node cap", cap: "node", want: codes.ResourceExhausted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newTerminalPeerDispatcher(t)
			limits := config.DefaultOutputConfig()
			charge := int64(pb.OutputRunCharge + pb.OutputFrameCharge + len(payload))
			switch tc.cap {
			case "run":
				limits.RunBytes = int64(len(payload))
			case "account":
				limits.AccountBytes = charge
			case "node":
				limits.NodeBytes = charge
			}
			if err := d.ConfigureOutputLimits(limits); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			transport, err := testpeer.Start(ctx, d.Bidi, &outputVersionPeer{version: tc.version})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
				defer stop()
				if err := transport.Stop(cleanup); err != nil {
					t.Error(err)
				}
			})
			if err := transport.Client.WaitReadyContext(ctx); err != nil {
				t.Fatal(err)
			}
			d.mu.RLock()
			owner := d.executors["output-executor"].owner
			d.mu.RUnlock()
			original := &pb.ControlBinding{DispatcherIncarnation: owner.Binding().Incarnation, SessionId: owner.Binding().SessionID}
			writer, err := outputWriterFor(owner, original)
			if err != nil {
				t.Fatal(err)
			}
			if writer.version != tc.version {
				t.Fatalf("negotiated version %d, want %d", writer.version, tc.version)
			}
			id := outputTestRun(t, d, writer, nil)
			client, err := transport.Client.ClientFor(owner.Binding())
			if err != nil {
				t.Fatal(err)
			}
			stream, err := client.DebugletStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			ident := &pb.DebugletIdent{DebugletId: id.String(), ExecutorId: owner.ExecutorID()}
			if tc.version != 0 {
				ident.OriginalBinding = original
			}
			if err := stream.Send(&pb.DebugletStreamRequest{Msg: &pb.DebugletStreamRequest_Ident{Ident: ident}}); err != nil {
				t.Fatal(err)
			}
			if tc.version != 0 {
				if receipt, err := stream.Recv(); err != nil || receipt.CommittedSequence != 0 || receipt.End != nil {
					t.Fatalf("identity receipt: %v %v", receipt, err)
				}
			}
			frames := 1
			if tc.cap != "" {
				frames = 2
			}
			for i := range frames {
				frame := &pb.DebugletOutput{Timestamp: timestamppb.New(time.Unix(123, 456)), Output: payload}
				if tc.version != 0 {
					frame.Sequence = int64(i + 1)
				}
				if err := stream.Send(&pb.DebugletStreamRequest{Msg: &pb.DebugletStreamRequest_Output{Output: frame}}); err != nil {
					t.Fatal(err)
				}
			}
			if err := stream.CloseSend(); err != nil {
				t.Fatal(err)
			}
			_, err = stream.Recv()
			if tc.want == codes.OK {
				if err != io.EOF {
					t.Fatalf("legacy close: %v", err)
				}
			} else if status.Code(err) != tc.want {
				t.Fatalf("stream error: %v, want %s", err, tc.want)
			}
			q := database.New(d.db)
			logs, err := q.ListDebugletLogs(ctx, database.ListDebugletLogsParams{Uuid: id, Limit: 10})
			if err != nil {
				t.Fatal(err)
			}
			row, err := q.GetDebugletOutput(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			usage, err := q.GetOutputNodeUsage(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if tc.version != 0 {
				if len(logs) != 0 || row.ByteCount != 0 || row.CommittedSequence != 0 || row.FinalSequence.Valid || usage.ChargedBytes != pb.OutputRunCharge {
					t.Fatalf("oversized v1 frame committed: logs=%d row=%+v usage=%+v", len(logs), row, usage)
				}
				return
			}
			if len(logs) != 1 || !bytes.Equal(logs[0].Output, payload) || logs[0].SourceSequence.Valid || row.ByteCount != int64(len(payload)) || row.CommittedSequence != 0 || usage.ChargedBytes != charge {
				t.Fatalf("legacy bytes or accounting changed: logs=%d row=%+v usage=%+v", len(logs), row, usage)
			}
			if tc.cap == "" {
				if row.OutputVersion != 0 || row.FinalSequence.Valid || row.FinalCursor.Valid || row.Status != "pending" {
					t.Fatalf("legacy output acquired finality: %+v", row)
				}
			} else {
				reason := pb.OutputReasonStorageLimit
				if tc.cap == "run" {
					reason = pb.OutputReasonLimit
				}
				if row.Status != "truncated" || !row.FinalCursor.Valid || row.FinalCursor.Int64 != logs[0].ID || row.Reason != reason {
					t.Fatalf("cap lost accepted prefix: %+v", row)
				}
			}
		})
	}
}
