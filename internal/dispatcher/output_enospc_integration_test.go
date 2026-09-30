// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux && output_integration

package dispatcher

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDispatcherPhysicalDiskFullPreservesCommittedPrefix(t *testing.T) {
	root := os.Getenv("DEBUGLET_OUTPUT_ENOSPC_ROOT")
	if !filepath.IsAbs(root) {
		t.Fatal("absolute private DEBUGLET_OUTPUT_ENOSPC_ROOT required")
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(root, &fs); err != nil {
		t.Fatal(err)
	}
	if fs.Type != unix.TMPFS_MAGIC || fs.Blocks == 0 || fs.Blocks*uint64(fs.Bsize) > 16<<20 {
		t.Fatal("requires private tmpfs no larger than 16 MiB")
	}
	dir, err := os.MkdirTemp(root, "dispatcher-full-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	// Existing TLS/database fixtures now live entirely on the private volume.
	t.Setenv("TMPDIR", dir)
	f := newOutputTLS(t)
	f.d.outputLimits.ControlReserveBytes = 4096 // This fixture's private filesystem is smaller than the deployment default.
	client, owner := f.connect(f.identity, true)
	original := owner.Binding()
	writer, err := outputWriterFor(owner, &pb.ControlBinding{DispatcherIncarnation: original.Incarnation, SessionId: original.SessionID})
	if err != nil {
		t.Fatal(err)
	}
	id := outputTestRun(t, f.d, writer, nil)
	stream := outputClientStream(t, f.ctx, client, id, original)
	if receipt, err := stream.Recv(); err != nil || receipt.CommittedSequence != 0 {
		t.Fatalf("identity: %v %v", receipt, err)
	}
	if err := stream.Send(&pb.DebugletStreamRequest{Msg: &pb.DebugletStreamRequest_Output{Output: outputFrame(1, "one")}}); err != nil {
		t.Fatal(err)
	}
	if receipt, err := stream.Recv(); err != nil || receipt.CommittedSequence != 1 {
		t.Fatalf("prefix: %v %v", receipt, err)
	}
	fillerPath := filepath.Join(dir, "filler")
	filler, err := os.OpenFile(fillerPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	block := make([]byte, 64<<10)
	for err == nil {
		_, err = filler.Write(block)
	}
	closeErr := filler.Close()
	if !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("no physical ENOSPC: %v", err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	t.Cleanup(func() { os.Remove(fillerPath) })
	frame := outputFrame(2, strings.Repeat("x", pb.MaxOutputFrameBytes))
	if err := stream.Send(&pb.DebugletStreamRequest{Msg: &pb.DebugletStreamRequest_Output{Output: frame}}); err != nil {
		t.Fatal(err)
	}
	receipt, receiveErr := stream.Recv()
	if receiveErr == nil {
		// The headroom guard can stop before SQLite needs another allocation.
		// If the finality record still fits, acknowledge only the durable prefix.
		if receipt == nil || receipt.CommittedSequence != 1 || receipt.GetEnd().GetLastSequence() != 1 || receipt.GetEnd().GetStatus() != pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_TRUNCATED || receipt.GetEnd().GetReason() != pb.OutputReasonStorageLimit {
			t.Fatalf("low-space finality invented output: %v", receipt)
		}
		row, err := database.New(f.d.db).GetDebugletOutput(t.Context(), id)
		if err != nil || row.CommittedSequence != 1 || row.FrameCount != 1 || row.ByteCount != 3 || !row.FinalSequence.Valid || row.FinalSequence.Int64 != 1 || row.Status != "truncated" || row.Reason != pb.OutputReasonStorageLimit {
			t.Fatalf("low-space finality was not durable: %+v %v", row, err)
		}
		usage, err := database.New(f.d.db).GetOutputNodeUsage(t.Context())
		if err != nil || usage.ChargedBytes != pb.OutputRunCharge+pb.OutputFrameCharge+3 {
			t.Fatalf("declined frame charged: %+v %v", usage, err)
		}
		return
	}
	if receipt != nil || status.Code(receiveErr) != codes.Unavailable {
		t.Fatalf("failed receiver write acknowledged: %v %v", receipt, receiveErr)
	}
	q := database.New(f.d.db)
	row, err := q.GetDebugletOutput(t.Context(), id)
	if err != nil || row.CommittedSequence != 1 || row.FrameCount != 1 || row.ByteCount != 3 || row.FinalSequence.Valid || row.Status != "pending" {
		t.Fatalf("disk failure invented prefix/finality: %+v %v", row, err)
	}
	usage, err := q.GetOutputNodeUsage(t.Context())
	if err != nil || usage.ChargedBytes != pb.OutputRunCharge+pb.OutputFrameCharge+3 {
		t.Fatalf("failed frame charged: %+v %v", usage, err)
	}
	if err := os.Remove(fillerPath); err != nil {
		t.Fatal(err)
	}
	stream = outputClientStream(t, f.ctx, client, id, original)
	if receipt, err := stream.Recv(); err != nil || receipt.CommittedSequence != 1 || receipt.End != nil {
		t.Fatalf("recovery receipt: %v %v", receipt, err)
	}
	if err := stream.Send(&pb.DebugletStreamRequest{Msg: &pb.DebugletStreamRequest_Output{Output: frame}}); err != nil {
		t.Fatal(err)
	}
	if receipt, err := stream.Recv(); err != nil || receipt.CommittedSequence != 2 || receipt.End != nil {
		t.Fatalf("retry receipt: %v %v", receipt, err)
	}
	end := &pb.DebugletOutputEnd{LastSequence: 2, Status: pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE}
	if err := stream.Send(&pb.DebugletStreamRequest{Msg: &pb.DebugletStreamRequest_End{End: end}}); err != nil {
		t.Fatal(err)
	}
	if receipt, err := stream.Recv(); err != nil || receipt.CommittedSequence != 2 || receipt.GetEnd().GetStatus() != end.Status {
		t.Fatalf("recovered finality: %v %v", receipt, err)
	}
	row, err = q.GetDebugletOutput(t.Context(), id)
	if err != nil || row.FrameCount != 2 || row.ByteCount != 3+pb.MaxOutputFrameBytes || !row.FinalCursor.Valid || row.Status != "complete" {
		t.Fatalf("recovery lost or duplicated output: %+v %v", row, err)
	}
}
