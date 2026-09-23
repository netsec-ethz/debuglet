package api

import (
	"context"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

// Direct registry/payment unit fixtures explicitly own a session. Actual wire
// admission is exercised by the SDK/CLI peer and session integration fixtures.
func apiTestOwner(t *testing.T, d *dispatcher.Dispatcher, id string) *rpc.SessionOwner {
	t.Helper()
	binding, err := controlsession.NewBinding(d.ControlIncarnation())
	if err != nil {
		t.Fatal(err)
	}
	owner, err := rpc.NewSessionOwner(id, binding, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Retire() })
	return owner
}

// apiTestRegister registers an executor the way the control transport does: it
// admits the one setup operation the registration runs under and finishes that
// operation once the registration has returned.
func apiTestRegister(ctx context.Context, d *dispatcher.Dispatcher, owner *rpc.SessionOwner, hello *pb.HelloResponse, sourceIP string) error {
	setup, err := owner.AdmitSetup(ctx)
	if err != nil {
		return err
	}
	defer setup.Finish()
	return d.RegisterExecutor(setup.Context(), owner, hello, sourceIP)
}

func apiTestMutation(t *testing.T, ctx context.Context, owner *rpc.SessionOwner) *rpc.Mutation {
	t.Helper()
	mutation, err := owner.AdmitMutation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return mutation // caller finishes at the actual operation boundary
}
