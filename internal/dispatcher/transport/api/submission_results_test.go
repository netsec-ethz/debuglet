// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/pkg/client"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestFailedSubmissionRetainsAdmittedIDs(t *testing.T) {
	for _, confirmed := range []bool{true, false} {
		name := "cancellation unresolved"
		if confirmed {
			name = "cancellation acknowledged"
		}
		t.Run(name, func(t *testing.T) {
			f := ccNewFixture(t)
			f.peer.setUploadHook(func(context.Context, *pb.UploadRequest) error {
				return errors.New("owned fixture upload failed")
			})
			if !confirmed {
				f.peer.setAbortHook(func(context.Context, *pb.AbortRequest) error {
					return status.Error(codes.Unavailable, "owned fixture cancellation unconfirmed")
				})
			}
			recorder := &oaRecorder{}
			sdk, err := client.New(f.root.URL, client.Options{HTTPClient: &http.Client{Transport: recorder}, RequestTimeout: ccRequestBound})
			if err != nil {
				t.Fatal(err)
			}
			batch, err := client.Prepare([]client.Request{ccRequest(nil)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = sdk.SubmitTEST(f.ctx, batch)
			var failure *client.SubmissionError
			var httpFailure *client.HTTPError
			if !errors.As(err, &failure) || !errors.As(err, &httpFailure) || !failure.OutcomeUnknown || failure.TransactionID == "" || len(failure.AdmittedIDs) != 1 || httpFailure.StatusCode != http.StatusInternalServerError || failure.Code() != client.CodeInternal {
				t.Fatalf("admission receipt lost: %v", err)
			}
			id := failure.AdmittedIDs[0]
			if uploaded := f.peer.lastUpload(); uploaded == nil || uploaded.GetId() != id || uploaded.GetTransactionId() != failure.TransactionID {
				t.Fatalf("receipt is not the admitted run: %+v", uploaded)
			}
			state, err := sdk.Status(f.ctx, id)
			want := models.RunStateUnreconciled.String()
			if confirmed {
				want = models.RunStateExited.String()
			}
			if err != nil || state.State != want {
				t.Fatalf("inspect admitted disposition: %+v %v, want %s", state, err, want)
			}
			if f.peer.uploadCount() != 1 || f.peer.abortCount() != 1 {
				t.Fatal("inspection replayed work or cancellation")
			}
			contract := oaContract(t)
			for _, exchange := range recorder.recorded() {
				oaCheckExchange(t, contract, exchange)
			}
		})
	}
}
