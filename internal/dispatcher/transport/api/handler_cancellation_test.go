// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/pkg/client"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCancellationAfterLostHTTPResponse(t *testing.T) {
	f := ccNewFixture(t)
	sdk := f.client(f.root.URL, false)
	sub := f.submit(sdk, nil)
	id := sub.IDs[0]
	e := echo.New()
	NewHandler(f.d, f.db, zap.NewNop(), LocalDevelopment(true)).RegisterRoutes(e)
	// Complete the real route, then close the actual HTTP connection without
	// sending its successful response. The SDK must report uncertainty.
	dropping := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			e.ServeHTTP(w, r)
			return
		}
		reply := httptest.NewRecorder()
		e.ServeHTTP(reply, r)
		if reply.Code != http.StatusNoContent {
			t.Errorf("cancellation before dropped response: %d %s", reply.Code, reply.Body.String())
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = conn.Close()
	}))
	defer dropping.Close()
	lossy := f.client(dropping.URL, false)
	if err := lossy.Cancel(f.ctx, id, ccExecutorID); !client.IsTransportError(err) {
		t.Fatalf("lost response: %v", err)
	}
	first, err := sdk.Cancellation(f.ctx, id)
	if err != nil || first.Disposition != "acknowledged" || first.AcknowledgedAt == nil || first.State != client.StateExited {
		t.Fatalf("inspection: %+v, %v", first, err)
	}
	run, err := f.queries.GetDebugletByUUID(f.ctx, uuid.MustParse(id))
	if err != nil {
		t.Fatal(err)
	}
	if err := sdk.Cancel(f.ctx, id, ccExecutorID); err != nil {
		t.Fatal(err)
	}
	after, err := sdk.Cancellation(f.ctx, id)
	if err != nil || first.RequestID != after.RequestID || !first.AcknowledgedAt.Equal(*after.AcknowledgedAt) {
		t.Fatalf("retry changed request: %+v, %v", after, err)
	}
	stored, err := f.queries.GetDebugletByUUID(f.ctx, uuid.MustParse(id))
	if err != nil || !reflect.DeepEqual(stored, run) || f.peer.abortCount() != 1 {
		t.Fatalf("retry changed terminal/delivered again: %+v %v, aborts=%d", stored, err, f.peer.abortCount())
	}
}

func TestConcurrentCancellationRefusalCannotEraseAcknowledgement(t *testing.T) {
	f := ccNewFixture(t)
	sdk := f.client(f.root.URL, false)
	sub := f.submit(sdk, nil)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	f.peer.setAbortHook(func(ctx context.Context, _ *pb.AbortRequest) error {
		if calls.Add(1) != 1 {
			return nil
		}
		close(entered)
		select {
		case <-release:
			return status.Error(codes.NotFound, "already removed")
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	result := make(chan error, 1)
	go func() { result <- sdk.Cancel(f.ctx, sub.IDs[0], ccExecutorID) }()
	select {
	case <-entered:
	case <-f.ctx.Done():
		t.Fatal(f.ctx.Err())
	}
	err := sdk.Cancel(f.ctx, sub.IDs[0], ccExecutorID)
	close(release)
	firstErr := <-result
	if err != nil || firstErr == nil {
		t.Fatalf("concurrent outcomes: success=%v delayed=%v", err, firstErr)
	}
	doc, err := sdk.Cancellation(f.ctx, sub.IDs[0])
	if err != nil || doc.Disposition != "acknowledged" || doc.Reason != "" || doc.AcknowledgedAt == nil {
		t.Fatalf("late refusal downgraded ACK: %+v, %v", doc, err)
	}
	if err := sdk.Cancel(f.ctx, sub.IDs[0], ccExecutorID); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("retry resent acknowledged request: %d", calls.Load())
	}
}

func TestCancellationInspectionAuthorizationAndNoImplicitRequest(t *testing.T) {
	f := ccNewFixtureWith(t)
	_, ownToken, own := authAccount(t, f, "cancellation owner")
	_, otherToken, _ := authAccount(t, f, "other account")
	batch, err := client.Prepare([]client.Request{ccRequest([]string{"127.0.0.1:8080"})})
	if err != nil {
		t.Fatal(err)
	}
	sub, err := own.SubmitTEST(f.ctx, batch)
	if err != nil {
		t.Fatal(err)
	}
	id := sub.IDs[0]
	if _, err := own.Cancellation(f.ctx, id); !authIsNotFound(err) {
		t.Fatalf("inspection created request: %v", err)
	}
	if err := own.Cancel(f.ctx, id, ccExecutorID); err != nil {
		t.Fatal(err)
	}
	e := echo.New()
	NewHandler(f.d, f.db, zap.NewNop()).RegisterRoutes(e)
	for _, tc := range []struct {
		name, id, token string
		status          int
	}{
		{"owner", id, ownToken, http.StatusOK},
		{"other account", id, otherToken, http.StatusNotFound},
		{"anonymous", id, "", http.StatusUnauthorized},
		{"unknown", uuid.NewString(), ownToken, http.StatusNotFound},
		{"malformed", "not-a-uuid", ownToken, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/debuglet/"+tc.id+"/cancellation", nil)
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			response := httptest.NewRecorder()
			e.ServeHTTP(response, req)
			if response.Code != tc.status {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if response.Code == http.StatusOK {
				var doc client.CancellationDocument
				if err := json.Unmarshal(response.Body.Bytes(), &doc); err != nil || doc.ID != id || doc.AcknowledgedAt == nil {
					t.Fatalf("inspection: %+v, %v", doc, err)
				}
			}
		})
	}
	if f.peer.abortCount() != 1 {
		t.Fatal("inspection sent Abort")
	}
}
