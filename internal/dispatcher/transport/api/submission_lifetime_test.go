// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/testpeer"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func submissionWait(t *testing.T, ready <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ready:
	case <-time.After(ccRequestBound):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func submissionIntent(t *testing.T, f *ccFixture, executors ...string) SubmitDebugletsRequest {
	t.Helper()
	request := SubmitDebugletsRequest{}
	for i, executor := range executors {
		request.Debuglets = append(request.Debuglets, DebugletRequest{
			OrderID: int64(i), ExecutorID: executor, Wasm: base64.StdEncoding.EncodeToString(ccGuest),
			Policy: DebugletPolicyRequest{FloorBW: ccFloorBW, CeilBW: ccFloorBW, TimeoutMS: ccDurationMS},
		})
	}
	raw := &wfClient{t: t, base: f.root.URL, http: f.root.Client()}
	code, body := raw.do(http.MethodPut, "/payment/intent", PaymentIntentRequest{Debuglets: request.Debuglets, PaymentMethod: "TEST"})
	wfExpect(t, "intent", code, http.StatusOK, body)
	var intent struct {
		Intent DummyIntent `json:"intent"`
	}
	if err := json.Unmarshal(body, &intent); err != nil {
		t.Fatal(err)
	}
	request.TransactionId, request.AuthKey = intent.Intent.TransactionID, intent.Intent.AuthKey
	return request
}

// Disconnect a real HTTP client while one participant is already uploaded and
// another is awaiting acknowledgement. The admitted group belongs to the
// dispatcher, even when the browser cannot receive its submission receipt.
func TestSubmissionHTTPDisconnectAfterAdmission(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		name := "completes"
		if refuse {
			name = "executor_refusal_still_finalizes"
		}
		t.Run(name, func(t *testing.T) {
			f := ccNewFixture(t)
			second := &cpPeer{id: "submission-second", price: ccPricePerBwS, currency: "TEST"}
			transport, err := testpeer.Start(f.ctx, f.d.Bidi, second)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cleanup, cancel := context.WithTimeout(context.Background(), ccCleanupBound)
				defer cancel()
				if err := transport.Stop(cleanup); err != nil {
					t.Error(err)
				}
			})
			ready, cancelReady := context.WithTimeout(f.ctx, cpRegistrationBound)
			defer cancelReady()
			if err := transport.Client.WaitReadyContext(ready); err != nil {
				t.Fatal(err)
			}
			binding, ok := transport.Client.Binding()
			if !ok {
				t.Fatal("second executor has no binding")
			}
			direct, err := transport.Client.ClientFor(binding)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := direct.Resources(ready, &pb.ResourcesRequest{ExecutorId: second.id, BandwidthCapacity: int64(ccCapacity)}); err != nil {
				t.Fatal(err)
			}

			request := submissionIntent(t, f, ccExecutorID, second.id)
			release, entered := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			releaseUpload := func() { releaseOnce.Do(func() { close(release) }) }
			defer releaseUpload()
			second.setUploadHook(func(ctx context.Context, _ *pb.UploadRequest) error {
				close(entered)
				select {
				case <-release:
					if refuse {
						return errors.New("executor refused the program")
					}
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
			e := echo.New()
			logCore, logs := observer.New(zap.DebugLevel)
			NewHandler(f.d, f.db, zap.New(logCore), LocalDevelopment(true)).RegisterRoutes(e)
			serverContext := make(chan context.Context, 1)
			finished := make(chan int, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				serverContext <- r.Context()
				recorder := httptest.NewRecorder()
				e.ServeHTTP(recorder, r)
				finished <- recorder.Code
				w.WriteHeader(recorder.Code)
				_, _ = w.Write(recorder.Body.Bytes())
			}))
			defer func() { releaseUpload(); server.Close() }()
			encoded, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			ctx, disconnect := context.WithCancel(f.ctx)
			defer disconnect()
			req, err := http.NewRequestWithContext(ctx, http.MethodPut, server.URL+"/debuglet", bytes.NewReader(encoded))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			clientDone := make(chan error, 1)
			go func() {
				response, err := server.Client().Do(req)
				if response != nil {
					response.Body.Close()
				}
				clientDone <- err
			}()
			submissionWait(t, entered, "second upload")
			deadline := time.After(ccRequestBound)
			for {
				var count int
				if err := f.db.QueryRow("SELECT COUNT(*) FROM debuglets WHERE transaction_id = ? AND state = ?", request.TransactionId, models.RunStateUploaded).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count == 1 {
					break
				}
				select {
				case <-deadline:
					t.Fatal("first participant did not finish uploading")
				case <-time.After(time.Millisecond):
				}
			}
			disconnect()
			submissionWait(t, (<-serverContext).Done(), "HTTP request cancellation")
			if err := <-clientDone; !errors.Is(err, context.Canceled) {
				t.Fatalf("disconnected client = %v", err)
			}
			// Release only after the server has observed the broken connection.
			releaseUpload()
			var code int
			select {
			case code = <-finished:
			case <-time.After(ccRequestBound):
				t.Fatal("admitted request did not finish after disconnect")
			}
			wantCode, wantState, wantPayment := http.StatusOK, models.RunStateUploaded, models.Paid
			if refuse {
				wantCode, wantState = http.StatusInternalServerError, models.RunStateExited
			}
			if code != wantCode {
				t.Fatalf("server completion = %d, want %d", code, wantCode)
			}
			runs, err := f.queries.GetAdmittedRuns(f.ctx, request.TransactionId)
			if err != nil || len(runs) != 2 {
				t.Fatalf("admitted group = %+v, %v", runs, err)
			}
			ids := make([]string, len(runs))
			for i, run := range runs {
				ids[i] = run.Uuid.String()
				stored, err := f.queries.GetDebugletByUUID(f.ctx, run.Uuid)
				if err != nil || stored.State != wantState {
					t.Fatalf("run = %+v, %v; want %s", stored, err, wantState)
				}
			}
			tx, err := f.queries.GetTransactionByID(f.ctx, request.TransactionId)
			if err != nil || tx.Status != int64(wantPayment) {
				t.Fatalf("payment after disconnect = %+v, %v; want %v", tx, err, wantPayment)
			}
			if refuse {
				// TEST currency intentionally cannot be refunded. Reaching its
				// currency check proves the refund read the transaction and orders
				// using a live context after the HTTP connection was cancelled.
				// Reusing the request context instead fails at BeginTx.
				refundChecked := false
				for _, entry := range logs.FilterMessage("Private request diagnostic").All() {
					if entry.ContextMap()["error"] == "Refunds are not supported for currency TEST" {
						refundChecked = true
					}
				}
				if !refundChecked {
					t.Fatalf("refund did not reach its currency check after disconnect: %+v", logs.All())
				}
			}
			if !refuse {
				raw := &wfClient{t: t, base: f.root.URL, http: f.root.Client()}
				code, body := raw.do(http.MethodPut, "/debuglet", request)
				wfExpect(t, "recover receipt", code, http.StatusOK, body)
				var repeated []string
				if err := json.Unmarshal(body, &repeated); err != nil || !reflect.DeepEqual(ids, repeated) {
					t.Fatalf("recovered receipt = %v, %v; want %v", repeated, err, ids)
				}
				if f.peer.abortCount()+second.abortCount() != 0 {
					t.Fatal("browser disconnect cancelled an admitted participant")
				}
			}
			if f.peer.uploadCount() != 1 || second.uploadCount() != 1 {
				t.Fatal("receipt recovery uploaded a duplicate participant")
			}
		})
	}
}

func TestSubmissionCanceledBeforeAdmission(t *testing.T) {
	f := ccNewFixture(t)
	request := submissionIntent(t, f, ccExecutorID)
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	req := httptest.NewRequest(http.MethodPut, "/debuglet", bytes.NewReader(encoded)).WithContext(ctx)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	e := echo.New()
	NewHandler(f.d, f.db, zap.NewNop(), LocalDevelopment(true)).RegisterRoutes(e)
	recorder := httptest.NewRecorder()
	e.ServeHTTP(recorder, req)
	runs, err := f.queries.GetAdmittedRuns(f.ctx, request.TransactionId)
	if err != nil || len(runs) != 0 || f.peer.uploadCount() != 0 || recorder.Code == http.StatusOK {
		t.Fatalf("cancelled request admitted work: runs=%v err=%v uploads=%d HTTP=%d", runs, err, f.peer.uploadCount(), recorder.Code)
	}
}
