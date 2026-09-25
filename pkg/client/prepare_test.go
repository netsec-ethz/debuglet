package client

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestPreparedBatchIdentity(t *testing.T) {
	t.Run("frozen bytes survive caller mutation", func(t *testing.T) {
		start := int64(1700000000)
		wasmA := []byte{1, 2, 3}
		args := []string{"127.0.0.1:12345", "two words"}
		addresses := []string{"127.0.0.1"}
		requests := []Request{
			{
				OrderID:    0,
				ExecutorID: "exec-a",
				Args:       args,
				Wasm:       wasmA,
				Policy:     Policy{FloorBW: 1048576, CeilBW: 1048576, TimeoutMS: 10000, Addresses: addresses},
			},
			{
				OrderID:        1,
				StartTimestamp: &start,
				ExecutorID:     "exec-b",
				Wasm:           []byte{4, 5, 6},
				Policy:         Policy{TimeoutMS: 1, RequireICMP: true, ListenUDP: true, ListenTCP: true, ListenSCION: true},
			},
		}
		batch, err := Prepare(requests)
		if err != nil {
			t.Fatalf("Prepare: %v", err)
		}
		// Mutate everything the caller still holds.
		wasmA[0] = 0xff
		args[0] = "changed"
		addresses[0] = "changed"
		start = 1
		requests[0].ExecutorID = "changed"
		requests[0].Policy.TimeoutMS = 1
		requests[1].StartTimestamp = nil
		requests[1].Wasm = nil
		requests = append(requests[:0], Request{})
		_ = requests

		const want = `[{"order_id":0,"executor_id":"exec-a","args":["127.0.0.1:12345","two words"],"wasm":"AQID","policy":{"floor_bw":1048576,"ceil_bw":1048576,"timeout_ms":10000,"addresses":["127.0.0.1"],"require_icmp":false,"listen_udp":false,"listen_tcp":false,"listen_scion":false}},` +
			`{"order_id":1,"start_time":1700000000,"executor_id":"exec-b","wasm":"BAUG","policy":{"floor_bw":0,"ceil_bw":0,"timeout_ms":1,"addresses":null,"require_icmp":true,"listen_udp":true,"listen_tcp":true,"listen_scion":true}}]`
		if got := string(batch.debuglets); got != want {
			t.Fatalf("frozen debuglets:\n got %s\nwant %s", got, want)
		}
		if batch.count != 2 {
			t.Fatalf("count = %d, want 2", batch.count)
		}

		f := newFakeServer(t, "/api")
		f.defaults()
		c := f.client(t, Options{})
		sub, err := c.SubmitTEST(testContext(t), batch)
		if err != nil {
			t.Fatalf("SubmitTEST: %v", err)
		}
		if sub.TransactionID != fixtureTx || len(sub.IDs) != 2 {
			t.Fatalf("submission = %+v", sub)
		}
		reqs := f.requests()
		if len(reqs) != 2 {
			t.Fatalf("expected exactly 2 requests, got %d", len(reqs))
		}
		intent, submit := reqs[0], reqs[1]
		wantIntent := `{"debuglets":` + want + `,"payment_method":"TEST","refund_address":""}`
		wantSubmit := `{"debuglets":` + want + `,"transaction_id":"` + fixtureTx + `","auth_key":""}`
		if string(intent.Body) != wantIntent {
			t.Fatalf("intent body:\n got %s\nwant %s", intent.Body, wantIntent)
		}
		if string(submit.Body) != wantSubmit {
			t.Fatalf("submit body:\n got %s\nwant %s", submit.Body, wantSubmit)
		}
		for _, r := range reqs {
			if ct := r.Header.Get("Content-Type"); ct != "application/json" {
				t.Fatalf("%s %s Content-Type = %q", r.Method, r.Path, ct)
			}
			if ac := r.Header.Get("Accept"); ac != "application/json" {
				t.Fatalf("%s %s Accept = %q", r.Method, r.Path, ac)
			}
		}
	})

	t.Run("validation", func(t *testing.T) {
		valid := func() Request {
			return Request{OrderID: 7, ExecutorID: "exec", Wasm: []byte{1}, Policy: Policy{FloorBW: 1, CeilBW: 2, TimeoutMS: 1000}}
		}
		cases := []struct {
			name     string
			requests []Request
			want     string
		}{
			{"nil batch", nil, "empty batch"},
			{"empty batch", []Request{}, "empty batch"},
			{"empty wasm", func() []Request { r := valid(); r.Wasm = nil; return []Request{r} }(), "request 0: empty wasm"},
			{"blank executor", func() []Request { r := valid(); r.ExecutorID = " \t"; return []Request{r} }(), "request 0: blank executor id"},
			{"duplicate order ids", []Request{valid(), valid()}, "request 1: duplicate order id 7"},
			{"zero timeout", func() []Request { r := valid(); r.Policy.TimeoutMS = 0; return []Request{r} }(), "timeout_ms must be positive"},
			{"negative timeout", func() []Request { r := valid(); r.Policy.TimeoutMS = -1; return []Request{r} }(), "timeout_ms must be positive"},
			{"timeout overflow", func() []Request {
				r := valid()
				r.Policy.TimeoutMS = math.MaxInt64/int64(time.Millisecond) + 1
				return []Request{r}
			}(), "exceeds maximum"},
			{"negative floor", func() []Request { r := valid(); r.Policy.FloorBW = -1; return []Request{r} }(), "floor_bw must not be negative"},
			{"ceil below floor", func() []Request { r := valid(); r.Policy.CeilBW = 0; return []Request{r} }(), "ceil_bw must be at least floor_bw"},
			{"second request invalid", []Request{valid(), func() Request { r := valid(); r.OrderID = 8; r.Wasm = nil; return r }()}, "request 1: empty wasm"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				batch, err := Prepare(tc.requests)
				if err == nil {
					t.Fatalf("expected error, got batch %+v", batch)
				}
				if !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("error %q does not contain %q", err, tc.want)
				}
			})
		}
		ok := []Request{
			{OrderID: -1, ExecutorID: "e", Wasm: []byte{1}, Policy: Policy{TimeoutMS: 1}},
			{OrderID: 0, ExecutorID: "e", Wasm: []byte{1}, Policy: Policy{FloorBW: 5, CeilBW: 5, TimeoutMS: math.MaxInt64 / int64(time.Millisecond)}},
			{OrderID: 1, ExecutorID: "e", Wasm: []byte{1}, Policy: Policy{FloorBW: 0, CeilBW: 5, TimeoutMS: 1, Addresses: []string{}}},
		}
		if _, err := Prepare(ok); err != nil {
			t.Fatalf("boundary values rejected: %v", err)
		}
	})

	t.Run("envelope bound", func(t *testing.T) {
		small, err := Prepare([]Request{{ExecutorID: "e", Wasm: []byte{1, 2, 3}, Policy: Policy{TimeoutMS: 1}}})
		if err != nil {
			t.Fatal(err)
		}
		overhead := intentEnvelopeSize(small.debuglets) - 4 // base64 of 3 bytes is 4 characters
		n := 3 * ((maxEnvelopeBytes - overhead) / 4)        // largest wasm whose base64 still fits
		big := make([]byte, n)
		batch, err := Prepare([]Request{{ExecutorID: "e", Wasm: big, Policy: Policy{TimeoutMS: 1}}})
		if err != nil {
			t.Fatalf("wasm of %d bytes must fit the envelope: %v", n, err)
		}
		if size := intentEnvelopeSize(batch.debuglets); size > maxEnvelopeBytes || size+4 <= maxEnvelopeBytes {
			t.Fatalf("envelope size %d is not at the boundary %d", size, maxEnvelopeBytes)
		}
		if len(intentEnvelope(batch.debuglets)) != intentEnvelopeSize(batch.debuglets) {
			t.Fatalf("envelope size mismatch")
		}
		bigger := make([]byte, n+3)
		_, err = Prepare([]Request{{ExecutorID: "e", Wasm: bigger, Policy: Policy{TimeoutMS: 1}}})
		if err == nil || !strings.Contains(err.Error(), "32 MiB") {
			t.Fatalf("expected 32 MiB bound error, got %v", err)
		}
	})

	t.Run("invalid prepared batch is a pre-send rejection", func(t *testing.T) {
		f := newFakeServer(t, "")
		f.defaults()
		c := f.client(t, Options{})
		for _, batch := range []*PreparedBatch{nil, {}} {
			_, err := c.SubmitTEST(testContext(t), batch)
			se := asSubmissionError(t, err)
			if se.Stage != "intent" || se.OutcomeUnknown || se.TransactionID != "" {
				t.Fatalf("unexpected %+v", se)
			}
		}
		if n := len(f.requests()); n != 0 {
			t.Fatalf("%d requests sent for invalid batches", n)
		}
	})

	t.Run("actual submit envelope bound", func(t *testing.T) {
		for _, metadata := range []struct {
			name string
			tx   string
			key  string
		}{
			{"ordinary metadata", fixtureTx, ""},
			// Opaque metadata is neither length-limited nor normalized. Escaped
			// characters must count at their actual encoded lengths.
			{"long opaque metadata", strings.Repeat("opaque/\"\\€", 1024), strings.Repeat("key\n\"\\", 1024)},
		} {
			t.Run(metadata.name, func(t *testing.T) {
				requests := sampleRequests()
				requests[0].Args = []string{""}
				base, err := Prepare(requests)
				if err != nil {
					t.Fatal(err)
				}
				// Independently encode the full wire envelope, including the
				// exact metadata returned by the intent fixture.
				encodedSubmit := func(batch *PreparedBatch) []byte {
					t.Helper()
					body, err := json.Marshal(struct {
						Debuglets     json.RawMessage `json:"debuglets"`
						TransactionID string          `json:"transaction_id"`
						AuthKey       string          `json:"auth_key"`
					}{batch.debuglets, metadata.tx, metadata.key})
					if err != nil {
						t.Fatal(err)
					}
					return body
				}
				padding := maxEnvelopeBytes - len(encodedSubmit(base))
				for _, extra := range []int{0, 1} {
					name := "exact 32 MiB accepted"
					if extra != 0 {
						name = "32 MiB plus one rejected before submit"
					}
					t.Run(name, func(t *testing.T) {
						requests[0].Args[0] = strings.Repeat("x", padding+extra)
						batch, err := Prepare(requests)
						if err != nil {
							t.Fatalf("intent must fit before metadata is known: %v", err)
						}
						wantBody := encodedSubmit(batch)
						if len(wantBody) != maxEnvelopeBytes+extra {
							t.Fatalf("fixture submit size = %d, want %d", len(wantBody), maxEnvelopeBytes+extra)
						}
						// Mutations after preparation must affect neither envelope.
						requests[0].Args[0] = "changed"
						requests[0].Wasm[0] ^= 0xff
						f := newFakeServer(t, "/api")
						f.handle("PUT /payment/intent", intentHandler(metadata.tx, metadata.key))
						f.handle("PUT /debuglet", jsonHandler(http.StatusOK, `["`+fixtureID+`"]`))
						c := f.client(t, Options{})
						sub, err := c.SubmitTEST(testContext(t), batch)
						if extra == 0 {
							if err != nil || sub.TransactionID != metadata.tx || len(sub.IDs) != 1 || sub.IDs[0] != fixtureID {
								t.Fatalf("exact-limit submission failed: %v", err)
							}
							if f.count("PUT", "/api/debuglet") != 1 {
								t.Fatal("expected exactly one submit attempt")
							}
							sent := f.requests()[1].Body
							if len(sent) != maxEnvelopeBytes || !bytes.Equal(sent, wantBody) {
								t.Fatalf("actual submit envelope differs: size %d", len(sent))
							}
							if !bytes.Equal(debugletsOf(t, sent), batch.debuglets) {
								t.Fatal("submit changed the frozen debuglets")
							}
						} else {
							se := asSubmissionError(t, err)
							if se.Stage != "submit" || se.TransactionID != metadata.tx || se.OutcomeUnknown || !strings.Contains(err.Error(), "32 MiB") {
								t.Fatal("oversize must be a submit-stage rejection retaining the transaction")
							}
							if f.count("PUT", "/api/debuglet") != 0 {
								t.Fatal("oversize submission reached the server")
							}
						}
						if f.count("PUT", "/api/payment/intent") != 1 {
							t.Fatal("expected exactly one intent request")
						}
						intent := f.requests()[0].Body
						if len(intent) > maxEnvelopeBytes || !bytes.Equal(debugletsOf(t, intent), batch.debuglets) {
							t.Fatal("intent exceeded its bound or changed the frozen debuglets")
						}
					})
				}
			})
		}
	})

	t.Run("the intent's auth key is forwarded to the submission", func(t *testing.T) {
		f := newFakeServer(t, "")
		f.defaults()
		c := f.client(t, Options{})
		f.handle("PUT /payment/intent", intentHandler("tx-2", "secret-key"))
		sub, err := c.SubmitTEST(testContext(t), sampleBatch(t))
		if err != nil {
			t.Fatalf("nonempty auth key: %v", err)
		}
		if sub.TransactionID != "tx-2" {
			t.Fatalf("transaction id %q", sub.TransactionID)
		}
		reqs := f.requests()
		if len(reqs) != 2 {
			t.Fatalf("%d requests", len(reqs))
		}
		want := `{"debuglets":` + sampleDebuglets + `,"transaction_id":"tx-2","auth_key":"secret-key"}`
		if string(reqs[1].Body) != want {
			t.Fatalf("submit body:\n got %s\nwant %s", reqs[1].Body, want)
		}
	})
}
