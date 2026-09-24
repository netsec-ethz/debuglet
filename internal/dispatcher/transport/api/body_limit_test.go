package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	apispec "github.com/netsec-ethz/debuglet/api"
)

// blTooLargeMessage is the fixed message of a body above the limit.
const blTooLargeMessage = "request body exceeds 33554432 bytes"

// blBody builds a JSON body of exactly size bytes whose padding is the string
// value that head opens and tail closes. The members after the padding are
// read only once everything before them has been read.
func blBody(t *testing.T, head, tail string, size int) []byte {
	t.Helper()
	padding := size - len(head) - len(tail)
	if padding < 0 {
		t.Fatalf("a body of %d bytes cannot hold its members", size)
	}
	body := make([]byte, 0, size)
	body = append(body, head...)
	body = append(body, bytes.Repeat([]byte("a"), padding)...)
	body = append(body, tail...)
	return body
}

// blIntentBody is a payment intent whose last member names a method the API
// does not admit, so a handler can reject it only after reading the whole body.
func blIntentBody(t *testing.T, size int) []byte {
	t.Helper()
	return blBody(t, `{"debuglets":[],"refund_address":"`, `","payment_method":"NONE"}`, size)
}

// blSubmitBody is a submission as a raw client could send it.
func blSubmitBody(t *testing.T, size int) []byte {
	t.Helper()
	return blBody(t, `{"debuglets":[],"auth_key":"k","transaction_id":"`, `"}`, size)
}

// blSend sends one raw request. A chunked body is passed through a reader
// whose length the client cannot know, so it is sent without Content-Length.
func blSend(t *testing.T, f *ccFixture, c *http.Client, method, target string, body []byte, chunked bool) (int, http.Header, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.ctx, ccCommandBound)
	defer cancel()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
		if chunked {
			reader = io.MultiReader(reader)
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s %s: read response: %v", method, target, err)
	}
	return resp.StatusCode, resp.Header, data
}

// blAssertTooLarge checks the refusal of a body above the limit.
func blAssertTooLarge(t *testing.T, status int, header http.Header, body []byte) {
	t.Helper()
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body %s", status, http.StatusRequestEntityTooLarge, body)
	}
	if contentType := header.Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}
	if got := header.Get(apispec.VersionHeader); got != apispec.Version {
		t.Errorf("%s = %q, want %q", apispec.VersionHeader, got, apispec.Version)
	}
	var envelope map[string]any
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	if len(envelope) != 2 || envelope["code"] != CodePayloadTooLarge || envelope["message"] != blTooLargeMessage {
		t.Errorf("body = %s, want {\"code\":%q,\"message\":%q}", body, CodePayloadTooLarge, blTooLargeMessage)
	}
}

// blAssertNoRows checks that nothing of a refused request was recorded.
func blAssertNoRows(t *testing.T, f *ccFixture, tables ...string) {
	t.Helper()
	for _, table := range tables {
		var n int
		if err := f.db.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if n != 0 {
			t.Errorf("%s holds %d rows after a refused request, want none", table, n)
		}
	}
}

// Every route refuses a body above maxRequestBodyBytes with the documented
// envelope before a handler acts on it, whether the body declares its length
// or not, and a body of exactly the limit reaches the handler whole.
func TestRequestBodyLimit(t *testing.T) {
	f := ccNewFixture(t)
	spec := oaContract(t)
	root := f.root.Client()
	intentOver := blIntentBody(t, maxRequestBodyBytes+1)
	intentAt := blIntentBody(t, maxRequestBodyBytes)
	submitOver := blSubmitBody(t, maxRequestBodyBytes+1)

	for _, chunked := range []bool{false, true} {
		name := "declared length"
		if chunked {
			name = "unknown length"
		}
		t.Run("payment intent over the limit, "+name, func(t *testing.T) {
			status, header, body := blSend(t, f, root, http.MethodPut, f.root.URL+"/payment/intent", intentOver, chunked)
			blAssertTooLarge(t, status, header, body)
			oaCheckResponse(t, spec, http.MethodPut, "/payment/intent", status, body)
			blAssertNoRows(t, f, "transactions", "debuglet_order")
		})
		t.Run("submission over the limit, "+name, func(t *testing.T) {
			status, header, body := blSend(t, f, root, http.MethodPut, f.root.URL+"/debuglet", submitOver, chunked)
			blAssertTooLarge(t, status, header, body)
			oaCheckResponse(t, spec, http.MethodPut, "/debuglet", status, body)
			blAssertNoRows(t, f, "debuglets")
		})
		t.Run("payment intent at the limit, "+name, func(t *testing.T) {
			status, _, body := blSend(t, f, root, http.MethodPut, f.root.URL+"/payment/intent", intentAt, chunked)
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d; body %s", status, http.StatusBadRequest, body)
			}
			var envelope ErrorResponse
			if err := json.Unmarshal(body, &envelope); err != nil {
				t.Fatalf("decode %s: %v", body, err)
			}
			if envelope.Code != CodeUnsupportedPaymentMethod {
				t.Errorf("code = %q, want %q: the handler did not read the whole body", envelope.Code, CodeUnsupportedPaymentMethod)
			}
			blAssertNoRows(t, f, "transactions", "debuglet_order")
		})
	}

	t.Run("behind a path prefix", func(t *testing.T) {
		status, header, body := blSend(t, f, f.prefix.Client(), http.MethodPut, f.prefix.URL+"/api/payment/intent", intentOver, false)
		blAssertTooLarge(t, status, header, body)
		blAssertNoRows(t, f, "transactions", "debuglet_order")
	})

	t.Run("a route that reads no body", func(t *testing.T) {
		status, header, body := blSend(t, f, root, http.MethodGet, f.root.URL+"/version", intentOver, false)
		blAssertTooLarge(t, status, header, body)
		status, _, body = blSend(t, f, root, http.MethodGet, f.root.URL+"/version", nil, false)
		if status != http.StatusOK {
			t.Fatalf("GET /version without a body: status = %d, want %d; body %s", status, http.StatusOK, body)
		}
	})

	t.Run("every registered route", func(t *testing.T) {
		values := strings.NewReplacer(":id", "00000000-0000-0000-0000-000000000000", ":transaction_id", "bl-transaction")
		for _, route := range f.routes {
			t.Run(route, func(t *testing.T) {
				method, path, _ := strings.Cut(route, " ")
				status, header, body := blSend(t, f, root, method, f.root.URL+values.Replace(path), intentOver, false)
				blAssertTooLarge(t, status, header, body)
			})
		}
	})
}
