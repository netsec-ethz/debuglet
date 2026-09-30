// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"bytes"
	"encoding/json"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	"net/http"
	"testing"
)

func TestRetryRequiresVersionAndLineageReceipt(t *testing.T) {
	f := newFakeServer(t, "")
	f.handle("PUT /payment/intent", jsonHandler(http.StatusOK, `{"method":"TEST","intent":{"transaction_id":"tx","auth_key":""}}`))
	batch, err := Prepare([]Request{{OrderID: 0, ExecutorID: "node", Wasm: []byte{1}, Policy: Policy{TimeoutMS: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	c := f.client(t, Options{})
	key := "9a8ddf26-205a-48a4-8c93-42e384f1e611"
	if _, err := c.RetryTEST(testContext(t), fixtureID, key, batch); err == nil {
		t.Fatal("old intent response accepted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reqs) != 1 || f.reqs[0].Header.Get(apiVersionHeader) != "1.12" {
		t.Fatal("retry did not require its API version or submitted without a lineage receipt")
	}
	var body struct {
		Retry wire.RetryLink `json:"retry"`
	}
	if err := json.Unmarshal(f.reqs[0].Body, &body); err != nil || body.Retry.ParentRunID != fixtureID || body.Retry.RequestID != key {
		t.Fatal("missing frozen retry identity")
	}
}

func TestResultRetryVersionCompatibility(t *testing.T) {
	doc := resultFixture(t)
	setResultAdmission(&doc)
	doc.Provenance.Retry = &wire.RetryLink{ParentRunID: "9a8ddf26-205a-48a4-8c93-42e384f1e611", RequestID: "c47d58ce-a87f-476f-b453-d3cb53528496"}
	doc.Version = "1.2"
	encode := func() error {
		data, err := json.Marshal(doc)
		if err != nil {
			return err
		}
		_, err = ReadResult(bytes.NewReader(data))
		return err
	}
	if err := encode(); err != nil {
		t.Fatal(err)
	}
	doc.Version = "1.1"
	if err := encode(); err == nil {
		t.Fatal("retry lineage mislabeled 1.1")
	}
	doc.Version = "1.0"
	if err := encode(); err == nil {
		t.Fatal("retry lineage mislabeled 1.0")
	}
	doc.Version = "1.2"
	doc.Provenance.Retry.ParentRunID = doc.RunID
	if err := encode(); err == nil {
		t.Fatal("self-parent accepted")
	}
	doc.Provenance.Retry = nil
	if err := encode(); err == nil {
		t.Fatal("1.2 without lineage accepted")
	}
	doc.Version = "1.1"
	if err := encode(); err != nil {
		t.Fatalf("ordinary 1.1 no longer readable: %v", err)
	}
	doc.Version = "1.0"
	if err := encode(); err != nil {
		t.Fatalf("ordinary 1.0 no longer readable: %v", err)
	}
}
