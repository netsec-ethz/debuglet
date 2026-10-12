// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func TestResultOwnerDisplayRoundTrip(t *testing.T) {
	doc := currentResultFixture(t)
	value, source := "Owner city", wire.SourceOwner
	doc.Provenance.VantagePoint.Display.City = wire.LabelledString{Value: &value, Source: &source}
	data, _ := json.Marshal(doc)
	if _, err := ReadResult(bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	doc.Provenance.VantagePoint.SourceIP = wire.LabelledString{Value: &value, Source: &source}
	data, _ = json.Marshal(doc)
	if _, err := ReadResult(bytes.NewReader(data)); err == nil {
		t.Fatal("owner labelled an observed source IP")
	}
}
