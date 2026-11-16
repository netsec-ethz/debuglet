// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package studio

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type personalTestTransport func(*http.Request) (*http.Response, error)

func (f personalTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPersonalAssistantUsesFixedOpenAIAndTestsWithoutGeneration(t *testing.T) {
	a, err := NewPersonalAssistant("test-model", "sk-private-test", "high")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if a.endpoint != "https://api.openai.com/v1/responses" || a.reasoningEffort != "high" || !a.responsesAPI {
		t.Fatal("personal client lost fixed endpoint or settings")
	}
	for _, status := range []int{200, 401, 403, 404, 429, 500, 302} {
		a.client.Transport = personalTestTransport(func(r *http.Request) (*http.Response, error) {
			if r.Method != "GET" || r.URL.String() != "https://api.openai.com/v1/models/test-model" || r.Body != nil || r.Header.Get("Authorization") != "Bearer sk-private-test" {
				t.Error("unexpected access test request")
			}
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("private upstream details")), Header: make(http.Header)}, nil
		})
		err := a.CheckAccess(t.Context())
		if status == 200 {
			if err != nil {
				t.Fatal(err)
			}
			continue
		}
		var failure *AssistantError
		if !errors.As(err, &failure) || failure.ProviderStatus != status || strings.Contains(err.Error(), "private") {
			t.Fatal("unsafe access failure", err)
		}
	}
}
