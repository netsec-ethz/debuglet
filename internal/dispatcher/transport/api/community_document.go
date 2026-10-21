// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package api

import (
	"encoding/json"
	"net/http"

	"github.com/netsec-ethz/debuglet/internal/studio"
)

func validateCommunityDocument(kind string, document, bundle json.RawMessage) (json.RawMessage, json.RawMessage, error) {
	document, bundle, err := studio.ValidateDocument(kind, document, bundle)
	if err != nil {
		return nil, nil, apiError(http.StatusBadRequest, CodeInvalidRequest, err.Error())
	}
	return document, bundle, nil
}

func communityDocumentDigest(data []byte) string { return studio.DocumentDigest(data) }
