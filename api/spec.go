// Package api publishes the machine-readable description of the dispatcher's
// public HTTP API together with the contract version it describes. The
// dispatcher serves the embedded document at GET /openapi.yaml; docs/api.md
// states the compatibility and deprecation policy that governs it.
package api

import _ "embed"

// OpenAPI is the tracked OpenAPI description of the HTTP API, embedded so that
// a running dispatcher serves exactly the contract it was built from.
//
//go:embed openapi.yaml
var OpenAPI []byte

const (
	// Version is the HTTP API contract version as major.minor. It equals the
	// info.version field of OpenAPI.
	Version = "1.6"
	// Major is the compatibility number of Version. Clients that require a
	// different major version are answered with an explicit incompatibility
	// error instead of a best-effort response.
	Major = 1
	// Minor counts backward-compatible additions within Major. A client that
	// requires a higher minor version than the server implements is answered
	// with the same incompatibility error. 1.1 added the session routes, the
	// credentials of an account and the authorization failures of the routes
	// that were previously reachable without one. 1.2 added the health routes
	// /healthz, /readyz and /health. 1.3 added browser login with GitHub.
	// 1.4 added the operator metrics endpoint. 1.5 added dated recovery
	// inspection of known runs. 1.6 added durable output finality.
	Minor = 6
	// VersionHeader carries the contract version a client requires on requests
	// and the version the dispatcher implements on responses.
	VersionHeader = "Debuglet-API-Version"
	// MediaType is the content type of the served OpenAPI document.
	MediaType = "application/yaml"
)
