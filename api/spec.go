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
	Version = "1.20"
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
	// 1.7 added executor capability discovery. 1.8 added portable results.
	// 1.9 added durable cancellation inspection.
	// 1.10 added account-owned executor enrollment.
	// 1.11 added attribution lookups.
	// 1.12 added measurement workflows, payload deletion and structured request field failures.
	// 1.13 added linked provider identities and scoped browser-approved credentials.
	// 1.14 added local allocation reclamation to recovery inspection.
	// 1.15 added payment quotes, the account's order history, the account's
	// payment features, usage allowances (GET /me/allowance, POST
	// /operator/accounts/{id}/allowance) and executor earnings
	// (GET /operator/executors/{id}/earnings).
	// 1.16 added the RIPE Atlas-style is_public, address, prefix and ASN
	// fields of each address family to GET /executors.
	// 1.17 added the RIPE Atlas-style status history and tags to GET
	// /executors and its status filter.
	// 1.18 added server-assisted verification and receipt keys.
	// 1.19 added recorded destination policies: deny, reason, expiry and their listing.
	// 1.20 added admission and unavailable drain status to account-owned executors.
	Minor = 20
	// VersionHeader carries the contract version a client requires on requests
	// and the version the dispatcher implements on responses.
	VersionHeader = "Debuglet-API-Version"
	// MediaType is the content type of the served OpenAPI document.
	MediaType = "application/yaml"
)
