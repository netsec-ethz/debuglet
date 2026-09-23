// Package buildinfo holds linker-set distribution identity. Empty values preserve go install metadata fallback.
//
// This is the identity of a built binary only. It is deliberately separate
// from the two contracts a binary speaks, which are versioned on their own:
// the HTTP API contract in package api, and the executor control protocol in
// package internal/controlsession. GuestABI below is the third, the WASI
// import surface a guest module is built against.
package buildinfo

var (
	Version  string
	Revision string
	GuestABI = "debuglet-go-wasi-imports-v1"
)
