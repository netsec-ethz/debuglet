// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guestio

// TLSInfo contains public metadata from a successfully verified handshake.
type TLSInfo struct {
	Version      string           `json:"tls_version"`
	Cipher       string           `json:"cipher"`
	ALPN         string           `json:"alpn"`
	ServerName   string           `json:"server_name"`
	PeerAddress  string           `json:"peer_address"`
	Verified     bool             `json:"verified"`
	Certificates []TLSCertificate `json:"certificates"`
}

type TLSCertificate struct {
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	SHA256    string `json:"sha256"`
}

// HopReply describes one correlated IPv4 ICMP response, not captured traffic.
type HopReply struct {
	Address    string  `json:"reply_address"`
	Type       int     `json:"icmp_type"`
	Code       int     `json:"icmp_code"`
	Reached    bool    `json:"reached"`
	DurationMS float64 `json:"duration_ms"`
}
