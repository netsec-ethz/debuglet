// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package rpc

import (
	"testing"

	pb "github.com/netsec-ethz/debuglet/protocol"
)

func TestOutputIdentityCapturedAtEnrollment(t *testing.T) {
	f, store, _ := enrolledControl(t)
	peer := &lifecyclePeer{id: "executor", version: "output-v1", outputVersion: pb.OutputVersion,
		token: issueToken(t, store, "executor")}
	f.connectedPeer(peer, f.ca.ClientConfig(f.client, ""))
	owner := f.registered(peer.version)
	if owner.OutputVersion() != pb.OutputVersion || owner.CredentialFingerprint() != fingerprintOf(f.client) {
		t.Fatalf("admitted output identity: version=%d fingerprint=%q", owner.OutputVersion(), owner.CredentialFingerprint())
	}
	// The stored admission identity must not follow a later enrollment change.
	if _, err := store.Revoke(t.Context(), "executor"); err != nil {
		t.Fatal(err)
	}
	if owner.CredentialFingerprint() != fingerprintOf(f.client) {
		t.Fatal("admission identity changed")
	}
}

func TestOutputIdentityAbsentWithoutEnrollment(t *testing.T) {
	f := newControlTLS(t, controlTLSOptions{requireClientIdentity: true})
	peer := &lifecyclePeer{id: "executor", version: "legacy"}
	f.connectedPeer(peer, f.ca.ClientConfig(f.client, ""))
	owner := f.registered(peer.version)
	if owner.OutputVersion() != 0 || owner.CredentialFingerprint() != "" {
		t.Fatalf("unnegotiated or unenrolled identity: version=%d fingerprint=%q", owner.OutputVersion(), owner.CredentialFingerprint())
	}
}

func TestUnsupportedOutputVersionDoesNotRegister(t *testing.T) {
	f := newControlTLS(t, controlTLSOptions{})
	peer := &lifecyclePeer{id: "executor", version: "future", outputVersion: pb.OutputVersion + 1}
	owned := f.connectedPeer(peer, f.ca.ClientConfig(nil, ""))
	f.refused(owned, "")
}
