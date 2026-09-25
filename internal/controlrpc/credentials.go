// Package controlrpc carries the control session credential of one dispatcher
// and executor pair over gRPC metadata: the metadata keys both channels agree
// on, the constant-time match each side admits a request with, and the status
// vocabulary that answers a request it cannot admit. The nonsecret identity and
// the lease vocabulary stay in controlsession, which holds no transport.
package controlrpc

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"strconv"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// The metadata keys of a control session credential, in the order Keys returns
// and both channels send them.
const (
	VersionKey     = "debuglet-control-version"
	IncarnationKey = "debuglet-dispatcher-incarnation"
	SessionIDKey   = "debuglet-session-id"
	TokenKey       = "debuglet-session-token"
)

// version is the one supported protocol version as it travels in metadata.
var version = strconv.FormatUint(uint64(controlsession.ProtocolVersion), 10)

// Keys names every metadata key a credential occupies. The returned array is a
// copy, so a caller cannot change what this transport reads or sends.
func Keys() [4]string {
	return [4]string{VersionKey, IncarnationKey, SessionIDKey, TokenKey}
}

// Credentials is private transport state. Never format it or an offer.
type Credentials struct {
	Binding controlsession.Binding
	Token   [32]byte
}

// Unavailable, Malformed and Denied are the only statuses a credential check
// answers with. None of them repeats supplied metadata.
func Unavailable() error {
	return status.Error(codes.FailedPrecondition, "control session unavailable")
}
func Malformed() error {
	return status.Error(codes.InvalidArgument, "invalid control session metadata")
}
func Denied() error {
	return status.Error(codes.PermissionDenied, "control session ownership mismatch")
}

// Read takes the credential an incoming request carries. It decides nothing
// about ownership or leases: the caller matches it against the session it holds.
func Read(ctx context.Context) (Credentials, error) {
	var result Credentials
	md, _ := metadata.FromIncomingContext(ctx)
	values := [4]string{}
	for i, key := range Keys() {
		entries := md.Get(key)
		if len(entries) == 0 {
			return result, Unavailable()
		}
		if len(entries) != 1 {
			return result, Malformed()
		}
		values[i] = entries[0]
	}
	if values[0] != version {
		return result, Unavailable()
	}
	binding, err := controlsession.ParseBinding(values[1], values[2])
	if err != nil {
		return result, Malformed()
	}
	token, err := base64.RawURLEncoding.Strict().DecodeString(values[3])
	if err != nil || len(token) != 32 || base64.RawURLEncoding.EncodeToString(token) != values[3] {
		return result, Malformed()
	}
	result.Binding = binding
	copy(result.Token[:], token)
	return result, nil
}

// Matches compares the token in constant time, so a rejected request tells a
// peer nothing about how far its guess reached.
func (c Credentials) Matches(other Credentials) bool {
	return c.Binding == other.Binding && subtle.ConstantTimeCompare(c.Token[:], other.Token[:]) == 1
}

// Outgoing replaces the reserved keys of an outgoing call without mutating the
// metadata its caller supplied.
func (c Credentials) Outgoing(ctx context.Context) context.Context {
	md, _ := metadata.FromOutgoingContext(ctx)
	md = md.Copy()
	md.Set(VersionKey, version)
	md.Set(IncarnationKey, c.Binding.Incarnation)
	md.Set(SessionIDKey, c.Binding.SessionID)
	md.Set(TokenKey, base64.RawURLEncoding.EncodeToString(c.Token[:]))
	return metadata.NewOutgoingContext(ctx, md)
}
