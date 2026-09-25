package rpc

import (
	"crypto/tls"
	"strings"
	"testing"

	"go.uber.org/zap"
	"google.golang.org/grpc/credentials"
)

// TestTransportSecurityIsWholeOrAbsent keeps the two control channels on the
// same footing. The direct channel takes its security from TLSCreds and the
// reverse channel from TLSConfig, so half a profile would connect one verified
// and one cleartext channel to the same dispatcher.
func TestTransportSecurityIsWholeOrAbsent(t *testing.T) {
	profile := &tls.Config{MinVersion: tls.VersionTLS12}
	for _, tc := range []struct {
		name string
		opts BidiOptions
	}{
		{"profile without credentials", BidiOptions{Address: "127.0.0.1:1", Logger: zap.NewNop(), TLSConfig: profile}},
		{"credentials without a profile", BidiOptions{Address: "127.0.0.1:1", Logger: zap.NewNop(), TLSCreds: credentials.NewTLS(profile)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := NewBidiClient(tc.opts, nil)
			if err == nil {
				client.Close()
				t.Fatal("accepted one secured and one cleartext control channel")
			}
			if !strings.Contains(err.Error(), "together, or neither") {
				t.Fatalf("error %q does not state the requirement", err)
			}
		})
	}
	for _, tc := range []struct {
		name string
		opts BidiOptions
	}{
		{"both", BidiOptions{Address: "127.0.0.1:1", Logger: zap.NewNop(), TLSConfig: profile, TLSCreds: credentials.NewTLS(profile)}},
		{"neither", BidiOptions{Address: "127.0.0.1:1", Logger: zap.NewNop()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := NewBidiClient(tc.opts, nil)
			if err != nil {
				t.Fatalf("complete profile: %v", err)
			}
			client.Close()
		})
	}
}
