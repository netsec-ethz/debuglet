package controlrpc

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestControlErrorProjection(t *testing.T) {
	var credentials Credentials
	copy(credentials.Token[:], []byte("0123456789abcdef0123456789abcdef"))
	for _, unaffected := range []error{context.Canceled, context.DeadlineExceeded, status.Error(codes.Unavailable, "ordinary peer failure")} {
		if credentials.RedactError(unaffected) != unaffected {
			t.Fatal("projection changed an error without a credential")
		}
	}
	if credentials.RedactError(nil) != nil {
		t.Fatal("nil error changed")
	}
	raw := string(credentials.Token[:])
	for _, secret := range []string{raw, base64.RawURLEncoding.EncodeToString(credentials.Token[:]), base64.StdEncoding.EncodeToString(credentials.Token[:]), hex.EncodeToString(credentials.Token[:]), fmt.Sprintf("%q", raw), fmt.Sprint(credentials.Token[:])} {
		original := status.Error(codes.Aborted, "local work failed; "+secret)
		projected := credentials.RedactError(original)
		if status.Code(projected) != codes.Aborted || !strings.Contains(projected.Error(), "local work failed") || !strings.Contains(projected.Error(), "[redacted]") {
			t.Fatal("projection changed code or unrelated diagnostic")
		}
		if strings.Contains(projected.Error(), secret) {
			t.Fatal("projected error retains a known credential representation")
		}
		if unwrap, ok := projected.(interface{ Unwrap() error }); ok && unwrap.Unwrap() != nil {
			t.Fatal("projection retained original error")
		}
	}
}
