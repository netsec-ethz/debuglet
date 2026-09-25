package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestIsTransportError(t *testing.T) {
	expired, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel()
	reset := errors.New("connection reset by peer")
	httpErr := &HTTPError{Method: http.MethodDelete, Path: "/debuglet", StatusCode: http.StatusInternalServerError}
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"transport failure", wrapTransport(context.Background(), http.MethodDelete, "/debuglet", reset), true},
		{"transport failure at the deadline", wrapTransport(expired, http.MethodDelete, "/debuglet", reset), true},
		{"wrapped transport failure", fmt.Errorf("cancel: %w", wrapTransport(context.Background(), http.MethodDelete, "/debuglet", reset)), true},
		{"HTTP error", httpErr, false},
		{"wrapped HTTP error", fmt.Errorf("cancel: %w", httpErr), false},
		{"protocol error", &protocolError{method: http.MethodDelete, path: "/debuglet", msg: "malformed"}, false},
		{"plain error", reset, false},
		{"nil", nil, false},
	} {
		if got := IsTransportError(tc.err); got != tc.want {
			t.Errorf("%s: IsTransportError = %v, want %v", tc.name, got, tc.want)
		}
	}
	joined := wrapTransport(expired, http.MethodDelete, "/debuglet", reset)
	if !errors.Is(joined, context.DeadlineExceeded) {
		t.Fatalf("deadline not joined into the transport failure: %v", joined)
	}
}
