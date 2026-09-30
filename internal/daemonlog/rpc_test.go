// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package daemonlog

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlrpc"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestRPCDiagnosticBoundary(t *testing.T) {
	credential := controlrpc.Credentials{Binding: controlsession.Binding{Incarnation: uuid.NewString(), SessionID: uuid.NewString()}}
	copy(credential.Token[:], []byte("sentinel-control-credential-00001"))
	md, _ := metadata.FromOutgoingContext(credential.Outgoing(t.Context()))
	ctx := metadata.NewIncomingContext(t.Context(), md)
	secret := base64.RawURLEncoding.EncodeToString(credential.Token[:])
	for _, code := range []codes.Code{codes.Unknown, codes.Internal, codes.DataLoss, codes.InvalidArgument, codes.ResourceExhausted, codes.Canceled, codes.DeadlineExceeded} {
		t.Run(code.String(), func(t *testing.T) {
			core, logs := observer.New(zapcore.DebugLevel)
			logger := zap.New(core)
			private := "private-stack-sentinel " + secret
			message := private
			if code == codes.InvalidArgument {
				message = "floor_bw must be at least zero"
			}
			if code == codes.ResourceExhausted {
				message = "executor retained queue limit reached"
			}
			original := status.Error(code, message)
			out, err := UnaryErrors(logger)(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/debuglet.Executor/Upload"}, func(context.Context, any) (any, error) { return nil, original })
			if out != nil || status.Code(err) != code {
				t.Fatalf("classification: %v %v", out, err)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatal("public credential")
			}
			if code == codes.Unknown || code == codes.Internal || code == codes.DataLoss {
				if strings.Contains(err.Error(), "private-stack-sentinel") {
					t.Fatal("public internal detail")
				}
				for _, entry := range logs.All() {
					rendered := fmt.Sprint(entry.ContextMap())
					if strings.Contains(rendered, secret) {
						t.Fatal("private log credential")
					}
					if entry.Level >= zapcore.InfoLevel && strings.Contains(rendered, "private-stack-sentinel") {
						t.Fatal("routine log stack")
					}
				}
				if logs.FilterMessage("Private RPC diagnostic").Len() != 1 {
					t.Fatal("operator diagnostic missing")
				}
			} else if code == codes.InvalidArgument || code == codes.ResourceExhausted {
				if status.Convert(err).Message() != message {
					t.Fatal("actionable validation lost")
				}
			}
		})
	}
	for _, err := range []error{context.Canceled, fmt.Errorf("wrapped: %w", context.DeadlineExceeded)} {
		if status.Code(rpcFailure(ctx, zap.NewNop(), "test", err)) != status.Code(status.FromContextError(err).Err()) {
			t.Fatal("context status changed")
		}
	}
	bounded := Diagnostic(errors.New(strings.Repeat("x", 4000) + "\n"))
	if len(bounded) > 2051 || strings.Contains(bounded, "\n") {
		t.Fatal("diagnostic not bounded")
	}
}
