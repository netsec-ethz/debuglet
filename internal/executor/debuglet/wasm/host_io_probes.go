// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/guestio"
)

func writeProbeResult(mod Memory, ptr, length uint32, value any) uint64 {
	data, err := json.Marshal(value)
	if err == nil && (len(data) > int(length) || len(data) > MAX_SLICE_LENGTH) {
		err = errors.New("probe result exceeds buffer")
	}
	if err != nil {
		return ioResult(0, err)
	}
	if !mod.Write(ptr, data) {
		panic("probe result outside memory")
	}
	return ioResult(len(data), nil)
}

func hostTLSInspect(env *WasmEnv) func(context.Context, Memory, uint32, uint32, uint32, uint32, int64) uint64 {
	return func(ctx context.Context, mod Memory, ptr, length, out, size uint32, timeout int64) uint64 {
		address, err := extractStr(mod, ptr, length)
		if err != nil {
			panic(err)
		}
		if _, err := extractMem[byte](mod, out, size); err != nil {
			panic(err)
		}
		probeCtx, cancel := probeDeadline(ctx, timeout)
		defer cancel()
		info, err := inspectTLS(probeCtx, env, address)
		if err != nil {
			return ioResult(0, err)
		}
		return writeProbeResult(mod, out, size, info)
	}
}

func inspectTLS(ctx context.Context, env *WasmEnv, address string) (_ guestio.TLSInfo, err error) {
	info := guestio.TLSInfo{Certificates: []guestio.TLSCertificate{}}
	handle, err := connectSocket(ctx, ctx, env, socket.SocketTypeTLS, address)
	if err != nil {
		return info, err
	}
	defer func() { err = errors.Join(err, env.Registry.Close(handle)) }()
	connection, err := env.Registry.Get(handle)
	if err != nil {
		return info, err
	}
	secured, ok := connection.(interface {
		TLSState() (tls.ConnectionState, bool)
	})
	if !ok {
		return info, fmt.Errorf("TLS state unavailable")
	}
	state, ok := secured.TLSState()
	if !ok || !state.HandshakeComplete || len(state.VerifiedChains) == 0 {
		return info, fmt.Errorf("TLS handshake was not verified")
	}
	info.Version, info.Cipher = tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite)
	info.ALPN, info.ServerName, info.PeerAddress = state.NegotiatedProtocol, state.ServerName, connection.RemoteAddr()
	info.Verified = true
	for _, certificate := range state.PeerCertificates {
		digest := sha256.Sum256(certificate.Raw)
		info.Certificates = append(info.Certificates, guestio.TLSCertificate{
			Subject: certificate.Subject.String(), Issuer: certificate.Issuer.String(),
			NotBefore: certificate.NotBefore.UTC().Format(time.RFC3339), NotAfter: certificate.NotAfter.UTC().Format(time.RFC3339),
			SHA256: hex.EncodeToString(digest[:]),
		})
	}
	return info, nil
}

func hostHopProbe(env *WasmEnv) func(context.Context, Memory, uint32, uint32, uint32, uint32, uint32, int64) uint64 {
	return func(ctx context.Context, mod Memory, ptr, length, ttl, out, size uint32, timeout int64) uint64 {
		address, err := extractStr(mod, ptr, length)
		if err != nil {
			panic(err)
		}
		if _, err := extractMem[byte](mod, out, size); err != nil {
			panic(err)
		}
		if ttl < 1 || ttl > 255 {
			return ioResult(0, errors.New("TTL must be 1–255"))
		}
		probeCtx, cancel := probeDeadline(ctx, timeout)
		defer cancel()
		reply, err := probeHop(probeCtx, env, address, int(ttl))
		if err != nil {
			return ioResult(0, err)
		}
		return writeProbeResult(mod, out, size, reply)
	}
}

func probeDeadline(ctx context.Context, timeout int64) (context.Context, context.CancelFunc) {
	if timeout == 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, time.Duration(timeout))
}
