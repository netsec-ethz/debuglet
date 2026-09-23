package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"go.uber.org/zap"
)

func TestLocalConnectionMetadata(t *testing.T) {
	cfg := &config.DispatcherConfig{}
	cfg.Sui.Disabled, cfg.TLS.Disable = true, true
	httpL, grpcL, err := bindDispatcherListeners(context.Background(), config.ServerConfig{BindHost: "127.0.0.1"}, (&net.ListenConfig{}).Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer grpcL.Close()
	metadata := localConnectionMetadata(cfg, httpL.Addr().String(), grpcL.Addr().String())
	if metadata == nil {
		httpL.Close()
		t.Fatal("actual local-test listeners produced no connection metadata")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- startHTTPServer(ctx, httpL, &dispatcher.Dispatcher{}, cfg, nil, zap.NewNop(), metadata)
	}()
	defer func() {
		cancel()
		httpL.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("metadata HTTP fixture did not join")
		}
	}()
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get("http://" + httpL.Addr().String() + "/connection")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var got connectionMetadata
	if err := json.NewDecoder(response.Body).Decode(&got); err != nil || response.StatusCode != http.StatusOK || got != *metadata {
		t.Fatalf("connection route: status=%d metadata=%+v err=%v", response.StatusCode, got, err)
	}
	if got.GRPCAddress == got.YamuxAddress || got.Mode != "local-test" || got.SchemaVersion != 1 {
		t.Fatalf("metadata inferred ports or omitted mode: %+v", got)
	}
}

func TestConnectionMetadataRequiresLocalTestMode(t *testing.T) {
	for _, tc := range []struct {
		walletDisabled, tlsDisabled bool
		http, grpc                  string
	}{
		{false, true, "127.0.0.1:9000", "127.0.0.1:9001"},
		{true, false, "127.0.0.1:9000", "127.0.0.1:9001"},
		{true, true, "0.0.0.0:9000", "127.0.0.1:9001"},
		{true, true, "127.0.0.1:9000", "192.0.2.1:9001"},
		{true, true, "localhost:9000", "127.0.0.1:9001"},
		{true, true, "127.0.0.1:0", "127.0.0.1:9001"},
	} {
		cfg := &config.DispatcherConfig{}
		cfg.Sui.Disabled, cfg.TLS.Disable = tc.walletDisabled, tc.tlsDisabled
		if got := localConnectionMetadata(cfg, tc.http, tc.grpc); got != nil {
			t.Fatalf("published local metadata outside mode: %+v", tc)
		}
	}
}
