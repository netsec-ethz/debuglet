// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ETH Zurich

package platform

import (
	"context"
	"fmt"
	"os"

	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet/addrutil"
	"github.com/scionproto/scion/private/app"
)

func GetScionAddr(ctx context.Context) (string, error) {
	daemonAddr := os.Getenv("SCION_DAEMON_ADDRESS")
	if daemonAddr == "" {
		return "", serrors.New("SCION_DAEMON_ADDRESS not set")
	}

	sd, err := daemon.NewService(daemonAddr).Connect(ctx)
	if err != nil {
		return "", serrors.WrapStr("connecting to SCION Daemon", err)
	}
	defer sd.Close()

	info, err := app.QueryASInfo(ctx, sd)
	if err != nil {
		return "", err
	}

	localIP, err := addrutil.DefaultLocalIP(ctx, sd)
	if err != nil {
		return "", err
	}
	address := fmt.Sprintf("%s,%s", info.IA, localIP)
	return address, nil
}
