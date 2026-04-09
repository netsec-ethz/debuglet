// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package shared

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet/addrutil"
	"github.com/scionproto/scion/private/app"
)

func Check(err error) {
	if err != nil {
		panic(err)
	}
}

func W(pos string) {
	_, file, line, _ := runtime.Caller(1)

	println(time.Now().String(), pos, file, line)
}

func C[T interface{}](res T, err error) T {
	Check(err)
	return res
}

func C2[T, U interface{}](res T, res2 U, err error) (T, U) {
	Check(err)
	return res, res2
}

func GetScionAddr() (string, error) {
	daemonAddr := os.Getenv("SCION_DAEMON_ADDRESS")
	if daemonAddr == "" {
		return "", serrors.New("SCION_DAEMON_ADDRESS not set")
	}
	ctx := context.Background()
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
