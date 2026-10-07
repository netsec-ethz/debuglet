// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
 "context"
 "errors"
 "fmt"
 "os"
 "time"

 "github.com/netsec-ethz/debuglet/pkg/debuglet"
)

func main() {
 ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
 defer cancel()
 if os.Args[0] == "deadline" { ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond); defer cancel() }
 exp, err := debuglet.Ready(ctx, []byte("guest endpoint"))
 if err != nil { fmt.Printf("deadline=%v late=%v\n", errors.Is(err, context.DeadlineExceeded), errors.Is(err, debuglet.ErrExperimentLate)); return }
 fmt.Printf("experiment=%s members=%d peer=%s\n", exp.ID, len(exp.Participants), exp.Participants[0].Metadata)
 err = debuglet.WaitStart(ctx, exp)
 fmt.Printf("wait=%v observed=%d target=%d\n", err, time.Now().UnixNano(), exp.StartTimeNS)
}
