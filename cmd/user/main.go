package main

import (
	"debuglet/internal/dispatcher/transport/api"
	"debuglet/internal/user"
	"flag"
	"log"
	"sync"
	"time"
)

var (
	measurementAmount = flag.Int("measurements", 1, "amount of measurements to add")
	debugletAmount    = flag.Int("debuglets", 1, "amount of debuglets per measurement to add")
	wasmPath          = flag.String("wasm", "local/wasm_samples/ping/debuglet.wasm", "wasm to use")
	abort             = flag.Bool("abort", false, "if measurements should be aborted after they're submitted")
	delay             = flag.Duration("delay", 0, "the delay after which to start debuglets")
)

func main() {
	flag.Parse()

	wg := sync.WaitGroup{}
	wg.Add(*measurementAmount)

	for i := range *measurementAmount {
		go func(i int) {
			start := time.Now().Add(*delay)
			seconds := start.Unix()
			log.Printf("creating measurement i=%d\n", i)
			debugletIDs := user.CreateMeasurement(*wasmPath, *debugletAmount, api.DebugletRequest{
				ExecutorID:     "executor-1",
				StartTimestamp: &seconds,
				Policy: api.DebugletPolicyRequest{
					FloorBW:   1000,
					CeilBW:    4096,
					TimeoutMS: (10 * time.Second).Milliseconds(),
					Addresses: []string{"google.com:80"},
				},
			})
			log.Printf("added debuglets i=%d, len=%d\n", i, len(debugletIDs))
			for j, m := range debugletIDs {
				log.Printf("\t%d. %s\n", j, m)
			}

			if *abort {
				time.Sleep(time.Second)
				user.AbortDebuglet(debugletIDs[0])
			} else {
				for {
					err := user.ReadOutput(debugletIDs[0])
					if err == nil {
						break
					}
					time.Sleep(time.Second)
				}
			}

			wg.Done()
		}(i)
	}

	wg.Wait()
}
