package main

import (
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
)

func main() {
	flag.Parse()

	wg := sync.WaitGroup{}
	wg.Add(*measurementAmount)

	for i := range *measurementAmount {
		go func(i int) {
			log.Printf("creating measurement i=%d\n", i)
			debugletIDs := user.CreateMeasurement(
				*wasmPath,
				*debugletAmount,
				"executor-1",
				1000,
				4096,
				10*time.Second,
				[]string{"google.com:80"},
			)
			log.Printf("added debuglets i=%d, len=%d\n", i, len(debugletIDs))
			for j, m := range debugletIDs {
				log.Printf("\t%d. %s\n", j, m)
			}

			time.Sleep(time.Second)
			user.ReadOutput(debugletIDs[0])

			wg.Done()
		}(i)
	}

	wg.Wait()
}
