package main

import (
	"context"
	measurement "debuglet/internal/user"
	"flag"
	"log"
	"sync"
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
			measurementID := measurement.CreateMeasurement(
				*wasmPath,
				*debugletAmount,
				"executor-1",
				1000,
				4096,
				7000,
				[]string{"google.com:80"},
			)
			log.Printf("created measurement i=%d, ID=%s\n", i, measurementID)

			start := measurement.ConnectMeasurement(measurementID)
			log.Printf("connected to measurement websocket ID=%s\n", measurementID)

			log.Printf("starting measurement ID=%s\n", measurementID)
			start(context.TODO())

			wg.Done()
		}(i)
	}

	wg.Wait()
}
