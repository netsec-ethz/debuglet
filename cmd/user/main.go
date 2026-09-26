// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"flag"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/api"
	"github.com/netsec-ethz/debuglet/internal/executor/ratelimit/app"
	"github.com/netsec-ethz/debuglet/internal/user"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	dispatcherAddr    = flag.String("dispatcher", "localhost:9000", "dispatcher address (host:port)")
	dispatcherTLS     = flag.Bool("tls", false, "use HTTPS when talking to the dispatcher")
	measurementAmount = flag.Int("measurements", 1, "amount of measurements to add")
	debugletAmount    = flag.Int("debuglets", 1, "amount of debuglets per measurement to add")
	wasmPath          = flag.String("wasm", "examples/debuglets/go/ping/debuglet.wasm", "wasm to use")
	abort             = flag.Bool("abort", false, "if measurements should be aborted right after they're submitted")
	delay             = flag.Duration("delay", 0, "the delay after which to start debuglets")
	executor          = flag.String("executor", "ac4e023b-1b69-44ed-905f-640e7a1841b4", "the executor to connect to")
	floorBW           = flag.Int64("floor", 0, "Floor bandwidth (in bits) to request in the policy. Defaults to ceil.")
	ceilBW            = flag.Int64("ceil", 4096, "Ceiling bandwidth (in bits) to request in the policy")
	timeout           = flag.Duration("timeout", 10*time.Second, "Timeout for debuglet execution")
	listenTCP         = flag.Bool("listen-tcp", false, "request a TCP listening server")
	listenUDP         = flag.Bool("listen-udp", false, "request a UDP listening server")
)

type stringSlice []string

func (s *stringSlice) String() string         { return strings.Join(*s, ",") }
func (s *stringSlice) Set(value string) error { *s = append(*s, value); return nil }

func main() {
	var list stringSlice
	flag.Var(&list, "addr", "addresses to connect to (can be specified multiple times)")
	flag.Parse()
	// collects arguments after `--`
	passthroughArgs := flag.Args()

	user.DispatcherAddr = *dispatcherAddr
	user.DispatcherTLS = *dispatcherTLS

	if *floorBW == 0 {
		floorBW = ceilBW
	}
	var (
		runningDebuglets   []string
		runningDebugletsMu sync.Mutex
	)

	// handle Ctrl+C: abort all running debuglets before exiting
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT)
	go func() {
		<-sigCh
		runningDebugletsMu.Lock()
		for _, ID := range runningDebuglets {
			log.Printf("Aborting debuglet [%s]\n", ID)
			user.AbortDebuglet(ID, *executor)
		}
		runningDebugletsMu.Unlock()
		os.Exit(0)
	}()

	wg := sync.WaitGroup{}
	wg.Add(*measurementAmount * *debugletAmount)

	for i := range *measurementAmount {
		go func(i int) {
			start := time.Now().Add(*delay)
			seconds := start.Unix()
			log.Printf("creating measurement i=%d\n", i)
			debugletIDs := user.CreateMeasurement(*wasmPath, *debugletAmount, api.DebugletRequest{
				ExecutorID:     *executor,
				StartTimestamp: &seconds,
				Args:           passthroughArgs,
				Policy: api.DebugletPolicyRequest{
					FloorBW:   *floorBW,
					CeilBW:    *ceilBW,
					TimeoutMS: timeout.Milliseconds(),
					Addresses: list,
					ListenTCP: *listenTCP,
					ListenUDP: *listenUDP,
				},
			})
			log.Printf("added debuglets i=%d, len=%d, ceil=%s\n", i, len(debugletIDs), app.Bitrate(*ceilBW))
			for j, m := range debugletIDs {
				log.Printf("\t%d. %s\n", j, m)
			}

			for _, ID := range debugletIDs {
				runningDebugletsMu.Lock()
				runningDebuglets = append(runningDebuglets, ID)
				runningDebugletsMu.Unlock()
				go func() {
					defer func() {
						runningDebugletsMu.Lock()
						for idx, rid := range runningDebuglets {
							if rid == ID {
								runningDebuglets = append(runningDebuglets[:idx], runningDebuglets[idx+1:]...)
								break
							}
						}
						runningDebugletsMu.Unlock()
						wg.Done()
					}()
					if *abort {
						for range 5 {
							time.Sleep(time.Second)
							if status := user.AbortDebuglet(ID, *executor); status != 400 {
								break
							}
						}
						return
					}

					if err := user.ReadOutput(ID); err != nil {
						log.Printf("error reading output for debuglet %s: %v\n", ID, err)
					}
					resp, err := user.ReadState(ID)
					if err != nil {
						log.Printf("error reading state for debuglet %s: %v\n", ID, err)
						return
					}
					if resp.Error != "" {
						log.Printf("debuglet %s failed with error: %s\n", ID, resp.Error)
					} else {
						log.Printf("debuglet %s finished successfully\n", ID)
					}
				}()
			}
		}(i)
	}

	wg.Wait()
}
