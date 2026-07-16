package main

import (
	"debuglet/internal/dispatcher/transport/api"
	"debuglet/internal/executor/ratelimit/app"
	"debuglet/internal/user"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	measurementAmount = flag.Int("measurements", 1, "amount of measurements to add")
	debugletAmount    = flag.Int("debuglets", 1, "amount of debuglets per measurement to add")
	wasmPath          = flag.String("wasm", "local/wasm_samples/go/ping/debuglet.wasm", "wasm to use")
	abort             = flag.Bool("abort", false, "if measurements should be aborted after they're submitted")
	delay             = flag.Duration("delay", 0, "the delay after which to start debuglets")
	executor          = flag.String("executor", "local-executor", "the executor to connect to")
	floorBW           = flag.Int64("floor", 1024, "Floor bandwidth (in bits) to request in the policy")
	ceilBW            = flag.Int64("ceil", 4096, "Ceiling bandwidth (in bits) to request in the policy")
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
					TimeoutMS: (10 * time.Second).Milliseconds(),
					Addresses: list,
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
