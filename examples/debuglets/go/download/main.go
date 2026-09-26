// download — HTTP download rate over the raw host imports.
//
// This sample calls the executor's imports directly instead of using the guest
// SDK, so it shows what the SDK does with pointers and lengths. Prefer the SDK
// (see the http_get sample) unless you need that level of detail.
//
// It reports the transfer rate of one HTTP response body. Point it at a target
// you are authorized to measure and add that target to the job's --allow list:
//
//	make wasm SAMPLE_DIR=examples/debuglets/go/download
//	dbl run --wasm examples/debuglets/go/download/debuglet.wasm \
//	  --executor EXECUTOR_ID --allow 127.0.0.1 --ceil-bps 1000000 --wait \
//	  -- -target http://127.0.0.1:8080/payload.bin

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sync/atomic"
	"time"
	"unsafe"
)

//go:wasmimport env connect_tcp
func connect_tcp(addrp, addrLen uint32) int32

//go:wasmimport env receive_tcp_data
func receive_tcp_data(sockID int32, bufPtr uint32, bufLen uint32) int32

//go:wasmimport env send_tcp_data
func send_tcp_data(sockID int32, bufPtr, bufLen uint32)

var (
	target = flag.String("target", "http://127.0.0.1:8080/", "http URL to download")
)

type WasmReader struct {
	sockID    int32
	bytesRead atomic.Int64
}

func (w *WasmReader) Read(p []byte) (int, error) {
	ptr := uint32(uintptr(unsafe.Pointer(&p[0])))
	n := receive_tcp_data(w.sockID, ptr, uint32(len(p)))
	w.bytesRead.Add(int64(n))

	runtime.Gosched()

	if n == 0 {
		return 0, io.EOF
	}
	return int(n), nil
}

func (w *WasmReader) BytesRead() int64 {
	return w.bytesRead.Load()
}

type Bitrate uint64

func (b Bitrate) Bytes() uint64 { return (uint64(b) + 7) / 8 }
func FromBytes(b int64) Bitrate { return Bitrate(b * 8) }

func (b Bitrate) String() string {
	bytes := b.Bytes()
	switch {
	case bytes >= 1<<30:
		return fmt.Sprintf("%.1fGiB", float64(bytes)/float64(1<<30))
	case bytes >= 1<<20:
		return fmt.Sprintf("%.1fMiB", float64(bytes)/float64(1<<20))
	case bytes >= 1<<10:
		return fmt.Sprintf("%.1fKiB", float64(bytes)/float64(1<<10))
	default:
		return fmt.Sprintf("%dB", uint64(bytes))
	}
}

func main() {
	flag.CommandLine.Parse(os.Args)
	u, err := url.Parse(*target)
	if err != nil {
		log.Fatalf("Failed to parse URL: %v", err)
	}
	host := u.Host
	if u.Port() == "" {
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	fmt.Printf("[*] downloading: %s\n", *target)
	addrp := uint32(uintptr(unsafe.Pointer(unsafe.StringData(host))))
	sockID := connect_tcp(addrp, uint32(len(host)))

	msg := fmt.Appendf([]byte{}, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: nc/0.0.1\r\nAccept: */*\r\n\r\n", u.Path, host)
	msgp := uint32(uintptr(unsafe.Pointer(&msg[0])))
	send_tcp_data(sockID, msgp, uint32(len(msg)))

	wasmReader := &WasmReader{sockID: sockID}
	reader := bufio.NewReader(wasmReader)

	done := make(chan struct{})
	// contentLength is published by the main goroutine and read by the
	// progress goroutine, so it is stored atomically.
	var contentLength atomic.Int64
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		var lastBytes int64
		for {
			select {
			case <-ticker.C:
				currentBytes := wasmReader.BytesRead()
				speed := currentBytes - lastBytes
				lastBytes = currentBytes

				fmt.Printf("Current Speed: %s/s", FromBytes(speed))
				if total := contentLength.Load(); total > 0 {
					percentage := float64(currentBytes) / float64(total) * 100
					fmt.Printf(" (%.2f%%)", percentage)
				}
				fmt.Println()
			case <-done:
				return
			}
		}
	}()

	start := time.Now()

	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	contentLength.Store(resp.ContentLength)
	body, err := io.ReadAll(resp.Body)
	close(done)
	if err != nil {
		log.Fatalf("Failed to read body: %v", err)
	}

	since := time.Since(start)
	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Body length: %d\n", len(body))
	fmt.Printf("Time passed: %s\n", since.Round(time.Second))
	fmt.Printf("Average speed: %s/s", FromBytes(int64(float64(len(body))/since.Seconds())))

}
