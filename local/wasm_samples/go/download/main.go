// Downloads a file from the target while indicating the download speed.
// Requires http-compatible endpoint.
//
// go run ./cmd/user -addr ash-speed.hetzner.com -ceil 1000000 -wasm local/wasm_samples/go/download/debuglet.wasm -- -target http://ash-speed.hetzner.com/100MB.bin

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
	target = flag.String("target", "http://ash-speed.hetzner.com/100MB.bin", "http path to download from")
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
	var contentLength int64
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
				if contentLength > 0 {
					percentage := float64(currentBytes) / float64(contentLength) * 100
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

	contentLength = resp.ContentLength
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
