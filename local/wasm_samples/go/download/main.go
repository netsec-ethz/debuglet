package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
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

func main() {
	path := "/100MB.bin"
	host := "ash-speed.hetzner.com"
	addr := fmt.Sprintf("%s:80", host)
	addrp := uint32(uintptr(unsafe.Pointer(unsafe.StringData(addr))))
	sockID := connect_tcp(addrp, uint32(len(addr)))

	msg := fmt.Appendf([]byte{}, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: nc/0.0.1\r\nAccept: */*\r\n\r\n", path, host)
	msgp := uint32(uintptr(unsafe.Pointer(&msg[0])))
	send_tcp_data(sockID, msgp, uint32(len(msg)))

	wasmReader := &WasmReader{sockID: sockID}
	reader := bufio.NewReader(wasmReader)

	done := make(chan struct{})
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

				fmt.Printf("Current Speed: %.2f MB/s\n", float64(speed)/(1024*1024))
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

	body, err := io.ReadAll(resp.Body)
	close(done)
	if err != nil {
		log.Fatalf("Failed to read body: %v", err)
	}

	since := time.Since(start)
	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Body length: %d\n", len(body))
	fmt.Printf("Time passed: %s\n", since.Round(time.Second))
	fmt.Printf("Average speed: %.2f MB/s", float64(len(body))/since.Seconds()/(1024*1024))

}
