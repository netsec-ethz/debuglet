package main

import (
	"flag"
	"fmt"
	"os"
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
	addr = flag.String("addr", "google.com:80", "address and port to contact")
	iter = flag.Int("iter", 1, "times to send a request")
)

func main() {
	// os.Args does not include the binary/command
	flag.CommandLine.Parse(os.Args)

	fmt.Printf("Sending GET / to %s for %d times\n", *addr, *iter)
	ptr := uint32(uintptr(unsafe.Pointer(unsafe.StringData(*addr))))
	connID := connect_tcp(ptr, uint32(len(*addr)))
	if connID < 0 {
		panic("failed to connect")
	}

	fmt.Println("connID", connID)

	msg := fmt.Appendf([]byte{}, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: nc/0.0.1\r\nAccept: */*\r\n\r\n", *addr)

	for i := range *iter {
		send_tcp_data(connID, uint32(uintptr(unsafe.Pointer(&msg[0]))), uint32(len(msg)))
		fmt.Println("sent tcp request")

		var tcpRecvBuffer []byte = make([]byte, 1024)
		n := receive_tcp_data(connID, uint32(uintptr(unsafe.Pointer(&tcpRecvBuffer[0]))), uint32(len(tcpRecvBuffer)))
		fmt.Println("received", n, "bytes")
		fmt.Println("response:", string(tcpRecvBuffer[:n]))

		if i != *iter-1 {
			time.Sleep(time.Second)
		}
	}
}
