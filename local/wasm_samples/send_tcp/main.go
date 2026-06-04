package main

import (
	"fmt"
	"runtime"
	"unsafe"
)

//go:wasmimport env connect_tcp
func connect_tcp(addrPtr int32) int32

//go:wasmimport env receive_tcp_data
func receive_tcp_data(connID int32, length int32, bufferPtr int32) int32

//go:wasmimport env send_tcp_data
func send_tcp_data(connID int32, length int32, bufferPtr int32)

var tcpSendBuffer []byte = make([]byte, 100)
var tcpRecvBuffer []byte = make([]byte, 4096)
var pinner runtime.Pinner

func init() {
	pinner.Pin(&tcpSendBuffer[0])
	pinner.Pin(&tcpRecvBuffer[0])
}

//go:wasmexport run_debuglet
func run_debuglet() int32 {
	// requires addresses[0] to be "127.0.0.1:5173"
	connID := connect_tcp(0)
	if connID < 0 {
		fmt.Println("failed to connect")
		return 1
	}
	fmt.Println("connID", connID)

	msg := []byte("GET / HTTP/1.1\r\nHost: localhost:5173\r\nUser-Agent: nc/0.0.1\r\nAccept: */*\r\n\r\n")
	copiedLen := copy(tcpSendBuffer, msg)

	send_tcp_data(connID, int32(copiedLen), int32(uintptr(unsafe.Pointer(&tcpSendBuffer[0]))))
	fmt.Println("sent tcp request")

	n := receive_tcp_data(connID, int32(len(tcpRecvBuffer)), int32(uintptr(unsafe.Pointer(&tcpRecvBuffer[0]))))
	fmt.Println("received", n, "bytes")
	fmt.Println("response:", string(tcpRecvBuffer[:n]))

	return 0
}

func main() {}
