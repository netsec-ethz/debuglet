package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"time"
	"unsafe"
)

//go:wasmimport env sleep
func sleep(ts int64)

//go:wasmimport env connect_icmp4
func connect_icmp4(addrPtr int32) int32

//go:wasmimport env receive_icmp4_data
func receive_icmp4_data(connID int32, length int32, bufferPtr int32) int32

//go:wasmimport env send_icmp4_data
func send_icmp4_data(connID int32, length int32, bufferPtr int32)

//go:wasmimport env close_icmp4
func close_icmp4(connID int32)

var sendBuffer []byte = make([]byte, 64)
var recvBuffer []byte = make([]byte, 100)
var pinner runtime.Pinner

func main() {}

func init() {
	pinner.Pin(&sendBuffer[0])
	pinner.Pin(&recvBuffer[0])
}

//go:wasmexport run_debuglet
func run_debuglet() int32 {
	for seq := range 5 {
		taken, err := ping(1, uint16(seq))
		if err != nil {
			panic(err)
		}
		sleep(int64(time.Second - min(time.Second, taken)))
	}

	return 0
}

func createEchoPacket(id uint16, seq uint16, size int) []byte {
	echo := make([]byte, size)
	echo[0] = 8
	binary.BigEndian.PutUint16(echo[4:6], id)
	binary.BigEndian.PutUint16(echo[6:8], seq)

	sum := ^((uint16(echo[0])<<8 | uint16(echo[1])) +
		(uint16(echo[4])<<8 | uint16(echo[5])) +
		(uint16(echo[6])<<8 | uint16(echo[7])))
	binary.BigEndian.PutUint16(echo[2:4], sum)
	return echo
}

func ping(id uint16, seq uint16) (time.Duration, error) {
	connID := connect_icmp4(0)
	if connID == -1 {
		return 0, errors.New("failed to setup socket")
	}
	defer close_icmp4(connID)

	echo := createEchoPacket(id, seq, 64)
	copy(sendBuffer, echo)

	start := time.Now()

	send_icmp4_data(connID, int32(len(sendBuffer)), int32(uintptr(unsafe.Pointer(&sendBuffer[0]))))
	n := receive_icmp4_data(connID, int32(len(recvBuffer)), int32(uintptr(unsafe.Pointer(&recvBuffer[0]))))

	taken := time.Since(start)

	if n < 20 {
		return 0, errors.New("missing ip header")
	}
	ihl := (recvBuffer[0] & 0xF) * 4

	fmt.Printf("%d bytes: icmp_seq=%d  time=%v\n", n-int32(ihl), seq, taken)
	return taken, nil
}
