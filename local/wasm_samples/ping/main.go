package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"
	"unsafe"
)

//go:wasmimport env connect_icmp4
func connect_icmp4(addrp, addrLen uint32) int32

//go:wasmimport env receive_icmp4_data
func receive_icmp4_data(sockID int32, bufPtr uint32, bufLen uint32) int32

//go:wasmimport env send_icmp4_data
func send_icmp4_data(sockID int32, bufPtr, bufLen uint32)

//go:wasmimport env close_icmp4
func close_icmp4(connID int32)

var (
	addr = flag.String("addr", "1.1.1.1", "address to contact")
	iter = flag.Int("iter", 1, "times to send a ping request")
)

func main() {
	// os.Args does not include the binary/command
	flag.CommandLine.Parse(os.Args)

	for seq := range *iter {
		taken, err := ping(1, uint16(seq))
		if err != nil {
			panic(err)
		}
		time.Sleep(time.Second - min(time.Second, taken))
	}
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
	ptr := uint32(uintptr(unsafe.Pointer(unsafe.StringData(*addr))))
	connID := connect_icmp4(ptr, uint32(len(*addr)))
	if connID == -1 {
		return 0, errors.New("failed to setup socket")
	}
	defer close_icmp4(connID)

	echo := createEchoPacket(id, seq, 64)

	start := time.Now()

	send_icmp4_data(connID, uint32(uintptr(unsafe.Pointer(&echo[0]))), uint32(len(echo)))
	var recvBuffer []byte = make([]byte, 100)
	n := receive_icmp4_data(connID, uint32(uintptr(unsafe.Pointer(&recvBuffer[0]))), uint32(len(recvBuffer)))

	taken := time.Since(start)

	if n < 20 {
		return 0, errors.New("missing ip header")
	}
	ihl := (recvBuffer[0] & 0xF) * 4

	fmt.Printf("%d bytes: icmp_seq=%d  time=%v\n", n-int32(ihl), seq, taken)
	return taken, nil
}
