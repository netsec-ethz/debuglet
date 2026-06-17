package main

import (
	"fmt"
)

//go:wasmimport env connect_tcp
func connect_tcp(addrp, addrLen uint32) int32

//go:wasmimport env connect_tls
func connect_tls(addrp, addrLen uint32) int32

//go:wasmimport env accept_tcp
func accept_tcp() int32

//go:wasmimport env receive_tcp_data
func receive_tcp_data(sockID int32, bufp, bufLen uint32) int32

//go:wasmimport env send_tcp_data
func send_tcp_data(sockID int32, bufp, bufLen uint32)

//go:wasmimport env close_tcp
func close_tcp(connID int32)

//go:wasmimport env send_scion_udp_packet
func send_scion_udp_packet(addrp, addrLen, sendp, sendLen uint32) int64

//go:wasmimport env receive_scion_server_udp_packet
// func receive_scion_server_udp_packet(recvp, recvLen uint32, timeout int32) (int32, int64)

//go:wasmimport env answer_scion_udp_packet
func answer_scion_udp_packet(addrp, addrLen, sendp, sendLen uint32) int64

//go:wasmimport env scion_available_paths
func scion_available_paths(addrp, addrLen uint32) int32

//go:wasmimport env scion_path_length
func scion_path_length(addrp, addrLen uint32, pathIdx int32) int32

//go:wasmimport env scion_get_interface_details
// func scion_get_interface_details(addrp, addrLen uint32, pathIdx int32, ifIdx int32) (int64, int64)

//go:wasmimport env scion_select_path
func scion_select_path(addrp, addrLen uint32, pathIdx int32)

func main() {
	fmt.Println("Hello from Debuglet!")
}
