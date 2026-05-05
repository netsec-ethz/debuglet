package main

import (
	"fmt"
)

//go:wasmimport env wait_start
func wait_start()

//go:wasmimport env get_timestamp
func get_timestamp() int64

//go:wasmimport env wait_until
func wait_until(ts int64)

//go:wasmimport env connect_tcp
func connect_tcp(addrPtr int32) int32

//go:wasmimport env connect_tls
func connect_tls(addrPtr int32) int32

//go:wasmimport env accept_tcp
func accept_tcp() int32

//go:wasmimport env receive_tcp_data
func receive_tcp_data(connID int32, length int32, bufferPtr int32) int32

//go:wasmimport env send_tcp_data
func send_tcp_data(connID int32, bufferPtr int32, length int32)

//go:wasmimport env close_tcp
func close_tcp(connID int32)

//go:wasmimport env send_scion_udp_packet
func send_scion_udp_packet(connID int32, packetPtr int32) int64

// //go:wasmimport env receive_scion_server_udp_packet
// func receive_scion_server_udp_packet(bufferPtr int32) (int32, int64)

//go:wasmimport env scion_available_paths
func scion_available_paths(connID int32) int32

//go:wasmimport env scion_path_length
func scion_path_length(connID int32, pathIndex int32) int32

// //go:wasmimport env scion_get_interface_details
// func scion_get_interface_details(connID int32, pathIndex int32, interfaceIndex int32) (int64, int64)

//go:wasmimport env scion_select_path
func scion_select_path(connID int32, pathIndex int32)

//go:wasmimport env write
func write(strPtr int32)

//go:wasmimport env write_noeol
func write_noeol(strPtr int32)

//go:wasmimport env write_i32
func write_i32(val int32)

//go:wasmimport env write_i64
func write_i64(val int64)

//go:wasmimport env write_i32x
func write_i32x(val int32)

//go:wasmimport env write_i64x
func write_i64x(val int64)

//go:wasmimport env write_delta_timestamp
func write_delta_timestamp(ts int64)

//go:wasmexport run_debuglet
func run_debuglet() int32 {
	fmt.Println("Hello from Debuglet!")
	return 0
}

func main() {}
