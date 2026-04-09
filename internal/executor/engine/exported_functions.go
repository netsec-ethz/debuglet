// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package engine

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/wasmerio/wasmer-go/wasmer"
	"go.uber.org/zap"
)

// This file contains functions to be exported to the WASM modules

func wait_start(environment interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
	env := environment.(HostEnvironment)
	if err := checkContext(env); err != nil {
		return nil, err
	}

	return []wasmer.Value{}, nil
}

/*
### Functions for UDP communication ###
!!! CURRENTLY NOT SUPPORTED !!!
*/

func send_udp_packet(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
	udpAddresses []*net.UDPAddr,
	instanceTarget *wasmer.Instance,
	udpServer *net.PacketConn,
) ([]wasmer.Value, error) {
	env := environment.(HostEnvironment)
	if err := checkContext(env); err != nil {
		return nil, err
	}

	sugar.Debugw("send_udp_packet sending", "dst", udpAddresses[args[0].I32()])

	contents, err := extractSlice(instanceTarget, "udp_send_buffer", 0, args[1].I32())
	if err != nil {
		sugar.Warnw("Failed to extract slice", "sliceName", "udp_send_buffer", "err", err)
		return nil, fmt.Errorf("send_udp_packet failed to extract udp_send_buffer: %w", err)
	}

	_, err = (*udpServer).WriteTo(contents, udpAddresses[args[0].I32()])
	if err != nil {
		sugar.Warnw("Failed to write to UDP connection", "conn", udpServer, "err", err)
		return []wasmer.Value{wasmer.NewI64(0)}, fmt.Errorf("send_udp_packet failed to write to specified UDP address: %w", err)
	}

	return []wasmer.Value{wasmer.NewI64(time.Now().UnixNano())}, nil
}

func answer_udp_packet(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
	lastUdpReceived *net.Addr,
	udpAddresses []*net.UDPAddr,
	instanceTarget *wasmer.Instance,
	udpServer *net.PacketConn,
) ([]wasmer.Value, error) {
	env := environment.(HostEnvironment)
	if err := checkContext(env); err != nil {
		return nil, err
	}

	contents, err := extractSlice(instanceTarget, "udp_send_buffer", 0, args[1].I32())
	if err != nil {
		sugar.Warnw("Failed to extract slice", "sliceName", "udp_send_buffer", "err", err)
		return nil, fmt.Errorf("answer_udp_packet failed to extract udp_send_buffer: %w", err)
	}

	// answer_udp_packet sends a packet back to the source of the last UDP received packet.
	// It requires a "fallback" address in case of no packet was received previously
	if lastUdpReceived != nil {
		_, err := (*udpServer).WriteTo(contents, *lastUdpReceived)
		if err != nil {
			sugar.Warnw("Failed to write to UDP connection", "conn", udpServer, "err", err)
			return []wasmer.Value{wasmer.NewI64(0)}, fmt.Errorf("answer_udp_packet failed to write to specified UDP address: %w", err)
		}
	} else {
		sugar.Warnln("answer_udp_packet called but 'lastUdpReceived' is nil")

		_, err := (*udpServer).WriteTo(contents, udpAddresses[args[0].I32()])
		if err != nil {
			sugar.Warnw("Failed to write to UDP connection", "conn", udpServer, "err", err)
			return []wasmer.Value{wasmer.NewI64(0)}, fmt.Errorf("answer_udp_packet failed to write to specified UDP address: %w", err)
		}
	}

	return []wasmer.Value{wasmer.NewI64(time.Now().UnixNano())}, nil
}

func receive_udp_packet(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
	lastUdpReceived *net.Addr,
	instanceTarget *wasmer.Instance,
	udpServer *net.PacketConn,
) ([]wasmer.Value, error) {
	env := environment.(HostEnvironment)
	if err := checkContext(env); err != nil {
		return nil, err
	}

	contents, err := extractSlice(instanceTarget, "udp_receive_buffer", 0, 1024)
	if err != nil {
		sugar.Warnw("Failed to extract slice", "sliceName", "udp_receive_buffer", "err", err)
		return nil, fmt.Errorf("receive_udp_packet failed to extract udp_receive_buffer: %w", err)
	}

	err = (*udpServer).SetReadDeadline(time.Now().Add(time.Duration(args[0].I64()) * time.Nanosecond))
	if err != nil {
		sugar.Warnw("Failed to set reading deadline", "duration", args[0].I64(), "err", err)
		return nil, fmt.Errorf("receive_udp_packet failed to set reading deadline: %w", err)
	}

	l, addr, err := (*udpServer).ReadFrom(contents)
	if err != nil {
		sugar.Warnw("Failed to read from connection", "udpServer", udpServer, "err", err)
		l = -1
	}

	lastUdpReceived = &addr

	return []wasmer.Value{wasmer.NewI32(int32(l)), wasmer.NewI64(time.Now().UnixNano())}, nil
}

/*
### Functions to get time and wait ###
*/

func get_timestamp(environment interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
	env := environment.(HostEnvironment)
	if err := checkContext(env); err != nil {
		return nil, err
	}

	return []wasmer.Value{wasmer.NewI64(time.Now().UnixNano())}, nil
}

func wait_until(environment interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
	target := time.Unix(0, args[0].I64())
	now := time.Now()

	env := environment.(HostEnvironment)
	if err := checkContext(env); err != nil {
		return nil, err
	}

	select {
	case <-time.After(target.Sub(now)):
		break
	case <-env.ctx.Done():
		err := checkContext(env)
		return nil, err
	}

	return []wasmer.Value{}, nil
}

/*
### Functions for TCP communication ###
!!! CURRENTLY NOT SUPPORTED !!!
*/

func connect_tcp(
	environment interface{},
	args []wasmer.Value,
	addresses []string,
	sugar *zap.SugaredLogger,
	tcpConnectionList *[]*ConnWrapper,
) ([]wasmer.Value, error) {
	env := environment.(HostEnvironment)
	if err := checkContext(env); err != nil {
		return nil, err
	}

	tcpAddress, err := net.ResolveTCPAddr("tcp", addresses[args[0].I32()])
	if err != nil {
		sugar.Warnw("Failed to resolve TCP address", "addr", addresses[args[0].I32()], "err", err)
		return nil, fmt.Errorf("connect_tcp failed to resolve TCP address: %w", err)
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddress)
	if err != nil {
		sugar.Warnw("Failed to dial TCP address", "addr", tcpAddress, "err", err)
		return nil, fmt.Errorf("connect_tcp failed to dial TCP address: %w", err)
	}

	*tcpConnectionList = append(*tcpConnectionList, &ConnWrapper{tcpConn: conn, tls: false})
	handle := int32(len(*tcpConnectionList) - 1)

	return []wasmer.Value{wasmer.NewI32(handle)}, nil
}

func connect_tls(
	environment interface{},
	args []wasmer.Value,
	addresses []string,
	sugar *zap.SugaredLogger,
	tcpConnectionList *[]*ConnWrapper,
) ([]wasmer.Value, error) {
	env := environment.(HostEnvironment)
	if err := checkContext(env); err != nil {
		return nil, err
	}

	conn, err := tls.Dial("tcp", addresses[args[0].I32()], &tls.Config{})
	if err != nil {
		sugar.Warnw("Failed to dial TCP address", "addr", addresses[args[0].I32()], "err", err)
		return nil, fmt.Errorf("connect_tls failed to dial TCP address: %w", err)
	}

	*tcpConnectionList = append(*tcpConnectionList, &ConnWrapper{tlsConn: conn, tls: true})
	handle := int32(len(*tcpConnectionList) - 1)

	return []wasmer.Value{wasmer.NewI32(handle)}, nil
}

func accept_tcp(
	environment interface{},
	args []wasmer.Value,
	tcpServer *net.TCPListener,
	sugar *zap.SugaredLogger,
	tcpConnectionList *[]*ConnWrapper,
) ([]wasmer.Value, error) {
	env := environment.(HostEnvironment)
	if err := checkContext(env); err != nil {
		return nil, err
	}

	conn, err := tcpServer.AcceptTCP()
	if err != nil {
		sugar.Warnw("Failed to accept TCP connection", "err", err)
		return nil, fmt.Errorf("accept_tcp failed to accept TCP connection: %w", err)
	}

	*tcpConnectionList = append(*tcpConnectionList, &ConnWrapper{tcpConn: conn, tls: false})
	handle := int32(len(*tcpConnectionList) - 1)

	return []wasmer.Value{wasmer.NewI32(handle)}, nil
}

func receive_tcp_data(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
	tcpConnectionList []*ConnWrapper,
	instanceTarget *wasmer.Instance,
) ([]wasmer.Value, error) {
	env := environment.(HostEnvironment)
	if err := checkContext(env); err != nil {
		return nil, err
	}

	conn := tcpConnectionList[args[0].I32()]

	size := args[1].I32()

	toRead, err := extractSlice(instanceTarget, "tcp_receive_buffer", 0, size)
	if err != nil {
		sugar.Warnw("Failed to extract slice", "sliceName", "tcp_receive_buffer", "err", err)
		return nil, fmt.Errorf("receive_tcp_data failed to extract tcp_receive_buffer: %w", err)
	}

	l, err := conn.Read(toRead)
	if err != nil {
		sugar.Warnw("Failed to read from TCP connection", "conn", conn, "err", err)
		return nil, fmt.Errorf("receive_tcp_data failed to read TCP data: %w", err)
	}

	return []wasmer.Value{wasmer.NewI32(l)}, nil
}

func send_tcp_data(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
	tcpConnectionList []*ConnWrapper,
	instanceTarget *wasmer.Instance,
) ([]wasmer.Value, error) {
	env := environment.(HostEnvironment)
	if err := checkContext(env); err != nil {
		return nil, err
	}

	conn := tcpConnectionList[args[0].I32()]

	size := args[1].I32()
	offset := args[2].I32()

	toWrite, err := extractSlice(instanceTarget, "tcp_send_buffer", offset, offset+size)
	if err != nil {
		sugar.Warnw("Failed to extract slice", "sliceName", "tcp_send_buffer", "err", err)
		return nil, fmt.Errorf("send_tcp_data failed to extract tcp_send_buffer: %w", err)
	}

	_, err = conn.Write(toWrite)
	if err != nil {
		sugar.Warnw("Failed to write to TCP connection", "conn", conn, "err", err)
		return nil, fmt.Errorf("send_tcp_data failed to write TCP data: %w", err)
	}

	return []wasmer.Value{}, nil
}

func close_tcp(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
	tcpConnectionList []*ConnWrapper,
) ([]wasmer.Value, error) {
	env := environment.(HostEnvironment)
	if err := checkContext(env); err != nil {
		return nil, err
	}

	conn := tcpConnectionList[args[0].I32()]

	err := conn.Close()
	if err != nil {
		sugar.Warnw("Failed to close TCP connection", "conn", conn, "err", err)
		return nil, fmt.Errorf("close_tcp failed to close TCP connection: %w", err)
	}

	return []wasmer.Value{}, nil
}

/*
### Functions for UDP communication over SCION ###
*/

func send_scion_udp_packet(
	environment interface{},
	args []wasmer.Value,
	dialedScionConnections *[]*ScionDialWrapper,
	addresses []string,
	sugar *zap.SugaredLogger,
	instanceTarget *wasmer.Instance,
) ([]wasmer.Value, error) {
	env := environment.(HostEnvironment)
	if err := checkContext(env); err != nil {
		return nil, err
	}

	size := args[1].I32()
	address := args[0].I32()

	conn, err := dialScion(dialedScionConnections, addresses, address, env.ctx, sugar)
	if err != nil {
		if ctxErr := checkContext(env); ctxErr != nil {
			return nil, ctxErr
		}

		sugar.Warnw("Failed to dial SCION address", "err", err)
		return nil, fmt.Errorf("send_scion_udp_packet failed to dial SCION address: %w", err)
	}

	slice, err := extractSlice(instanceTarget, "udp_send_buffer", 0, size)
	if err != nil {
		sugar.Warnw("Failed to extract slice", "sliceName", "udp_send_buffer", "err", err)
		return nil, fmt.Errorf("send_scion_udp_packet failed to extract udp_send_buffer: %w", err)
	}

	deadline, ok := env.ctx.Deadline()
	if !ok {
		return nil, fmt.Errorf("Debuglet is running without a deadline")
	}
	(*conn.conn).SetDeadline(deadline)

	_, err = (*conn.conn).Write(slice)
	if err != nil {
		if ctxErr := checkContext(env); ctxErr != nil {
			return nil, ctxErr
		}

		sugar.Warnw("Failed to write to SCION UDP connection", "conn", *conn, "err", err)
		return nil, fmt.Errorf("send_scion_udp_packet failed to write SCION UDP data: %w", err)
	}

	return []wasmer.Value{wasmer.NewI64(time.Now().UnixNano())}, nil
}

// !!! CURRENTLY NOT SUPPORTED !!!
func answer_scion_udp_packet(
	environment interface{},
	args []wasmer.Value,
	lastReceived *net.Addr,
	dialedScionConnections *[]*ScionDialWrapper,
	addresses []string,
	sugar *zap.SugaredLogger,
	instanceTarget *wasmer.Instance,
	scionServer *pan.ListenConn,
) ([]wasmer.Value, error) {
	env := environment.(HostEnvironment)
	if err := checkContext(env); err != nil {
		return nil, err
	}

	size := args[1].I32()

	slice, err := extractSlice(instanceTarget, "udp_send_buffer", 0, size)
	if err != nil {
		sugar.Warnw("Failed to extract slice", "sliceName", "udp_send_buffer", "err", err)
		return nil, fmt.Errorf("answer_scion_udp_packet failed to extract udp_send_buffer: %w", err)
	}

	if lastReceived != nil {
		lastReceivedAddr, ok := (*lastReceived).(pan.UDPAddr)
		if !ok {
			sugar.Warnw("answer_scion_udp_packet couldn't convert lastReceived to UDPAddr", "lastReceived", *lastReceived)
			return []wasmer.Value{wasmer.NewI64(0)}, fmt.Errorf("answer_scion_udp_packet failed to convert lastReceived")
		}

		for _, addr := range addresses {
			validSCIONAddr, err := pan.ParseUDPAddr(addr)
			if err != nil {
				continue
			}

			if validSCIONAddr.IA == lastReceivedAddr.IA && validSCIONAddr.IP == lastReceivedAddr.IP {
				sugar.Debugw("Found matching known address, setting port", "oldPort", lastReceivedAddr.Port, "newPort", validSCIONAddr.Port)
				lastReceivedAddr = lastReceivedAddr.WithPort(validSCIONAddr.Port)
				break
			}
		}

		sugar.Debugw("answer_scion_udp_packet writing", "dst", lastReceivedAddr.String())
		_, err := (*scionServer).WriteTo(slice, lastReceivedAddr)
		if err != nil {
			sugar.Warnw("Failed to write to SCION UDP connection", "conn", scionServer, "err", err)
			return []wasmer.Value{wasmer.NewI64(0)}, fmt.Errorf("answer_scion_udp_packet failed to write SCION UDP data: %w", err)
		}
	} else {
		sugar.Warnln("answer_scion_udp_packet called but 'lastReceived' is nil")

		address := args[0].I32()

		conn, err := dialScion(dialedScionConnections, addresses, address, env.ctx, sugar)
		if err != nil {
			sugar.Warnw("Failed to dial SCION address", "err", err)
			return nil, fmt.Errorf("answer_scion_udp_packet failed to dial SCION address: %w", err)
		}

		_, err = (*conn.conn).Write(slice)
		if err != nil {
			sugar.Warnw("Failed to write to SCION UDP connection", "conn", *conn, "err", err)
			return []wasmer.Value{wasmer.NewI64(0)}, fmt.Errorf("answer_scion_udp_packet failed to write SCION UDP data: %w", err)
		}
	}

	return []wasmer.Value{wasmer.NewI64(time.Now().UnixNano())}, nil
}

func receive_scion_server_udp_packet(
	environment interface{},
	args []wasmer.Value,
	lastReceived *net.Addr,
	sugar *zap.SugaredLogger,
	instanceTarget *wasmer.Instance,
	scionServer *pan.ListenConn,
) ([]wasmer.Value, error) {
	env := environment.(HostEnvironment)
	if err := checkContext(env); err != nil {
		return nil, err
	}

	buf, err := extractSlice(instanceTarget, "udp_receive_buffer", 0, 1024)
	if err != nil {
		sugar.Warnw("Failed to extract slice", "sliceName", "udp_receive_buffer", "err", err)
		return nil, fmt.Errorf("receive_scion_server_udp_packet failed to extract udp_receive_buffer: %w", err)
	}

	deadline := time.Now().Add(time.Duration(args[0].I32()) * time.Millisecond)
	ctxDeadline, ok := env.ctx.Deadline()
	if !ok {
		return nil, fmt.Errorf("Debuglet is running without a deadline")
	}
	if ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	err = (*scionServer).SetReadDeadline(deadline)
	if err != nil {
		sugar.Warnw("Failed to set reading deadline", "duration", args[0].I32(), "err", err)
		return nil, fmt.Errorf("receive_scion_server_udp_packet failed to set reading deadline: %w", err)
	}

	l, from, err := (*scionServer).ReadFrom(buf)
	if err != nil {
		if ctxErr := checkContext(env); ctxErr != nil {
			return nil, ctxErr
		}

		sugar.Warnw("Failed to read from SCION connection", "conn", scionServer, "err", err, "l", l)
		lastReceived = nil
		l = 0
	} else {
		lastReceived = &from
	}

	return []wasmer.Value{wasmer.NewI32(l), wasmer.NewI64(time.Now().UnixNano())}, nil
}

/*
### Functions to interact with SCION paths ###
*/

func scion_available_paths(
	environment interface{},
	args []wasmer.Value,
	dialedScionConnections *[]*ScionDialWrapper,
	addresses []string,
	sugar *zap.SugaredLogger,
) ([]wasmer.Value, error) {
	env := environment.(HostEnvironment)
	if err := checkContext(env); err != nil {
		return nil, err
	}

	address := args[0].I32()

	d, err := dialScion(dialedScionConnections, addresses, address, env.ctx, sugar)
	if err != nil {
		if ctxErr := checkContext(env); ctxErr != nil {
			return nil, ctxErr
		}

		sugar.Warnw("Failed to dial SCION address", "err", err)
		return nil, fmt.Errorf("scion_available_paths failed to dial SCION address: %w", err)
	}

	result := len(d.selector.paths)

	return []wasmer.Value{wasmer.NewI32(result)}, nil
}

func scion_path_length(
	environment interface{},
	args []wasmer.Value,
	dialedScionConnections *[]*ScionDialWrapper,
	addresses []string,
	sugar *zap.SugaredLogger,
) ([]wasmer.Value, error) {
	env := environment.(HostEnvironment)
	if err := checkContext(env); err != nil {
		return nil, err
	}

	address := args[0].I32()
	offset := args[1].I32()

	d, err := dialScion(dialedScionConnections, addresses, address, env.ctx, sugar)
	if err != nil {
		if ctxErr := checkContext(env); ctxErr != nil {
			return nil, ctxErr
		}

		sugar.Warnw("Failed to dial SCION address", "err", err)
		return nil, fmt.Errorf("scion_path_length failed to dial SCION address: %w", err)
	}

	result := len(d.selector.paths[offset].Metadata.Interfaces) / 2

	return []wasmer.Value{wasmer.NewI32(result)}, nil
}

func scion_get_interface_details(
	environment interface{},
	args []wasmer.Value,
	dialedScionConnections *[]*ScionDialWrapper,
	addresses []string,
	sugar *zap.SugaredLogger,
) ([]wasmer.Value, error) {
	env := environment.(HostEnvironment)
	if err := checkContext(env); err != nil {
		return nil, err
	}

	address := args[0].I32()
	offset := args[1].I32()
	index := args[2].I32()

	d, err := dialScion(dialedScionConnections, addresses, address, env.ctx, sugar)
	if err != nil {
		if ctxErr := checkContext(env); ctxErr != nil {
			return nil, ctxErr
		}

		sugar.Warnw("Failed to dial SCION address", "err", err)
		return nil, fmt.Errorf("scion_get_interface_details failed to dial SCION address: %w", err)
	}

	sugar.Debugw("Requested details", "addr", address, "path", offset, "index", index, "details", d.selector.paths[offset].String())

	if len(d.selector.paths) <= int(offset) || len(d.selector.paths[offset].Metadata.Interfaces) <= int(index) {
		return []wasmer.Value{
			wasmer.NewI64(0),
			wasmer.NewI64(0)}, nil
	}

	return []wasmer.Value{
		wasmer.NewI64(int64(d.selector.paths[offset].Metadata.Interfaces[index].IA)),
		wasmer.NewI64(int64(d.selector.paths[offset].Metadata.Interfaces[index].IfID))}, nil
}

func scion_select_path(
	environment interface{},
	args []wasmer.Value,
	dialedScionConnections *[]*ScionDialWrapper,
	addresses []string,
	sugar *zap.SugaredLogger,
) ([]wasmer.Value, error) {
	env := environment.(HostEnvironment)
	if err := checkContext(env); err != nil {
		return nil, err
	}

	address := args[0].I32()
	offset := args[1].I32()

	d, err := dialScion(dialedScionConnections, addresses, address, env.ctx, sugar)
	if err != nil {
		if ctxErr := checkContext(env); ctxErr != nil {
			return nil, ctxErr
		}

		sugar.Warnw("Failed to dial SCION address", "err", err)
		return nil, fmt.Errorf("scion_select_path failed to dial SCION address: %w", err)
	}

	sugar.Debugw("scion_select_path called", "offset", offset)

	d.selector.ForcePath(int(offset))

	sugar.Debugw("scion_select_path selected path", "path", d.selector.Path().String())

	return []wasmer.Value{}, nil
}

/*
### Functions to write to console for debugging purposes ###
!!! SHOULD PROBABLY NOT BE EXPOSED TO END USERS !!!
*/

// This is just a helper and not actually to be exported
func write_helper(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
	instanceTarget *wasmer.Instance,
) ([]byte, error) {
	env := environment.(HostEnvironment)
	if err := checkContext(env); err != nil {
		return nil, err
	}

	size := args[0].I32()

	toWrite, err := extractSlice(instanceTarget, "write_buffer", 0, size)
	if err != nil {
		sugar.Warnw("Failed to extract slice", "sliceName", "write_buffer", "err", err)
		return nil, fmt.Errorf("write failed to extract write_buffer: %w", err)
	}

	return toWrite, nil
}

func write(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
	instanceTarget *wasmer.Instance,
) ([]wasmer.Value, error) {
	toWrite, err := write_helper(
		environment,
		args,
		sugar,
		instanceTarget,
	)
	if err != nil {
		return nil, err
	}

	fmt.Printf("%s\n", toWrite)
	sugar.Debugw("Debuglet wrote", "toWrite", toWrite)

	return []wasmer.Value{}, nil
}

func write_noeol(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
	instanceTarget *wasmer.Instance,
) ([]wasmer.Value, error) {
	toWrite, err := write_helper(
		environment,
		args,
		sugar,
		instanceTarget,
	)
	if err != nil {
		return nil, err
	}

	fmt.Printf("%s", toWrite)
	sugar.Debugw("Debuglet wrote", "toWrite", toWrite)

	return []wasmer.Value{}, nil
}

func write_i32(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
	instanceTarget *wasmer.Instance,
) ([]wasmer.Value, error) {
	env := environment.(HostEnvironment)
	if err := checkContext(env); err != nil {
		return nil, err
	}
	n := args[0].I32()

	fmt.Printf("%d", n)
	sugar.Debugw("Debuglet wrote", "toWrite", n)

	return []wasmer.Value{}, nil
}

func write_i64(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
	instanceTarget *wasmer.Instance,
) ([]wasmer.Value, error) {
	env := environment.(HostEnvironment)
	if err := checkContext(env); err != nil {
		return nil, err
	}

	n := args[0].I64()

	fmt.Printf("%d", n)
	sugar.Debugw("Debuglet wrote", "toWrite", n)

	return []wasmer.Value{}, nil
}

func write_i32x(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
	instanceTarget *wasmer.Instance,
) ([]wasmer.Value, error) {
	env := environment.(HostEnvironment)
	if err := checkContext(env); err != nil {
		return nil, err
	}

	n := args[0].I32()

	fmt.Printf("%x", n)
	sugar.Debugw("Debuglet wrote", "toWrite", fmt.Sprintf("%x", n))

	return []wasmer.Value{}, nil
}

func write_i64x(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
	instanceTarget *wasmer.Instance,
) ([]wasmer.Value, error) {
	env := environment.(HostEnvironment)
	if err := checkContext(env); err != nil {
		return nil, err
	}

	n := args[0].I64()

	fmt.Printf("%x", n)
	sugar.Debugw("Debuglet wrote", "toWrite", fmt.Sprintf("%x", n))

	return []wasmer.Value{}, nil
}

func write_delta_timestamp(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
) ([]wasmer.Value, error) {
	env := environment.(HostEnvironment)
	if err := checkContext(env); err != nil {
		return nil, err
	}

	target := time.Duration(args[0].I64())

	fmt.Printf("duration: %s\n", target.String())
	sugar.Debugw("Debuglet wrote time delta", "delta", target.String())

	return []wasmer.Value{}, nil
}

/*
### Function to dump result to file on executor machine ###
!!! SHOULD PROBABLY NOT BE EXPORTED !!!
*/

func dump_result(
	environment interface{},
	args []wasmer.Value,
	sugar *zap.SugaredLogger,
	instanceTarget *wasmer.Instance,
) ([]wasmer.Value, error) {
	env := environment.(HostEnvironment)
	if err := checkContext(env); err != nil {
		return nil, err
	}

	size := args[0].I32()

	toWrite, err := extractSlice(instanceTarget, "result", 0, size)
	if err != nil {
		sugar.Warnw("Failed to extract slice", "sliceName", "result", "err", err)
		return nil, fmt.Errorf("dump_result failed to extract result: %w", err)
	}

	err = os.WriteFile(fmt.Sprintf("results/%s.dat", time.Now().String()), toWrite, 0644)
	if err != nil {
		sugar.Errorw("Failed to write results file", "fileName", toWrite)
	}

	return []wasmer.Value{}, nil
}

/*
!!! I DON'T EVEN KNOW WHAT THIS ONE DOES. I FOUND IT THERE, IT WAS COMMENTED OUT
AND ONLY LEFT IT IN BECAUSE I FELT BAD DELETING IT. !!!
*/

// func fetch_scion_paths(environment interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
// 	span, traceCtx := tracing.CtxWith(context.Background(), "run")
// 	remote := C(snet.ParseUDPAddr("17-ffaa:1:1084,127.0.0.1"))

// 	span.SetTag("dst.isd_as", remote.IA)
// 	span.SetTag("dst.host", remote.Host.IP)
// 	defer span.Finish()

// 	ctx, cancelF := context.WithTimeout(traceCtx, 5*time.Second)
// 	defer cancelF()
// 	sd := C(daemon.NewService(scionDaemonAddress).Connect(ctx))

// 	info := C(app.QueryASInfo(traceCtx, sd))

// 	span.SetTag("src.isd_as", info.IA)

// 	//fmt.Printf("%#v\n", info)

// 	opts := []path.Option{}

// 	//all := C(sd.Paths(traceCtx, remote.IA, 0, daemon.PathReqFlags{Refresh: false}))

// 	//for i, s := range all {
// 	//	fmt.Printf("path %d: %s\n", i, path.DefaultColorScheme(false).Path(s))
// 	//
// 	//}

// 	picked := C(path.Choose(traceCtx, sd, remote.IA, opts...))

// 	remote.Path = picked.Dataplane()
// 	remote.NextHop = picked.UnderlayNextHop()

// 	return []wasmer.Value{}, nil
// }
