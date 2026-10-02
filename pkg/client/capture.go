// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"time"
)

// Capture limits (docs/verification.md#limits). A larger capture is rejected,
// never truncated, so a verdict always covers the whole capture it names.
const (
	// MaxCaptureBytes bounds a capture read by ReadCapture.
	MaxCaptureBytes = 64 << 20
	// MaxCapturePackets bounds the packets ReadCapture returns.
	MaxCapturePackets = 1_000_000
	// maxRecordBytes bounds one captured frame: 256 KiB is the largest snap
	// length libpcap writes, so a longer record is a malformed length.
	maxRecordBytes = 256 << 10
)

// Link types ReadCapture strips down to the IP header.
const (
	linkTypeNull     = 0   // BSD loopback, host-endian address family
	linkTypeEthernet = 1   // Ethernet, with 802.1Q/802.1ad tags
	linkTypeRaw      = 101 // raw IPv4 or IPv6
	linkTypeLoop     = 108 // OpenBSD loopback, big-endian address family
	linkTypeLinuxSLL = 113 // Linux cooked capture v1 (tcpdump -i any)
	linkTypeIPv4     = 228 // raw IPv4
	linkTypeIPv6     = 229 // raw IPv6
	linkTypeSLL2     = 276 // Linux cooked capture v2
)

// CapturedPacket is one frame of a capture.
type CapturedPacket struct {
	// Data is the IP packet, starting at the IPv4 or IPv6 header, without
	// the link-layer header. An IPv4 packet is cut to its Total Length, so
	// link-layer padding and trailers are not part of it; a packet the
	// capture recorded only partly (snap length) is kept as recorded. Data
	// is empty for a frame of a link type ReadCapture does not know.
	Data []byte
	// CapturedAt is the capture's timestamp of the frame: the capture host's
	// clock, which offline verification has to trust.
	CapturedAt time.Time
	// LinkType is the capture's link-layer header type of the frame.
	LinkType uint16
}

// CaptureError reports a capture ReadCapture cannot read in full: not a pcap
// or pcapng file, a malformed or truncated record, or a capture over a limit.
type CaptureError struct {
	// Offset is the byte offset of the offending record, -1 when none.
	Offset int64
	Msg    string
}

func (e *CaptureError) Error() string {
	if e.Offset < 0 {
		return "client: read capture: " + e.Msg
	}
	return fmt.Sprintf("client: read capture: at byte %d: %s", e.Offset, e.Msg)
}

func captureErr(offset int, format string, args ...any) error {
	return &CaptureError{Offset: int64(offset), Msg: fmt.Sprintf(format, args...)}
}

// ReadCapture reads a pcap (microsecond or nanosecond) or pcapng capture and
// returns its IP packets in capture order. It understands Ethernet (with
// VLAN tags), raw IP, Linux cooked (SLL and SLL2) and BSD loopback link
// types; non-IP frames of those (ARP, LLDP, …) are skipped, and frames of any
// other link type are returned with empty Data so a verifier can report them
// unsupported. A capture larger than MaxCaptureBytes or holding more than
// MaxCapturePackets frames, a record whose length is malformed and a capture
// that ends inside a record are rejected with a *CaptureError: nothing is
// silently dropped.
func ReadCapture(r io.Reader) ([]CapturedPacket, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxCaptureBytes+1))
	if err != nil {
		return nil, fmt.Errorf("client: read capture: %w", err)
	}
	if len(data) > MaxCaptureBytes {
		return nil, &CaptureError{Offset: -1, Msg: fmt.Sprintf("capture exceeds %d MiB; split it (for example with editcap -c) or filter it to the probe traffic", MaxCaptureBytes>>20)}
	}
	if len(data) < 4 {
		return nil, &CaptureError{Offset: -1, Msg: "not a pcap or pcapng file (too short)"}
	}
	if binary.BigEndian.Uint32(data) == 0x0A0D0D0A {
		return readPcapng(data)
	}
	return readPcap(data)
}

func readPcap(data []byte) ([]CapturedPacket, error) {
	var order binary.ByteOrder
	var fracNS int64
	switch binary.BigEndian.Uint32(data) {
	case 0xd4c3b2a1:
		order, fracNS = binary.LittleEndian, 1000
	case 0xa1b2c3d4:
		order, fracNS = binary.BigEndian, 1000
	case 0x4d3cb2a1:
		order, fracNS = binary.LittleEndian, 1
	case 0xa1b23c4d:
		order, fracNS = binary.BigEndian, 1
	default:
		return nil, &CaptureError{Offset: -1, Msg: "not a pcap or pcapng file (unknown magic number)"}
	}
	if len(data) < 24 {
		return nil, captureErr(0, "truncated pcap file header")
	}
	// The upper bits of the link type field carry the FCS length.
	link := uint16(order.Uint32(data[20:24]))
	var out []CapturedPacket
	for pos := 24; pos < len(data); {
		if len(data)-pos < 16 {
			return nil, captureErr(pos, "capture ends inside a record header; the file is truncated")
		}
		sec := int64(order.Uint32(data[pos:]))
		frac := int64(order.Uint32(data[pos+4:]))
		caplen := int(order.Uint32(data[pos+8:]))
		if frac*fracNS >= int64(time.Second) {
			return nil, captureErr(pos, "malformed timestamp fraction %d", frac)
		}
		if caplen > maxRecordBytes {
			return nil, captureErr(pos, "malformed record length %d", caplen)
		}
		if len(data)-pos-16 < caplen {
			return nil, captureErr(pos, "capture ends inside a %d-byte record; the file is truncated", caplen)
		}
		frame := data[pos+16 : pos+16+caplen]
		pkt, keep := framePacket(link, frame, time.Unix(sec, frac*fracNS))
		if keep {
			if len(out) == MaxCapturePackets {
				return nil, captureErr(pos, "capture holds more than %d packets", MaxCapturePackets)
			}
			out = append(out, pkt)
		}
		pos += 16 + caplen
	}
	return out, nil
}

// pcapngIface is one interface of a pcapng section.
type pcapngIface struct {
	link uint16
	// Timestamps are units of 10^-exp s (pow2 false) or 2^-exp s.
	exp    uint8
	pow2   bool
	offset int64 // if_tsoffset, seconds
}

// maxPcapngInterfaces bounds the interfaces of one section.
const maxPcapngInterfaces = 1024

func readPcapng(data []byte) ([]CapturedPacket, error) {
	var order binary.ByteOrder = binary.LittleEndian
	var ifaces []pcapngIface
	var out []CapturedPacket
	section := false
	for pos := 0; pos < len(data); {
		if len(data)-pos < 12 {
			return nil, captureErr(pos, "capture ends inside a block header; the file is truncated")
		}
		blockType := order.Uint32(data[pos:])
		if binary.BigEndian.Uint32(data[pos:]) == 0x0A0D0D0A {
			switch binary.BigEndian.Uint32(data[pos+8:]) {
			case 0x1A2B3C4D:
				order = binary.BigEndian
			case 0x4D3C2B1A:
				order = binary.LittleEndian
			default:
				return nil, captureErr(pos, "malformed section header byte-order magic")
			}
			blockType = 0x0A0D0D0A
			ifaces = ifaces[:0]
			section = true
		}
		if !section {
			return nil, captureErr(pos, "pcapng block before the first section header")
		}
		blockLen := int(order.Uint32(data[pos+4:]))
		if blockLen < 12 || blockLen%4 != 0 {
			return nil, captureErr(pos, "malformed block length %d", blockLen)
		}
		if len(data)-pos < blockLen {
			return nil, captureErr(pos, "capture ends inside a %d-byte block; the file is truncated", blockLen)
		}
		if int(order.Uint32(data[pos+blockLen-4:])) != blockLen {
			return nil, captureErr(pos, "block length %d does not match its trailer", blockLen)
		}
		body := data[pos+8 : pos+blockLen-4]
		switch blockType {
		case 0x00000001: // Interface Description Block
			if len(body) < 8 {
				return nil, captureErr(pos, "malformed interface description block")
			}
			if len(ifaces) == maxPcapngInterfaces {
				return nil, captureErr(pos, "more than %d interfaces in one section", maxPcapngInterfaces)
			}
			iface := pcapngIface{link: order.Uint16(body), exp: 6}
			for opt := body[8:]; len(opt) >= 4; {
				code, olen := order.Uint16(opt), int(order.Uint16(opt[2:]))
				if code == 0 {
					break
				}
				if len(opt)-4 < olen {
					return nil, captureErr(pos, "malformed interface option length %d", olen)
				}
				val := opt[4 : 4+olen]
				switch {
				case code == 9 && olen >= 1: // if_tsresol
					iface.exp, iface.pow2 = val[0]&0x7F, val[0]&0x80 != 0
				case code == 14 && olen >= 8: // if_tsoffset
					iface.offset = int64(order.Uint64(val))
				}
				padded := (olen + 3) &^ 3
				if len(opt)-4 < padded {
					break
				}
				opt = opt[4+padded:]
			}
			if (!iface.pow2 && iface.exp > 18) || (iface.pow2 && iface.exp > 63) {
				return nil, captureErr(pos, "unsupported timestamp resolution")
			}
			ifaces = append(ifaces, iface)
		case 0x00000006: // Enhanced Packet Block
			if len(body) < 20 {
				return nil, captureErr(pos, "malformed enhanced packet block")
			}
			id := int(order.Uint32(body))
			raw := uint64(order.Uint32(body[4:]))<<32 | uint64(order.Uint32(body[8:]))
			caplen := int(order.Uint32(body[12:]))
			if id >= len(ifaces) {
				return nil, captureErr(pos, "packet names undeclared interface %d", id)
			}
			if caplen > maxRecordBytes || caplen > len(body)-20 {
				return nil, captureErr(pos, "malformed packet length %d", caplen)
			}
			at, ok := ifaces[id].timestamp(raw)
			if !ok {
				return nil, captureErr(pos, "timestamp out of range")
			}
			pkt, keep := framePacket(ifaces[id].link, body[20:20+caplen], at)
			if keep {
				if len(out) == MaxCapturePackets {
					return nil, captureErr(pos, "capture holds more than %d packets", MaxCapturePackets)
				}
				out = append(out, pkt)
			}
		}
		// Other blocks (name resolution, statistics, simple packets without
		// a timestamp, custom blocks) carry nothing a verifier can use.
		pos += blockLen
	}
	return out, nil
}

// timestamp converts a raw pcapng timestamp to a time, false when it does not
// fit a time.Time of int64 nanoseconds.
func (f pcapngIface) timestamp(raw uint64) (time.Time, bool) {
	var unit uint64
	if f.pow2 {
		unit = 1 << f.exp
	} else {
		unit = 1
		for range f.exp {
			unit *= 10
		}
	}
	sec, frac := raw/unit, raw%unit
	// frac/unit of a second in nanoseconds, without overflow.
	hi, lo := bits.Mul64(frac, uint64(time.Second))
	ns, _ := bits.Div64(hi, lo, unit)
	if sec > math.MaxInt64/2 || f.offset > math.MaxInt32 || f.offset < math.MinInt32 {
		return time.Time{}, false
	}
	s := int64(sec) + f.offset
	if s > math.MaxInt64/int64(time.Second)-1 || s < math.MinInt64/int64(time.Second)+1 {
		return time.Time{}, false
	}
	return time.Unix(s, int64(ns)), true
}

// framePacket strips the link-layer header of one frame. keep is false for a
// frame of a known link type that carries no IP packet.
func framePacket(link uint16, frame []byte, at time.Time) (CapturedPacket, bool) {
	pkt := CapturedPacket{CapturedAt: at, LinkType: link}
	var ip []byte
	switch link {
	case linkTypeEthernet:
		if len(frame) < 14 {
			return pkt, false
		}
		etherType, off := binary.BigEndian.Uint16(frame[12:]), 14
		for (etherType == 0x8100 || etherType == 0x88A8 || etherType == 0x9100) && len(frame) >= off+4 {
			etherType = binary.BigEndian.Uint16(frame[off+2:])
			off += 4
		}
		if etherType != 0x0800 && etherType != 0x86DD {
			return pkt, false
		}
		ip = frame[off:]
	case linkTypeRaw, linkTypeIPv4, linkTypeIPv6:
		ip = frame
	case linkTypeNull, linkTypeLoop:
		if len(frame) < 4 {
			return pkt, false
		}
		ip = frame[4:]
	case linkTypeLinuxSLL:
		if len(frame) < 16 {
			return pkt, false
		}
		if et := binary.BigEndian.Uint16(frame[14:]); et != 0x0800 && et != 0x86DD {
			return pkt, false
		}
		ip = frame[16:]
	case linkTypeSLL2:
		if len(frame) < 20 {
			return pkt, false
		}
		if et := binary.BigEndian.Uint16(frame); et != 0x0800 && et != 0x86DD {
			return pkt, false
		}
		ip = frame[20:]
	default:
		return pkt, true
	}
	if len(ip) == 0 || (ip[0]>>4 != 4 && ip[0]>>4 != 6) {
		return pkt, false
	}
	switch {
	case ip[0]>>4 == 4 && len(ip) >= 4:
		if total := int(binary.BigEndian.Uint16(ip[2:])); total >= 20 && total <= len(ip) {
			ip = ip[:total]
		}
	case ip[0]>>4 == 6 && len(ip) >= 40:
		if total := 40 + int(binary.BigEndian.Uint16(ip[4:])); total <= len(ip) {
			ip = ip[:total]
		}
	}
	pkt.Data = bytes.Clone(ip)
	return pkt, true
}

// errNoPackets is returned by Verify for a capture without packets.
var errNoPackets = errors.New("client: verify: the capture holds no packets")
