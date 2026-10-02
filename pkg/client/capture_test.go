// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// testFrame is one packet of a generated capture.
type testFrame struct {
	at time.Time
	ip []byte
}

// encapsulate wraps an IP packet in the link-layer header of link. Ethernet
// frames carry a VLAN tag, padding and a trailer the reader must strip.
func encapsulate(link uint16, ip []byte) []byte {
	proto := uint16(0x0800)
	if len(ip) > 0 && ip[0]>>4 == 6 {
		proto = 0x86DD
	}
	var hdr []byte
	switch link {
	case linkTypeEthernet:
		hdr = make([]byte, 18)
		copy(hdr, []byte{2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2})
		binary.BigEndian.PutUint16(hdr[12:], 0x8100)
		binary.BigEndian.PutUint16(hdr[14:], 7)
		binary.BigEndian.PutUint16(hdr[16:], proto)
		frame := append(hdr, ip...)
		if len(ip) >= 4 && ip[0]>>4 == 4 && int(binary.BigEndian.Uint16(ip[2:])) > len(ip) {
			return frame // a truncated capture has no padding or trailer
		}
		for len(frame) < 60 {
			frame = append(frame, 0)
		}
		return append(frame, 0xde, 0xad, 0xbe, 0xef) // FCS
	case linkTypeRaw, linkTypeIPv4:
		return bytes.Clone(ip)
	case linkTypeNull:
		hdr = binary.LittleEndian.AppendUint32(nil, 2)
	case linkTypeLoop:
		hdr = binary.BigEndian.AppendUint32(nil, 2)
	case linkTypeLinuxSLL:
		hdr = make([]byte, 16)
		binary.BigEndian.PutUint16(hdr[2:], 1)
		binary.BigEndian.PutUint16(hdr[4:], 6)
		binary.BigEndian.PutUint16(hdr[14:], proto)
	case linkTypeSLL2:
		hdr = make([]byte, 20)
		binary.BigEndian.PutUint16(hdr[0:], proto)
		binary.BigEndian.PutUint32(hdr[4:], 3)
		binary.BigEndian.PutUint16(hdr[8:], 1)
		hdr[11] = 6
	default:
		hdr = []byte{0xff, 0xff}
	}
	return append(hdr, ip...)
}

// writePcap returns a classic pcap of frames, in microseconds or nanoseconds
// and in either byte order.
func writePcap(link uint16, nano, bigEndian bool, frames []testFrame) []byte {
	var order binary.AppendByteOrder = binary.LittleEndian
	if bigEndian {
		order = binary.BigEndian
	}
	magic := uint32(0xa1b2c3d4)
	if nano {
		magic = 0xa1b23c4d
	}
	out := order.AppendUint32(nil, magic)
	out = order.AppendUint16(out, 2)
	out = order.AppendUint16(out, 4)
	out = order.AppendUint32(out, 0)
	out = order.AppendUint32(out, 0)
	out = order.AppendUint32(out, 262144)
	out = order.AppendUint32(out, uint32(link))
	for _, f := range frames {
		frame := encapsulate(link, f.ip)
		frac := uint32(f.at.Nanosecond())
		if !nano {
			frac /= 1000
		}
		out = order.AppendUint32(out, uint32(f.at.Unix()))
		out = order.AppendUint32(out, frac)
		out = order.AppendUint32(out, uint32(len(frame)))
		out = order.AppendUint32(out, uint32(len(frame)))
		out = append(out, frame...)
	}
	return out
}

// pcapngBlock frames one block.
func pcapngBlock(order binary.AppendByteOrder, typ uint32, body []byte) []byte {
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	n := uint32(12 + len(body))
	out := order.AppendUint32(nil, typ)
	out = order.AppendUint32(out, n)
	out = append(out, body...)
	return order.AppendUint32(out, n)
}

// writePcapng returns a pcapng of frames on one interface. tsresol 0 omits
// the option (microseconds); 0x80|n is 2^-n seconds.
func writePcapng(link uint16, tsresol byte, bigEndian bool, frames []testFrame) []byte {
	var order binary.AppendByteOrder = binary.LittleEndian
	if bigEndian {
		order = binary.BigEndian
	}
	shb := order.AppendUint32(nil, 0x1A2B3C4D)
	shb = order.AppendUint16(shb, 1)
	shb = order.AppendUint16(shb, 0)
	shb = order.AppendUint64(shb, ^uint64(0))
	out := pcapngBlock(order, 0x0A0D0D0A, shb)
	idb := order.AppendUint16(nil, link)
	idb = order.AppendUint16(idb, 0)
	idb = order.AppendUint32(idb, 0)
	if tsresol != 0 {
		idb = order.AppendUint16(idb, 9)
		idb = order.AppendUint16(idb, 1)
		idb = append(idb, tsresol, 0, 0, 0)
	}
	idb = order.AppendUint32(idb, 0) // opt_endofopt
	out = append(out, pcapngBlock(order, 1, idb)...)
	out = append(out, pcapngBlock(order, 4, []byte{0, 0, 0, 0})...) // name resolution, ignored
	for _, f := range frames {
		var units uint64
		ns := uint64(f.at.UnixNano())
		switch {
		case tsresol == 0:
			units = ns / 1000
		case tsresol&0x80 != 0:
			units = uint64(f.at.Unix())<<(tsresol&0x7f) | uint64(f.at.Nanosecond())<<(tsresol&0x7f)/1e9
		default:
			div := uint64(1)
			for range 9 - int(tsresol) {
				div *= 10
			}
			units = ns / div
		}
		frame := encapsulate(link, f.ip)
		epb := order.AppendUint32(nil, 0)
		epb = order.AppendUint32(epb, uint32(units>>32))
		epb = order.AppendUint32(epb, uint32(units))
		epb = order.AppendUint32(epb, uint32(len(frame)))
		epb = order.AppendUint32(epb, uint32(len(frame)))
		epb = append(epb, frame...)
		out = append(out, pcapngBlock(order, 6, epb)...)
	}
	return out
}

func testUDP(src [4]byte, n int, fill byte) []byte {
	pkt := make([]byte, n)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(n))
	binary.BigEndian.PutUint16(pkt[4:], 0x1234)
	pkt[8], pkt[9] = 64, 17
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], []byte{198, 51, 100, 1})
	if n < 28 {
		return pkt
	}
	binary.BigEndian.PutUint16(pkt[20:], 40000)
	binary.BigEndian.PutUint16(pkt[22:], 33434)
	binary.BigEndian.PutUint16(pkt[24:], uint16(n-20))
	for i := 28; i < n; i++ {
		pkt[i] = fill + byte(i)
	}
	return pkt
}

var captureLinks = map[string]uint16{
	"ethernet": linkTypeEthernet, "raw": linkTypeRaw, "ipv4": linkTypeIPv4, "null": linkTypeNull,
	"loop": linkTypeLoop, "sll": linkTypeLinuxSLL, "sll2": linkTypeSLL2,
}

func TestReadCaptureFormats(t *testing.T) {
	base := time.Date(2026, 9, 29, 10, 0, 0, 123456789, time.UTC)
	frames := []testFrame{
		{base, testUDP([4]byte{192, 0, 2, 7}, 40, 1)},
		{base.Add(time.Second), testUDP([4]byte{192, 0, 2, 8}, 100, 2)},
	}
	v6 := make([]byte, 48)
	v6[0], v6[5] = 0x60, 8
	frames = append(frames, testFrame{base.Add(2 * time.Second), v6})
	micro := func(at time.Time) time.Time { return at.Truncate(time.Microsecond) }
	for name, link := range captureLinks {
		for _, format := range []struct {
			name string
			data []byte
			ts   func(time.Time) time.Time
		}{
			{"pcap-us-le", writePcap(link, false, false, frames), micro},
			{"pcap-ns-be", writePcap(link, true, true, frames), func(at time.Time) time.Time { return at }},
			{"pcapng-default", writePcapng(link, 0, false, frames), micro},
			{"pcapng-ns-be", writePcapng(link, 9, true, frames), func(at time.Time) time.Time { return at }},
			{"pcapng-2^-30", writePcapng(link, 0x80|30, false, frames), func(at time.Time) time.Time { return at }},
		} {
			t.Run(name+"/"+format.name, func(t *testing.T) {
				pkts, err := ReadCapture(bytes.NewReader(format.data))
				if err != nil {
					t.Fatal(err)
				}
				if len(pkts) != len(frames) {
					t.Fatalf("read %d packets, want %d", len(pkts), len(frames))
				}
				for i, p := range pkts {
					if !bytes.Equal(p.Data, frames[i].ip) {
						t.Errorf("packet %d = %x, want %x", i, p.Data, frames[i].ip)
					}
					want := format.ts(frames[i].at)
					if d := p.CapturedAt.Sub(want); d < -time.Nanosecond || d > time.Nanosecond {
						t.Errorf("packet %d at %v, want %v", i, p.CapturedAt, want)
					}
					if p.LinkType != link {
						t.Errorf("link type %d, want %d", p.LinkType, link)
					}
				}
			})
		}
	}
}

func TestReadCaptureSkipsNonIPAndKeepsUnknownLinks(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	arp := make([]byte, 60)
	binary.BigEndian.PutUint16(arp[12:], 0x0806)
	data := writePcap(linkTypeEthernet, false, false, nil)
	data = binary.LittleEndian.AppendUint32(data, uint32(at.Unix()))
	data = binary.LittleEndian.AppendUint32(data, 0)
	data = binary.LittleEndian.AppendUint32(data, uint32(len(arp)))
	data = binary.LittleEndian.AppendUint32(data, uint32(len(arp)))
	data = append(data, arp...)
	pkts, err := ReadCapture(bytes.NewReader(data))
	if err != nil || len(pkts) != 0 {
		t.Fatalf("ARP frame: %d packets, %v; want none", len(pkts), err)
	}
	pkts, err = ReadCapture(bytes.NewReader(writePcap(147, false, false, []testFrame{{at, testUDP([4]byte{192, 0, 2, 1}, 64, 0)}})))
	if err != nil || len(pkts) != 1 || len(pkts[0].Data) != 0 || pkts[0].LinkType != 147 {
		t.Fatalf("unknown link type: %+v, %v; want one packet without data", pkts, err)
	}
}

func TestReadCaptureRejectsMalformedCaptures(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	good := writePcap(linkTypeRaw, false, false, []testFrame{{at, testUDP([4]byte{192, 0, 2, 1}, 64, 0)}})
	goodNG := writePcapng(linkTypeRaw, 0, false, []testFrame{{at, testUDP([4]byte{192, 0, 2, 1}, 64, 0)}})
	hugeLen := bytes.Clone(good)
	binary.LittleEndian.PutUint32(hugeLen[24+8:], 1<<30)
	badFrac := bytes.Clone(good)
	binary.LittleEndian.PutUint32(badFrac[24+4:], 2_000_000)
	ngTrailer := bytes.Clone(goodNG)
	ngTrailer[len(ngTrailer)-1] ^= 1
	for name, data := range map[string][]byte{
		"empty":             {},
		"not a capture":     []byte("hello, world"),
		"truncated header":  good[:20],
		"truncated record":  good[:len(good)-1],
		"cut record header": good[:24+8],
		"huge record":       hugeLen,
		"bad fraction":      badFrac,
		"pcapng trailer":    ngTrailer,
		"pcapng truncated":  goodNG[:len(goodNG)-2],
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ReadCapture(bytes.NewReader(data))
			var ce *CaptureError
			if !errors.As(err, &ce) {
				t.Fatalf("ReadCapture error %v, want a *CaptureError", err)
			}
		})
	}
}

func TestReadCaptureLimits(t *testing.T) {
	big := io.MultiReader(bytes.NewReader(writePcap(linkTypeRaw, false, false, nil)), io.LimitReader(zeroReader{}, MaxCaptureBytes))
	if _, err := ReadCapture(big); err == nil || !strings.Contains(err.Error(), "64 MiB") {
		t.Fatalf("oversized capture: %v, want the size limit", err)
	}
	// MaxCapturePackets+1 minimal records (a 20-byte header each).
	pkt := testUDP([4]byte{192, 0, 2, 1}, 20, 0)
	data := writePcap(linkTypeRaw, false, false, nil)
	rec := make([]byte, 16+len(pkt))
	binary.LittleEndian.PutUint32(rec[8:], uint32(len(pkt)))
	binary.LittleEndian.PutUint32(rec[12:], uint32(len(pkt)))
	copy(rec[16:], pkt)
	data = append(data, bytes.Repeat(rec, MaxCapturePackets+1)...)
	if _, err := ReadCapture(bytes.NewReader(data)); err == nil || !strings.Contains(err.Error(), "more than 1000000 packets") {
		t.Fatalf("too many packets: %v, want the packet limit", err)
	}
	pkts, err := ReadCapture(bytes.NewReader(data[:len(data)-len(rec)]))
	if err != nil || len(pkts) != MaxCapturePackets {
		t.Fatalf("exactly the limit: %d packets, %v", len(pkts), err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
