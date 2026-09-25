// dns — DNS A lookup over UDP, written with the Debuglet Go SDK.
//
// Sends one query to -addr and prints the A records of the reply. It builds and
// parses the message itself: a guest has no resolver and no operating-system
// sockets, only the executor's host imports.
//
// Build and run:
//
//	make wasm SAMPLE_DIR=local/wasm_samples/go/dns
//	dbl run --wasm local/wasm_samples/go/dns/debuglet.wasm \
//	  --executor EXECUTOR_ID --allow 1.1.1.1 --wait -- -addr 1.1.1.1:53 -name example.org
//
// The resolver's address must be in the job's --allow list, and only a resolver
// you are authorized to query belongs there; the default names a public one, so
// the guest reaches it only when a submission says so. A UDP read has no
// deadline of its own: if the reply is lost, the guest waits until the job's
// execution budget ends it, so give the job a budget you are willing to spend.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

var (
	addr = flag.String("addr", "1.1.1.1:53", "resolver (host:port)")
	name = flag.String("name", "example.org", "domain name to look up")
)

// A DNS message over UDP is at most 512 bytes without EDNS(0).
const messageSize = 512

func main() {
	flag.CommandLine.Parse(os.Args)

	question, err := encodeName(*name)
	if err != nil {
		fmt.Printf("name error=%v\n", err)
		os.Exit(1)
	}
	id := uint16(time.Now().UnixNano())
	fmt.Printf("query name=%s type=A server=%s\n", *name, *addr)

	conn, err := debuglet.ConnectUDP(*addr)
	if err != nil {
		fmt.Printf("connect error=%v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	start := time.Now()
	if err := conn.Write(query(id, question)); err != nil {
		fmt.Printf("write error=%v\n", err)
		os.Exit(1)
	}
	buf := make([]byte, messageSize)
	n, err := conn.Read(buf)
	elapsed := time.Since(start)
	if err != nil {
		fmt.Printf("read error=%v\n", err)
		os.Exit(1)
	}

	answers, err := printAnswers(buf[:n], id)
	if err != nil {
		fmt.Printf("response error=%v\n", err)
		os.Exit(1)
	}
	fmt.Printf("answers=%d elapsed_ms=%.3f\n", answers, float64(elapsed)/float64(time.Millisecond))
}

// query builds a standard recursive A query for one question.
func query(id uint16, question []byte) []byte {
	msg := make([]byte, 0, messageSize)
	msg = append(msg,
		byte(id>>8), byte(id), // transaction id
		0x01, 0x00, // recursion desired
		0x00, 0x01, // one question
		0x00, 0x00, // no answers
		0x00, 0x00, // no authority records
		0x00, 0x00, // no additional records
	)
	msg = append(msg, question...)
	msg = append(msg, 0x00, 0x01, 0x00, 0x01) // type A, class IN
	return msg
}

// encodeName writes a domain name as length-prefixed labels.
func encodeName(domain string) ([]byte, error) {
	trimmed := strings.TrimSuffix(domain, ".")
	if trimmed == "" {
		return nil, errors.New("empty domain name")
	}
	encoded := make([]byte, 0, len(trimmed)+2)
	for _, label := range strings.Split(trimmed, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid label %q", label)
		}
		encoded = append(encoded, byte(len(label)))
		encoded = append(encoded, label...)
	}
	return append(encoded, 0x00), nil
}

// printAnswers prints every A record of a reply to the query with this id.
func printAnswers(msg []byte, id uint16) (int, error) {
	if len(msg) < 12 {
		return 0, errors.New("response is shorter than a header")
	}
	if uint16(msg[0])<<8|uint16(msg[1]) != id {
		return 0, errors.New("response does not match the query id")
	}
	if msg[2]&0x80 == 0 {
		return 0, errors.New("message is not a response")
	}
	if code := msg[3] & 0x0f; code != 0 {
		return 0, fmt.Errorf("response code %d", code)
	}
	questions := int(msg[4])<<8 | int(msg[5])
	records := int(msg[6])<<8 | int(msg[7])

	offset := 12
	var err error
	for i := 0; i < questions; i++ {
		if offset, err = skipName(msg, offset); err != nil {
			return 0, err
		}
		offset += 4
		if offset > len(msg) {
			return 0, errors.New("truncated question")
		}
	}

	answers := 0
	for i := 0; i < records; i++ {
		if offset, err = skipName(msg, offset); err != nil {
			return 0, err
		}
		if offset+10 > len(msg) {
			return 0, errors.New("truncated record header")
		}
		recordType := int(msg[offset])<<8 | int(msg[offset+1])
		ttl := uint32(msg[offset+4])<<24 | uint32(msg[offset+5])<<16 | uint32(msg[offset+6])<<8 | uint32(msg[offset+7])
		length := int(msg[offset+8])<<8 | int(msg[offset+9])
		offset += 10
		if offset+length > len(msg) {
			return 0, errors.New("truncated record data")
		}
		if recordType == 1 && length == 4 {
			fmt.Printf("answer a=%d.%d.%d.%d ttl=%d\n", msg[offset], msg[offset+1], msg[offset+2], msg[offset+3], ttl)
			answers++
		}
		offset += length
	}
	return answers, nil
}

// skipName steps over a name, following the single compression pointer that
// ends one.
func skipName(msg []byte, offset int) (int, error) {
	for {
		if offset >= len(msg) {
			return 0, errors.New("truncated name")
		}
		length := int(msg[offset])
		switch {
		case length == 0:
			return offset + 1, nil
		case length&0xc0 == 0xc0:
			if offset+2 > len(msg) {
				return 0, errors.New("truncated name pointer")
			}
			return offset + 2, nil
		case length&0xc0 != 0:
			return 0, errors.New("unsupported label type")
		default:
			offset += 1 + length
		}
	}
}
