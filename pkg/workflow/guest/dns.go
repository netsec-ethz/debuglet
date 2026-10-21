// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
	"golang.org/x/net/dns/dnsmessage"
)

const dnsResponseLimit = debuglet.MaxIOBytes - 1

type dnsQuery struct {
	resolver, transport string
	timeout             time.Duration
	message             dnsmessage.Message
	wire                []byte
}

// DNSQuery measures one query against an explicitly selected resolver. A valid
// DNS error response (for example NXDOMAIN) is ok; rcode carries its meaning.
// UDP truncation is reported without silently retrying over another transport.
func DNSQuery(inputs map[string]any) (map[string]any, error) {
	query, err := networkDNSQuery(inputs)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"ok": false, "error": "", "rcode": "", "flags": map[string]any{}, "answers": []any{}, "authorities": []any{}, "additionals": []any{}, "addresses": []any{}, "names": []any{}, "nsid_base64": "", "nsid_present": false, "response_base64": "", "duration_ms": float64(0), "truncated": false}
	start := time.Now()
	defer networkDuration(out, start)
	deadline := start.Add(query.timeout)
	conn, err := debuglet.DialTimeout(query.transport, query.resolver, time.Until(deadline))
	if err != nil {
		out["error"] = err.Error()
		return out, nil
	}
	defer conn.Close()
	if err = conn.SetReadDeadline(deadline); err == nil {
		err = conn.SetWriteDeadline(deadline)
	}
	request := query.wire
	if query.transport == "tcp" {
		request = binary.BigEndian.AppendUint16(nil, uint16(len(request)))
		request = append(request, query.wire...)
	}
	if err == nil {
		var n int
		n, err = conn.Write(request)
		if err == nil && n != len(request) {
			err = io.ErrShortWrite
		}
	}
	var response []byte
	if err == nil {
		if query.transport == "tcp" {
			var length [2]byte
			if _, err = io.ReadFull(conn, length[:]); err == nil {
				size := int(binary.BigEndian.Uint16(length[:]))
				response = make([]byte, min(size, dnsResponseLimit+1))
				var n int
				n, err = io.ReadFull(conn, response)
				response = response[:n]
			}
		} else {
			response = make([]byte, dnsResponseLimit+1)
			var n int
			n, err = conn.Read(response)
			response = response[:n]
		}
	}
	if len(response) > dnsResponseLimit {
		out["truncated"] = true
		response = response[:dnsResponseLimit]
		err = fmt.Errorf("DNS response exceeds %d bytes", dnsResponseLimit)
	}
	out["response_base64"] = base64.StdEncoding.EncodeToString(response)
	if err == nil {
		var decoded map[string]any
		decoded, err = networkDNSResponse(response, query.message)
		if err == nil {
			for key, value := range decoded {
				out[key] = value
			}
		}
	}
	out["ok"] = err == nil
	if err != nil {
		out["error"] = err.Error()
	}
	return out, nil
}

func networkDNSQuery(inputs map[string]any) (dnsQuery, error) {
	var q dnsQuery
	var err error
	q.resolver, err = networkString(inputs, "resolver", "")
	if err != nil {
		return q, err
	}
	host, port, err := net.SplitHostPort(q.resolver)
	if err != nil || net.ParseIP(host) == nil || !networkPort(port) {
		return q, fmt.Errorf("resolver must be a literal IP:port, for example 192.0.2.53:53")
	}
	q.transport, err = networkString(inputs, "transport", "udp")
	if err != nil || q.transport != "udp" && q.transport != "tcp" {
		return q, fmt.Errorf("transport must be udp or tcp")
	}
	q.timeout, err = networkTimeout(inputs)
	if err != nil {
		return q, err
	}
	name, err := networkString(inputs, "name", "")
	if err != nil {
		return q, err
	}
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	dnsName, err := dnsmessage.NewName(name)
	if err != nil {
		return q, fmt.Errorf("DNS name: %w", err)
	}
	typeName, err := networkString(inputs, "record_type", "A")
	if err != nil {
		return q, err
	}
	typeNumber, ok := dnsTypeNumbers[strings.ToUpper(typeName)]
	if !ok && strings.HasPrefix(strings.ToUpper(typeName), "TYPE") {
		n, parseErr := strconv.ParseUint(typeName[4:], 10, 16)
		typeNumber, ok = dnsmessage.Type(n), parseErr == nil && n != 0
	}
	if !ok {
		return q, fmt.Errorf("record_type must be a supported DNS type or TYPE followed by a number from 1 to 65535")
	}
	boolInput := func(name string, fallback bool) (bool, error) {
		value, exists := inputs[name]
		if !exists {
			return fallback, nil
		}
		result, ok := value.(bool)
		if !ok {
			return false, fmt.Errorf("%s must be a boolean", name)
		}
		return result, nil
	}
	rd, err := boolInput("recursion_desired", true)
	if err != nil {
		return q, err
	}
	cd, err := boolInput("checking_disabled", false)
	if err != nil {
		return q, err
	}
	do, err := boolInput("dnssec_ok", false)
	if err != nil {
		return q, err
	}
	nsid, err := boolInput("request_nsid", false)
	if err != nil {
		return q, err
	}
	var id [2]byte
	if _, err = rand.Read(id[:]); err != nil {
		return q, fmt.Errorf("DNS query ID: %w", err)
	}
	q.message = dnsmessage.Message{Header: dnsmessage.Header{ID: binary.BigEndian.Uint16(id[:]), RecursionDesired: rd, CheckingDisabled: cd}, Questions: []dnsmessage.Question{{Name: dnsName, Type: typeNumber, Class: dnsmessage.ClassINET}}}
	if do || nsid {
		root, _ := dnsmessage.NewName(".")
		opt := &dnsmessage.OPTResource{}
		var flags uint32
		if do {
			flags = 1 << 15
		}
		if nsid {
			opt.Options = []dnsmessage.Option{{Code: 3}}
		}
		q.message.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: root, Type: dnsmessage.TypeOPT, Class: 1232, TTL: flags}, Body: opt}}
	}
	q.wire, err = q.message.Pack()
	if err != nil {
		return q, fmt.Errorf("DNS query: %w", err)
	}
	return q, nil
}

var dnsTypeNumbers = map[string]dnsmessage.Type{"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "OPT": 41, "CAA": 257, "ANY": 255}

func dnsTypeName(number dnsmessage.Type) string {
	for name, value := range dnsTypeNumbers {
		if value == number {
			return name
		}
	}
	return fmt.Sprintf("TYPE%d", number)
}

func networkDNSResponse(wire []byte, query dnsmessage.Message) (map[string]any, error) {
	var response dnsmessage.Message
	if err := response.Unpack(wire); err != nil {
		return nil, fmt.Errorf("decode DNS response: %w", err)
	}
	if !response.Response || response.ID != query.ID || response.OpCode != 0 || len(response.Questions) != 1 || len(query.Questions) != 1 {
		return nil, fmt.Errorf("DNS response does not match the query")
	}
	want, got := query.Questions[0], response.Questions[0]
	if !strings.EqualFold(want.Name.String(), got.Name.String()) || want.Type != got.Type || want.Class != got.Class {
		return nil, fmt.Errorf("DNS response question does not match the query")
	}
	if len(response.Answers)+len(response.Authorities)+len(response.Additionals) > 128 {
		return nil, fmt.Errorf("DNS response exceeds 128 resource records")
	}
	code := int(response.RCode)
	for _, record := range response.Additionals {
		if record.Header.Type == dnsmessage.TypeOPT {
			code |= int(record.Header.TTL>>24) << 4
		}
	}
	rcode := fmt.Sprintf("RCODE%d", code)
	names := []string{"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE"}
	if code < len(names) {
		rcode = names[code]
	}
	out := map[string]any{"rcode": rcode, "truncated": response.Truncated, "flags": map[string]any{"authoritative": response.Authoritative, "truncated": response.Truncated, "recursion_desired": response.RecursionDesired, "recursion_available": response.RecursionAvailable, "authenticated_data": response.AuthenticData, "checking_disabled": response.CheckingDisabled}, "answers": dnsResources(response.Answers), "authorities": dnsResources(response.Authorities), "additionals": dnsResources(response.Additionals)}
	out["addresses"], out["names"] = dnsAnswerValues(out["answers"].([]any))
	out["nsid_base64"], out["nsid_present"] = dnsNSID(response.Additionals)
	encoded, err := json.Marshal(out)
	if err != nil || len(encoded) > 48*1024 {
		return nil, fmt.Errorf("decoded DNS response exceeds 48 KiB")
	}
	return out, nil
}

func dnsAnswerValues(answers []any) (addresses, names []any) {
	addresses, names = []any{}, []any{}
	seen := map[string]bool{}
	for _, answer := range answers {
		row := answer.(map[string]any)
		var values *[]any
		switch row["type"] {
		case "A", "AAAA":
			values = &addresses
		case "NS", "CNAME", "PTR":
			values = &names
		default:
			continue
		}
		value := row["data"].(string)
		if !seen[value] {
			*values = append(*values, value)
			seen[value] = true
		}
	}
	return addresses, names
}

// NSID is opaque bytes. Presence distinguishes an empty identifier from a
// response without the option; neither identifies a physical server or site.
func dnsNSID(additionals []dnsmessage.Resource) (string, bool) {
	for _, record := range additionals {
		if opt, ok := record.Body.(*dnsmessage.OPTResource); ok {
			for _, option := range opt.Options {
				if option.Code == 3 {
					return base64.StdEncoding.EncodeToString(option.Data), true
				}
			}
		}
	}
	return "", false
}

func dnsResources(records []dnsmessage.Resource) []any {
	result := make([]any, 0, len(records))
	for _, record := range records {
		var data any
		switch body := record.Body.(type) {
		case *dnsmessage.AResource:
			data = net.IP(body.A[:]).String()
		case *dnsmessage.AAAAResource:
			data = net.IP(body.AAAA[:]).String()
		case *dnsmessage.CNAMEResource:
			data = body.CNAME.String()
		case *dnsmessage.NSResource:
			data = body.NS.String()
		case *dnsmessage.PTRResource:
			data = body.PTR.String()
		case *dnsmessage.MXResource:
			data = map[string]any{"preference": float64(body.Pref), "exchange": body.MX.String()}
		case *dnsmessage.SOAResource:
			data = map[string]any{"ns": body.NS.String(), "mailbox": body.MBox.String(), "serial": float64(body.Serial), "refresh": float64(body.Refresh), "retry": float64(body.Retry), "expire": float64(body.Expire), "minimum_ttl": float64(body.MinTTL)}
		case *dnsmessage.TXTResource:
			items := make([]any, len(body.TXT))
			for i, value := range body.TXT {
				items[i] = value
			}
			data = items
		case *dnsmessage.SRVResource:
			data = map[string]any{"priority": float64(body.Priority), "weight": float64(body.Weight), "port": float64(body.Port), "target": body.Target.String()}
		case *dnsmessage.OPTResource:
			options := make([]any, len(body.Options))
			for i, option := range body.Options {
				options[i] = map[string]any{"code": float64(option.Code), "data_base64": base64.StdEncoding.EncodeToString(option.Data)}
			}
			data = map[string]any{"udp_size": float64(record.Header.Class), "dnssec_ok": record.Header.TTL&(1<<15) != 0, "options": options}
		case *dnsmessage.UnknownResource:
			data = map[string]any{"base64": base64.StdEncoding.EncodeToString(body.Data)}
		}
		result = append(result, map[string]any{"name": record.Header.Name.String(), "type": dnsTypeName(record.Header.Type), "class": float64(record.Header.Class), "ttl": float64(record.Header.TTL), "data": data})
	}
	return result
}
