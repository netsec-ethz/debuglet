// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package debuglet

import (
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/guestio"
	"time"
)

type SCIONQUICListener = guestio.SCIONQUICListener
type SCIONQUICExchange = guestio.SCIONQUICExchange

// StartSCIONQUICEcho claims the run's SCION listener for a fixed reliable echo
// protocol. It may start once per run and excludes raw SCION receive/reply.
// Timeout bounds setup; the service ends on StopSCIONQUICEcho or run cleanup.
// The certificate pin is public. Distribute it through a trusted channel;
// receiving it over an unauthenticated message does not establish identity.
func StartSCIONQUICEcho(timeout time.Duration) (SCIONQUICListener, error) {
	r, err := scionCall(guestio.SCIONQUICEchoStart, invokeSCIONQUICEchoStart, guestio.SCIONRequest{TimeoutNS: int64(timeout)})
	if err == nil && r.QUICListener == nil {
		err = fmt.Errorf("debuglet: missing SCION QUIC listener result")
	}
	if r.QUICListener == nil {
		return SCIONQUICListener{}, err
	}
	return *r.QUICListener, err
}

// StopSCIONQUICEcho closes the service and its claimed listener. It is idempotent.
func StopSCIONQUICEcho() error {
	_, err := scionCall(guestio.SCIONQUICEchoStop, invokeSCIONQUICEchoStop, guestio.SCIONRequest{})
	return err
}

// ExchangeSCIONQUIC performs one framed reliable echo over QUIC/TLS using an
// exact outbound SCION path and a required SHA256 DER leaf certificate pin.
// The payload is at most SCIONMaxPayload bytes. This fixed echo protocol is not
// HTTP/3 or TCP. QUIC handshake, ACK and retransmission datagrams are accounted.
// Timeout zero means 10 seconds; longer requested timeouts are rejected.
func ExchangeSCIONQUIC(address, pathID, certificateSHA256 string, payload []byte, timeout time.Duration) (SCIONQUICExchange, error) {
	r, err := scionCall(guestio.SCIONQUICExchangeFunction, invokeSCIONQUICExchange, guestio.SCIONRequest{Address: address, PathID: pathID, CertificateSHA256: certificateSHA256, Payload: payload, TimeoutNS: int64(timeout)})
	if err == nil && r.QUICExchange == nil {
		err = fmt.Errorf("debuglet: missing SCION QUIC exchange result")
	}
	if r.QUICExchange == nil {
		return SCIONQUICExchange{}, err
	}
	return *r.QUICExchange, err
}
