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

package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"

	"github.com/netsec-ethz/debuglet/internal/tlsfiles"
)

// ServerTLS is the loaded transport security for the dispatcher's listeners.
//
// Combined carries the HTTP API and the reverse control stream, which share one
// port behind a protocol multiplexer. The multiplexer reads cleartext framing,
// so that connection is terminated before it and offers HTTP/1.1 only: an
// HTTP/2 connection negotiated through ALPN would reach the multiplexer as a
// preface it cannot route back into a protocol-aware server. Direct is the
// separate gRPC listener, which offers h2 because gRPC requires it.
//
// Both listeners present the same server identity and trust the same authority,
// so an executor verifies one name and one root for both of its channels.
type ServerTLS struct {
	Combined *tls.Config
	Direct   *tls.Config
	// RequireClientIdentity reports whether an executor must present a
	// certificate issued by tls.ca_file on both control channels.
	RequireClientIdentity bool
}

// LoadServerTLS reads the configured server identity and trust roots. It
// returns nil without an error for a plaintext listener, and otherwise fails
// naming the configuration key an operator has to correct — before the command
// opens storage or binds a listener, so an unusable certificate never leaves a
// half-started daemon serving a downgraded connection.
func LoadServerTLS(cfg TLSConfig) (*ServerTLS, error) {
	return loadServerTLS(cfg, time.Now())
}

func loadServerTLS(cfg TLSConfig, now time.Time) (*ServerTLS, error) {
	if cfg.Disable {
		if cfg.RequireClientCert {
			return nil, errors.New("tls.require_client_cert needs tls.disable = false: a plaintext listener has no client certificate to verify")
		}
		return nil, nil
	}
	certificate, err := tlsfiles.KeyPair("tls.cert_file", cfg.CertFile, "tls.key_file", cfg.KeyFile, now)
	if err != nil {
		return nil, err
	}
	var roots *x509.CertPool
	if cfg.CAFile != "" {
		roots, err = tlsfiles.TrustRoots("tls.ca_file", cfg.CAFile, now)
		if err != nil {
			return nil, err
		}
	}
	if cfg.RequireClientCert && roots == nil {
		return nil, errors.New("tls.require_client_cert needs tls.ca_file, which names the authority that issues executor certificates")
	}
	combined := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    roots,
		// A submitter reaching the HTTP API holds no certificate, so the
		// shared listener asks for none. A certificate that is offered is
		// verified, and the reverse control stream requires one separately.
		ClientAuth: tls.NoClientCert,
		NextProtos: []string{"http/1.1"},
	}
	if roots != nil {
		combined.ClientAuth = tls.VerifyClientCertIfGiven
	}
	direct := combined.Clone()
	direct.NextProtos = []string{"h2"}
	if cfg.RequireClientCert {
		direct.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return &ServerTLS{Combined: combined, Direct: direct, RequireClientIdentity: cfg.RequireClientCert}, nil
}
