// Package testtls issues certificate material for tests that need real TLS
// sockets: one authority, the identities it signs, and the unusable variants a
// verification test has to reject. Everything is generated in the running
// process and written into a caller-owned directory, so no key is checked in
// and no test depends on an external tool.
package testtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Identity is one issued certificate with its private key, held in memory and
// written as the PEM files a daemon configuration names.
type Identity struct {
	CertFile, KeyFile string
	CertPEM, KeyPEM   []byte
	Certificate       tls.Certificate
}

// Authority signs identities and is the trust root its peers configure.
type Authority struct {
	Identity
	dir         string
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
}

// Options selects what an issued identity is usable for. The zero value is a
// server identity valid for an hour around now and carrying no name.
type Options struct {
	// Hosts are the DNS names and IP addresses the certificate carries.
	Hosts []string
	// Client and Server select the extended key usages. Neither selected is
	// a server identity, which is what most fixtures need.
	Client, Server bool
	// NotBefore and NotAfter bound validity; zero spans an hour around now.
	NotBefore, NotAfter time.Time
}

// NewAuthority creates a self-signed authority in dir. Its CertFile is the
// PEM file a peer names as its trust root.
func NewAuthority(dir, name string) (*Authority, error) {
	return newAuthority(dir, name, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
}

// NewExpiredAuthority creates an authority whose own certificate has expired,
// for the checks that refuse a root no chain could be built on.
func NewExpiredAuthority(dir, name string) (*Authority, error) {
	return newAuthority(dir, name, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
}

func newAuthority(dir, name string, notBefore, notAfter time.Time) (*Authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	a := &Authority{dir: dir, key: key}
	a.Identity, err = write(dir, name, template, template, &key.PublicKey, key, key)
	if err != nil {
		return nil, err
	}
	a.certificate, err = x509.ParseCertificate(a.Certificate.Certificate[0])
	if err != nil {
		return nil, err
	}
	return a, nil
}

// Issue signs one identity and writes it next to the authority.
func (a *Authority) Issue(name string, opts Options) (*Identity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	notBefore, notAfter := opts.NotBefore, opts.NotAfter
	if notBefore.IsZero() {
		notBefore = time.Now().Add(-time.Hour)
	}
	if notAfter.IsZero() {
		notAfter = time.Now().Add(time.Hour)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	if opts.Server || !opts.Client {
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	if opts.Client {
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	for _, host := range opts.Hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
			continue
		}
		template.DNSNames = append(template.DNSNames, host)
	}
	identity, err := write(a.dir, name, template, a.certificate, &key.PublicKey, key, a.key)
	if err != nil {
		return nil, err
	}
	return &identity, nil
}

// Pool returns the authority as a verification root.
func (a *Authority) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(a.CertPEM)
	return pool
}

// ServerConfig is a listener profile that verifies client certificates the
// authority issued when required, and requests none otherwise.
func (a *Authority) ServerConfig(identity *Identity, requireClient bool) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{identity.Certificate}, ClientCAs: a.Pool()}
	cfg.ClientAuth = tls.VerifyClientCertIfGiven
	if requireClient {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg
}

// ClientConfig verifies the peer against this authority. A nil identity sends
// no client certificate, which is what an unenrolled peer looks like.
func (a *Authority) ClientConfig(identity *Identity, serverName string) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: a.Pool(), ServerName: serverName}
	if identity != nil {
		cfg.Certificates = []tls.Certificate{identity.Certificate}
	}
	return cfg
}

func write(dir, name string, template, parent *x509.Certificate, public any, key, signer *ecdsa.PrivateKey) (Identity, error) {
	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
	if err != nil {
		return Identity{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return Identity{}, err
	}
	identity := Identity{
		CertFile: filepath.Join(dir, name+".crt"),
		KeyFile:  filepath.Join(dir, name+".key"),
		CertPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:   pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
	if err := os.WriteFile(identity.CertFile, identity.CertPEM, 0o600); err != nil {
		return Identity{}, err
	}
	if err := os.WriteFile(identity.KeyFile, identity.KeyPEM, 0o600); err != nil {
		return Identity{}, err
	}
	identity.Certificate, err = tls.X509KeyPair(identity.CertPEM, identity.KeyPEM)
	if err != nil {
		return Identity{}, err
	}
	return identity, nil
}

func serialNumber() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("certificate serial: %w", err)
	}
	return serial, nil
}
