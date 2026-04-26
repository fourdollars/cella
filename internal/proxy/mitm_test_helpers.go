package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"
)

// signHostWithValidity signs a per-host cert with custom NotBefore/NotAfter offsets from now.
// Used by tests to create expired or near-expiry certs.
func (m *MITMConfig) signHostWithValidity(host string, notBeforeOffset, notAfterOffset time.Duration) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"cella MITM test"},
		},
		NotBefore: now.Add(notBeforeOffset),
		NotAfter:  now.Add(notAfterOffset),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, m.CACert, &key.PublicKey, m.CAKey)
	if err != nil {
		return nil, err
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER, m.CACert.Raw},
		PrivateKey:  key,
	}

	return tlsCert, nil
}

// socketPair creates a connected pair of net.Conn for testing.
func socketPair() (net.Conn, net.Conn, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	defer ln.Close()

	var serverConn net.Conn
	done := make(chan error, 1)
	go func() {
		var err error
		serverConn, err = ln.Accept()
		done <- err
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return nil, nil, err
	}

	if err := <-done; err != nil {
		clientConn.Close()
		return nil, nil, err
	}

	return serverConn, clientConn, nil
}
