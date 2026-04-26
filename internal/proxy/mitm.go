package proxy

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
	"sync"
	"time"
)

// MITMConfig holds the CA certificate and key for TLS interception
type MITMConfig struct {
	CACert    *x509.Certificate
	CAKey     *ecdsa.PrivateKey
	CAPem     []byte // PEM-encoded CA cert (for container injection)
	certCache map[string]*tls.Certificate
	mu        sync.RWMutex
}

// NewMITMConfig generates a new CA or loads from disk
func NewMITMConfig(dataDir string) (*MITMConfig, error) {
	certPath := filepath.Join(dataDir, "cella-ca.pem")
	keyPath := filepath.Join(dataDir, "cella-ca-key.pem")

	// Try loading existing CA
	if cfg, err := loadCA(certPath, keyPath); err == nil {
		return cfg, nil
	}

	// Generate new CA
	cfg, err := generateCA()
	if err != nil {
		return nil, fmt.Errorf("generate CA: %w", err)
	}

	// Save to disk
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dataDir, err)
	}
	if err := os.WriteFile(certPath, cfg.CAPem, 0644); err != nil {
		return nil, fmt.Errorf("write CA cert: %w", err)
	}
	keyPem, err := marshalECKey(cfg.CAKey)
	if err != nil {
		return nil, fmt.Errorf("marshal CA key: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPem, 0600); err != nil {
		return nil, fmt.Errorf("write CA key: %w", err)
	}

	return cfg, nil
}

// GetCertForHost returns a TLS certificate for the given hostname, signed by our CA.
// Certs are cached and reused. Expired or nearly-expired certs are automatically
// re-signed so that long-running proxy sessions do not lose MITM capability.
func (m *MITMConfig) GetCertForHost(host string) (*tls.Certificate, error) {
	m.mu.RLock()
	if cert, ok := m.certCache[host]; ok {
		// Check whether the cached cert is still valid (with 5-minute buffer).
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err == nil && time.Now().Add(5*time.Minute).Before(leaf.NotAfter) {
			m.mu.RUnlock()
			return cert, nil
		}
		// Expired or about to expire — fall through to re-sign.
	}
	m.mu.RUnlock()

	// Generate (or re-generate) cert for this host
	cert, err := m.signHost(host)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.certCache[host] = cert
	m.mu.Unlock()

	return cert, nil
}

// CACertPEM returns the PEM-encoded CA certificate for injection into containers
func (m *MITMConfig) CACertPEM() []byte {
	return m.CAPem
}

func generateCA() (*MITMConfig, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"cella MITM Proxy"},
			CommonName:   "cella Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour), // 5 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return &MITMConfig{
		CACert:    cert,
		CAKey:     key,
		CAPem:     certPEM,
		certCache: make(map[string]*tls.Certificate),
	}, nil
}

func loadCA(certPath, keyPath string) (*MITMConfig, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("no PEM block in %s", keyPath)
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return &MITMConfig{
		CACert:    cert,
		CAKey:     key,
		CAPem:     certPEM,
		certCache: make(map[string]*tls.Certificate),
	}, nil
}

func (m *MITMConfig) signHost(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"cella MITM"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour), // 24h per-host cert
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	// Add SANs
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

func marshalECKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}
