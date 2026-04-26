package proxy

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestGetCertForHost_CachesAndReuses(t *testing.T) {
	cfg, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}

	cert1, err := cfg.GetCertForHost("example.com")
	if err != nil {
		t.Fatal(err)
	}
	cert2, err := cfg.GetCertForHost("example.com")
	if err != nil {
		t.Fatal(err)
	}

	// Same pointer = same cached cert
	if cert1 != cert2 {
		t.Error("expected same cached cert, got different instances")
	}
}

func TestGetCertForHost_DifferentHostsDifferentCerts(t *testing.T) {
	cfg, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}

	cert1, err := cfg.GetCertForHost("a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	cert2, err := cfg.GetCertForHost("b.example.com")
	if err != nil {
		t.Fatal(err)
	}

	if cert1 == cert2 {
		t.Error("expected different certs for different hosts")
	}
}

func TestGetCertForHost_RenewsExpiredCert(t *testing.T) {
	cfg, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}

	// Get a cert normally
	cert1, err := cfg.GetCertForHost("expire-test.com")
	if err != nil {
		t.Fatal(err)
	}

	leaf1, err := x509.ParseCertificate(cert1.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	// Manually inject an already-expired cert into the cache
	cfg.mu.Lock()
	expiredCert, err := cfg.signHostWithValidity("expire-test.com", -2*time.Hour, -1*time.Hour)
	if err != nil {
		cfg.mu.Unlock()
		t.Fatal(err)
	}
	cfg.certCache["expire-test.com"] = expiredCert
	cfg.mu.Unlock()

	// GetCertForHost should detect the expiry and re-sign
	cert2, err := cfg.GetCertForHost("expire-test.com")
	if err != nil {
		t.Fatal(err)
	}

	leaf2, err := x509.ParseCertificate(cert2.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	// The renewed cert should have a later NotAfter
	if !leaf2.NotAfter.After(leaf1.NotAfter.Add(-25 * time.Hour)) {
		t.Errorf("renewed cert NotAfter (%v) should be much later than expired cert", leaf2.NotAfter)
	}

	// The renewed cert should be valid now
	if time.Now().Before(leaf2.NotBefore) || time.Now().After(leaf2.NotAfter) {
		t.Errorf("renewed cert should be valid now, NotBefore=%v NotAfter=%v", leaf2.NotBefore, leaf2.NotAfter)
	}
}

func TestGetCertForHost_RenewsNearlyExpiredCert(t *testing.T) {
	cfg, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}

	// Inject a cert that expires in 3 minutes (inside 5-minute buffer)
	cfg.mu.Lock()
	soonCert, err := cfg.signHostWithValidity("soon-test.com", -1*time.Hour, 3*time.Minute)
	if err != nil {
		cfg.mu.Unlock()
		t.Fatal(err)
	}
	cfg.certCache["soon-test.com"] = soonCert
	cfg.mu.Unlock()

	soonLeaf, _ := x509.ParseCertificate(soonCert.Certificate[0])

	// GetCertForHost should renew because 3min < 5min buffer
	renewed, err := cfg.GetCertForHost("soon-test.com")
	if err != nil {
		t.Fatal(err)
	}

	renewedLeaf, err := x509.ParseCertificate(renewed.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	if !renewedLeaf.NotAfter.After(soonLeaf.NotAfter) {
		t.Error("cert within 5-minute buffer should have been renewed")
	}
}

func TestSingleConnListener_CloseUnblocksAccept(t *testing.T) {
	// Create a pair of connected sockets
	server, client, err := socketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer server.Close()

	ln := newSingleConnListener(server)

	// First Accept should return the conn
	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("first Accept: %v", err)
	}
	if conn == nil {
		t.Fatal("first Accept returned nil conn")
	}

	// Second Accept should block until Close
	done := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		done <- err
	}()

	// Give the goroutine time to block
	time.Sleep(50 * time.Millisecond)

	select {
	case <-done:
		t.Fatal("second Accept returned before Close was called")
	default:
		// Good — it's blocking
	}

	// Close should unblock
	_ = ln.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Error("expected error from Accept after Close, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second Accept did not unblock after Close — goroutine leak!")
	}
}
