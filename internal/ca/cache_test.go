package ca

import (
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func TestGetCertCachesAndReturns(t *testing.T) {
	caCert, caKey, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	cache := NewCache(caCert, caKey)

	cert1, err := cache.GetCert("example.com")
	if err != nil {
		t.Fatal(err)
	}

	cert2, err := cache.GetCert("example.com")
	if err != nil {
		t.Fatal(err)
	}

	// Same object — cache hit
	serial1 := parseCertSerial(t, cert1)
	serial2 := parseCertSerial(t, cert2)
	if serial1.Cmp(serial2) != 0 {
		t.Error("expected same certificate on cache hit")
	}
}

func TestGetCertRegeneratesExpired(t *testing.T) {
	caCert, caKey, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	cache := NewCache(caCert, caKey)

	cert1, err := cache.GetCert("example.com")
	if err != nil {
		t.Fatal(err)
	}
	serial1 := parseCertSerial(t, cert1)

	// Manually expire the cached entry
	cache.mu.Lock()
	entry := cache.certs["example.com"]
	entry.expiresAt = time.Now().Add(-1 * time.Hour)
	cache.mu.Unlock()

	cert2, err := cache.GetCert("example.com")
	if err != nil {
		t.Fatal(err)
	}
	serial2 := parseCertSerial(t, cert2)

	if serial1.Cmp(serial2) == 0 {
		t.Error("expected different certificate after expiry (should regenerate)")
	}
}

func TestGetCertDifferentHosts(t *testing.T) {
	caCert, caKey, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	cache := NewCache(caCert, caKey)

	cert1, err := cache.GetCert("example.com")
	if err != nil {
		t.Fatal(err)
	}

	cert2, err := cache.GetCert("other.com")
	if err != nil {
		t.Fatal(err)
	}

	serial1 := parseCertSerial(t, cert1)
	serial2 := parseCertSerial(t, cert2)
	if serial1.Cmp(serial2) == 0 {
		t.Error("expected different certificates for different hosts")
	}
}

func parseCertSerial(t *testing.T, cert *tls.Certificate) *big.Int {
	t.Helper()
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return parsed.SerialNumber
}
