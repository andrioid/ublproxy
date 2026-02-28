package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"time"
)

type Cache struct {
	mu    sync.RWMutex
	certs map[string]*tls.Certificate

	CACert *x509.Certificate
	caKey  *rsa.PrivateKey
}

func NewCache(caCert *x509.Certificate, caKey *rsa.PrivateKey) *Cache {
	return &Cache{
		certs:  make(map[string]*tls.Certificate),
		CACert: caCert,
		caKey:  caKey,
	}
}

func (c *Cache) GetCert(host string) (*tls.Certificate, error) {
	c.mu.RLock()
	if cert, ok := c.certs[host]; ok {
		c.mu.RUnlock()
		return cert, nil
	}
	c.mu.RUnlock()

	cert, err := generateCert(host, c.CACert, c.caKey)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.certs[host] = cert
	c.mu.Unlock()

	return cert, nil
}

// PortalCert generates a TLS certificate for the portal that covers the
// given hostname, localhost, 127.0.0.1, and any additional IPs (e.g. the
// LAN IP). This allows access via hostname, localhost, or direct IP
// without TLS errors.
func (c *Cache) PortalCert(host string, extraIPs ...net.IP) (*tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"ublproxy"},
			CommonName:   host,
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{
			net.IPv4(127, 0, 0, 1),
		},
	}

	// Add the host as either a DNS or IP SAN
	if ip := net.ParseIP(host); ip != nil {
		if !ip.IsLoopback() {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	} else if host != "localhost" {
		template.DNSNames = append(template.DNSNames, host)
	}

	// Add any extra IPs (e.g. auto-detected LAN IP)
	for _, ip := range extraIPs {
		if ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, c.CACert, &key.PublicKey, c.caKey)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}

func generateCert(host string, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"ublproxy"},
			CommonName:   host,
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
		// Browsers check the hostname they typed against the cert's SANs.
		// Visiting https://localhost resolves to 127.0.0.1, but the cert
		// needs a DNS SAN for "localhost" to satisfy the hostname check.
		if ip.IsLoopback() {
			template.DNSNames = []string{"localhost"}
		}
	} else {
		template.DNSNames = []string{host}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	return tlsCert, nil
}
