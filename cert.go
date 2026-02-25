package main

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

type certCache struct {
	mu     sync.RWMutex
	certs  map[string]*tls.Certificate
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
}

func newCertCache(caCert *x509.Certificate, caKey *rsa.PrivateKey) *certCache {
	return &certCache{
		certs:  make(map[string]*tls.Certificate),
		caCert: caCert,
		caKey:  caKey,
	}
}

func (c *certCache) getCert(host string) (*tls.Certificate, error) {
	c.mu.RLock()
	if cert, ok := c.certs[host]; ok {
		c.mu.RUnlock()
		return cert, nil
	}
	c.mu.RUnlock()

	cert, err := generateCert(host, c.caCert, c.caKey)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.certs[host] = cert
	c.mu.Unlock()

	return cert, nil
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
