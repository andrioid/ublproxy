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

type cachedCert struct {
	cert      *tls.Certificate
	expiresAt time.Time
}

type Cache struct {
	mu    sync.RWMutex
	certs map[string]*cachedCert

	// Portal cert cached separately from per-host certs
	portalCert *cachedCert
	portalHost string
	portalIPs  []net.IP

	CACert *x509.Certificate
	caKey  *rsa.PrivateKey
}

func NewCache(caCert *x509.Certificate, caKey *rsa.PrivateKey) *Cache {
	return &Cache{
		certs:  make(map[string]*cachedCert),
		CACert: caCert,
		caKey:  caKey,
	}
}

// SetPortalParams stores the hostname and extra IPs used for portal cert
// generation. These are fixed for the lifetime of the process.
func (c *Cache) SetPortalParams(host string, extraIPs []net.IP) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.portalHost = host
	c.portalIPs = extraIPs
}

// GetPortalCert returns a cached portal certificate, regenerating it when
// expired. SetPortalParams must be called before the first call.
func (c *Cache) GetPortalCert() (*tls.Certificate, error) {
	c.mu.RLock()
	if c.portalCert != nil && time.Now().Before(c.portalCert.expiresAt) {
		cert := c.portalCert.cert
		c.mu.RUnlock()
		return cert, nil
	}
	c.mu.RUnlock()

	cert, err := c.PortalCert(c.portalHost, c.portalIPs...)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.portalCert = &cachedCert{
		cert:      cert,
		expiresAt: time.Now().Add(24 * time.Hour),
	}
	c.mu.Unlock()

	return cert, nil
}

func (c *Cache) GetCert(host string) (*tls.Certificate, error) {
	c.mu.RLock()
	if entry, ok := c.certs[host]; ok && time.Now().Before(entry.expiresAt) {
		c.mu.RUnlock()
		return entry.cert, nil
	}
	c.mu.RUnlock()

	cert, err := generateCert(host, c.CACert, c.caKey)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.certs[host] = &cachedCert{
		cert:      cert,
		expiresAt: time.Now().Add(24 * time.Hour),
	}
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
