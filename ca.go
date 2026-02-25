package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	caCertFilename = "ca.crt"
	caKeyFilename  = "ca.key"
)

func loadOrGenerateCA(caDir string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certPath := filepath.Join(caDir, caCertFilename)
	keyPath := filepath.Join(caDir, caKeyFilename)

	cert, key, err := loadCA(certPath, keyPath)
	if err == nil {
		return cert, key, nil
	}

	if !os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("failed to load CA: %w", err)
	}

	if err := os.MkdirAll(caDir, 0700); err != nil {
		return nil, nil, fmt.Errorf("failed to create CA directory %s: %w", caDir, err)
	}

	cert, key, err = generateCA()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA: %w", err)
	}

	if err := saveCA(certPath, keyPath, cert, key); err != nil {
		return nil, nil, fmt.Errorf("failed to save CA: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Generated new CA certificate at %s\n", certPath)
	fmt.Fprintf(os.Stderr, "Trust this certificate in your OS/browser to use HTTPS interception.\n")

	return cert, key, nil
}

func loadCA(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA key PEM")
	}

	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA key: %w", err)
	}

	return cert, key, nil
}

func generateCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"ublproxy"},
			CommonName:   "ublproxy CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

func encodeCertPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func saveCA(certPath, keyPath string, cert *x509.Certificate, key *rsa.PrivateKey) error {
	certFile, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		return err
	}

	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	return pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}
