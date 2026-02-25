package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get home directory: %v\n", err)
		os.Exit(1)
	}

	addr := flag.String("addr", "127.0.0.1", "address to listen on")
	port := flag.Int("port", 8080, "port to listen on")
	caDir := flag.String("ca-dir", filepath.Join(home, ".ublproxy"), "directory for CA certificate and key")
	flag.Parse()

	caCert, caKey, err := loadOrGenerateCA(*caDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "CA setup failed: %v\n", err)
		os.Exit(1)
	}

	certs := newCertCache(caCert, caKey)
	caCertPEM := encodeCertPEM(caCert)
	handler := newProxyHandler(certs, caCertPEM)

	listenAddr := fmt.Sprintf("%s:%d", *addr, *port)
	fmt.Fprintf(os.Stderr, "ublproxy listening on %s\n", listenAddr)

	if err := http.ListenAndServe(listenAddr, handler); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
