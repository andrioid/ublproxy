package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"ublproxy/pkg/blocklist"
)

// stringSlice implements flag.Value to support repeated CLI flags.
type stringSlice []string

func (s *stringSlice) String() string     { return strings.Join(*s, ", ") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get home directory: %v\n", err)
		os.Exit(1)
	}

	addr := flag.String("addr", "127.0.0.1", "address to listen on")
	port := flag.Int("port", 8080, "port to listen on")
	caDir := flag.String("ca-dir", filepath.Join(home, ".ublproxy"), "directory for CA certificate and key")

	var blocklistPaths stringSlice
	flag.Var(&blocklistPaths, "blocklist", "path to a blocklist file (can be specified multiple times)")

	flag.Parse()

	caCert, caKey, err := loadOrGenerateCA(*caDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "CA setup failed: %v\n", err)
		os.Exit(1)
	}

	var bl *blocklist.Blocklist
	if len(blocklistPaths) > 0 {
		bl = blocklist.New()
		for _, path := range blocklistPaths {
			if err := bl.LoadFile(path); err != nil {
				fmt.Fprintf(os.Stderr, "failed to load blocklist: %v\n", err)
				os.Exit(1)
			}
		}
		fmt.Fprintf(os.Stderr, "Loaded %d blocked hostnames\n", bl.Len())
	}

	certs := newCertCache(caCert, caKey)
	caCertPEM := encodeCertPEM(caCert)
	handler := newProxyHandler(certs, caCertPEM, bl)

	listenAddr := fmt.Sprintf("%s:%d", *addr, *port)
	fmt.Fprintf(os.Stderr, "ublproxy listening on http://%s\n", listenAddr)

	if err := http.ListenAndServe(listenAddr, handler); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
