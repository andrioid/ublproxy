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

	var blocklistSources stringSlice
	flag.Var(&blocklistSources, "blocklist", "path or URL to a blocklist file (can be specified multiple times)")

	flag.Parse()

	caCert, caKey, err := loadOrGenerateCA(*caDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "CA setup failed: %v\n", err)
		os.Exit(1)
	}

	var rules *blocklist.RuleSet
	if len(blocklistSources) > 0 {
		rules = blocklist.NewRuleSet()
		for _, src := range blocklistSources {
			var err error
			if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
				fmt.Fprintf(os.Stderr, "Fetching %s\n", src)
				err = rules.LoadURL(src)
			} else {
				err = rules.LoadFile(src)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to load blocklist: %v\n", err)
				os.Exit(1)
			}
		}
		fmt.Fprintf(os.Stderr, "Loaded %d blocked hostnames, %d URL rules\n", rules.HostCount(), rules.RuleCount())
	}

	certs := newCertCache(caCert, caKey)
	caCertPEM := encodeCertPEM(caCert)
	handler := newProxyHandler(certs, caCertPEM, rules)

	listenAddr := fmt.Sprintf("%s:%d", *addr, *port)
	fmt.Fprintf(os.Stderr, "ublproxy listening on http://%s\n", listenAddr)

	if err := http.ListenAndServe(listenAddr, handler); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
