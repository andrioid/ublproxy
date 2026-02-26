package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"ublproxy/pkg/blocklist"
	"ublproxy/pkg/store"
	"ublproxy/pkg/webauthn"
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

	defaultDataDir := filepath.Join(home, ".ublproxy")

	addr := flag.String("addr", "0.0.0.0", "address to listen on (0.0.0.0 for all interfaces)")
	port := flag.Int("port", 8080, "port to listen on")
	portalPort := flag.Int("portal-port", 8443, "HTTPS portal port for WebAuthn and rule management")
	hostname := flag.String("hostname", "localhost", "portal hostname for WebAuthn and TLS cert (must be a domain, not an IP)")
	caDir := flag.String("ca-dir", defaultDataDir, "directory for CA certificate and key")
	dbPath := flag.String("db", filepath.Join(defaultDataDir, "ublproxy.db"), "path to SQLite database")

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
			var loadErr error
			if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
				fmt.Fprintf(os.Stderr, "Fetching %s\n", src)
				loadErr = rules.LoadURL(src)
			} else {
				loadErr = rules.LoadFile(src)
			}
			if loadErr != nil {
				fmt.Fprintf(os.Stderr, "failed to load blocklist: %v\n", loadErr)
				os.Exit(1)
			}
		}
		fmt.Fprintf(os.Stderr, "Loaded %d blocked hostnames, %d URL rules\n", rules.HostCount(), rules.RuleCount())
	}

	certs := newCertCache(caCert, caKey)
	caCertPEM := encodeCertPEM(caCert)
	handler := newProxyHandler(certs, caCertPEM, rules)

	// Open SQLite database for credential/session/rule storage
	db, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "database setup failed: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()
	handler.store = db
	handler.blocklistSources = blocklistSources

	// Configure WebAuthn with the portal hostname. WebAuthn requires a
	// domain name as RP ID — IP addresses are not allowed by the spec.
	portalOrigin := fmt.Sprintf("https://%s:%d", *hostname, *portalPort)
	webauthnCfg := webauthn.Config{
		RPID:     *hostname,
		RPName:   "ublproxy",
		RPOrigin: portalOrigin,
	}

	sm := newSessionMap()
	api := newAPIHandler(db, webauthnCfg, sm)
	api.onRulesChanged = handler.reloadRules
	handler.api = api
	handler.sessions = sm
	handler.portalOrigin = portalOrigin

	// Auto-detect LAN IP for the portal TLS cert so it covers both the
	// hostname and the LAN IP (useful for CA cert download, etc.)
	var extraIPs []net.IP
	if lanIP := detectLANIP(); lanIP != "" {
		extraIPs = append(extraIPs, net.ParseIP(lanIP))
	}

	// Start HTTPS portal in a goroutine
	portalAddr := fmt.Sprintf("%s:%d", *addr, *portalPort)
	portalH := &portalHandler{proxy: handler, api: api}
	go startPortalHTTPS(portalAddr, *hostname, extraIPs, certs, portalH)

	listenAddr := fmt.Sprintf("%s:%d", *addr, *port)
	fmt.Fprintf(os.Stderr, "ublproxy listening on http://%s\n", listenAddr)
	fmt.Fprintf(os.Stderr, "ublproxy portal at %s\n", portalOrigin)

	if err := http.ListenAndServe(listenAddr, handler); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

// detectLANIP returns the first non-loopback IPv4 address found on a network
// interface that is up and not a point-to-point tunnel. Returns empty string
// if no suitable address is found.
func detectLANIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagPointToPoint != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ip4 := ipnet.IP.To4(); ip4 != nil && !ip4.IsLoopback() {
				return ip4.String()
			}
		}
	}
	return ""
}
