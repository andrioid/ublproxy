package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

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
	httpPort := flag.Int("http-port", 8080, "HTTP port for setup page and CA certificate download")
	httpsPort := flag.Int("https-port", 8443, "HTTPS port for proxy, portal, and API")
	hostname := flag.String("hostname", "localhost", "portal hostname for WebAuthn and TLS cert (must be a domain, not an IP)")
	caDir := flag.String("ca-dir", defaultDataDir, "directory for CA certificate and key")
	dbPath := flag.String("db", filepath.Join(defaultDataDir, "ublproxy.db"), "path to SQLite database")

	var blocklistSources stringSlice
	flag.Var(&blocklistSources, "blocklist", "path or URL to a blocklist file (can be specified multiple times)")

	var defaultSubs stringSlice
	flag.Var(&defaultSubs, "default-subscription", "default blocklist subscription URL, always active for all users (can be specified multiple times; defaults to EasyList + EasyPrivacy if none specified)")

	flag.Parse()

	// Built-in defaults if no --default-subscription flags were given
	if len(defaultSubs) == 0 {
		defaultSubs = stringSlice{
			"https://easylist.to/easylist/easylist.txt",
			"https://easylist.to/easylist/easyprivacy.txt",
		}
	}

	caCert, caKey, err := loadOrGenerateCA(*caDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "CA setup failed: %v\n", err)
		os.Exit(1)
	}

	certs := newCertCache(caCert, caKey)
	caCertPEM := encodeCertPEM(caCert)
	handler := newProxyHandler(certs, caCertPEM)
	handler.blocklistSources = blocklistSources
	handler.defaultSubscriptions = defaultSubs

	// Open SQLite database for credential/session/rule storage
	db, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "database setup failed: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()
	handler.store = db

	// Configure WebAuthn with the portal hostname. WebAuthn requires a
	// domain name as RP ID — IP addresses are not allowed by the spec.
	portalOrigin := fmt.Sprintf("https://%s:%d", *hostname, *httpsPort)
	webauthnCfg := webauthn.Config{
		RPID:     *hostname,
		RPName:   "ublproxy",
		RPOrigin: portalOrigin,
	}

	sm := newSessionMap()
	api := newAPIHandler(db, webauthnCfg, sm)
	api.onRulesChanged = handler.invalidateUserRules
	handler.api = api
	handler.sessions = sm
	handler.portalOrigin = portalOrigin

	// Load baseline rules (--blocklist + --default-subscription) at startup.
	// This runs synchronously so rules are ready before traffic arrives.
	handler.reloadBaseline()

	// Auto-detect LAN IP for the portal TLS cert so it covers both the
	// hostname and the LAN IP (useful for CA cert download, etc.)
	var extraIPs []net.IP
	if lanIP := detectLANIP(); lanIP != "" {
		extraIPs = append(extraIPs, net.ParseIP(lanIP))
	}

	// Start HTTPS proxy+portal server in a goroutine. This handles
	// proxy CONNECT/forward, the management portal, and the API.
	httpsAddr := fmt.Sprintf("%s:%d", *addr, *httpsPort)
	portalH := &portalHandler{proxy: handler, api: api}
	go startPortalHTTPS(httpsAddr, *hostname, extraIPs, certs, portalH)

	// HTTP server serves only the setup page and CA certificate download.
	// No proxy, no API — those require TLS on the HTTPS port.
	httpAddr := fmt.Sprintf("%s:%d", *addr, *httpPort)
	setupH := &setupHandler{caCertPEM: caCertPEM, portalOrigin: portalOrigin}
	fmt.Fprintf(os.Stderr, "ublproxy setup page on http://%s\n", httpAddr)
	fmt.Fprintf(os.Stderr, "ublproxy proxy+portal on %s\n", portalOrigin)

	if err := http.ListenAndServe(httpAddr, setupH); err != nil {
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
