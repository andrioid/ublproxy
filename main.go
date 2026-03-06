package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/urfave/cli/v3"

	"ublproxy/internal/ca"
	"ublproxy/internal/store"
	"ublproxy/internal/webauthn"
)

// version is set at build time via -ldflags "-X main.version=..."
var version = "dev"

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get home directory: %v\n", err)
		os.Exit(1)
	}

	defaultDataDir := filepath.Join(home, ".ublproxy")

	cmd := &cli.Command{
		Name:    "ublproxy",
		Usage:   "Ad-blocking HTTPS proxy with WebAuthn authentication",
		Version: version,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "addr",
				Value:   "0.0.0.0",
				Usage:   "address to listen on (0.0.0.0 for all interfaces)",
				Sources: cli.EnvVars("UBLPROXY_ADDR"),
			},
			&cli.IntFlag{
				Name:    "http-port",
				Value:   8080,
				Usage:   "HTTP port for setup page and CA certificate download",
				Sources: cli.EnvVars("UBLPROXY_HTTP_PORT"),
			},
			&cli.IntFlag{
				Name:    "https-port",
				Value:   8443,
				Usage:   "HTTPS port for proxy, portal, and API",
				Sources: cli.EnvVars("UBLPROXY_HTTPS_PORT"),
			},
			&cli.StringFlag{
				Name:    "hostname",
				Value:   "localhost",
				Usage:   "portal hostname for WebAuthn and TLS cert (must be a domain, not an IP)",
				Sources: cli.EnvVars("UBLPROXY_HOSTNAME"),
			},
			&cli.StringFlag{
				Name:    "ca-dir",
				Value:   defaultDataDir,
				Usage:   "directory for CA certificate and key",
				Sources: cli.EnvVars("UBLPROXY_CA_DIR"),
			},
			&cli.StringFlag{
				Name:    "db",
				Value:   filepath.Join(defaultDataDir, "ublproxy.db"),
				Usage:   "path to SQLite database",
				Sources: cli.EnvVars("UBLPROXY_DB"),
			},
			&cli.StringSliceFlag{
				Name:    "blocklist",
				Usage:   "path or URL to a blocklist file (can be specified multiple times)",
				Sources: cli.EnvVars("UBLPROXY_BLOCKLIST"),
			},
			&cli.BoolFlag{
				Name:    "transparent",
				Value:   false,
				Usage:   "run in transparent proxy mode (intercept redirected traffic instead of explicit proxy)",
				Sources: cli.EnvVars("UBLPROXY_TRANSPARENT"),
			},
			&cli.IntFlag{
				Name:    "dns-port",
				Value:   0,
				Usage:   "DNS resolver port for host-level blocking (disabled when 0)",
				Sources: cli.EnvVars("UBLPROXY_DNS_PORT"),
			},
			&cli.StringFlag{
				Name:    "dns-upstream",
				Value:   "1.1.1.1:53",
				Usage:   "upstream DNS resolver address",
				Sources: cli.EnvVars("UBLPROXY_DNS_UPSTREAM"),
			},
			&cli.StringFlag{
				Name:    "log-level",
				Value:   "info",
				Usage:   "log verbosity level (debug, info, warn, error)",
				Sources: cli.EnvVars("UBLPROXY_LOG_LEVEL"),
			},
		},
		Action: run,
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(_ context.Context, cmd *cli.Command) error {
	setupLogging(cmd.String("log-level"))

	addr := cmd.String("addr")
	httpPort := cmd.Int("http-port")
	httpsPort := cmd.Int("https-port")
	hostname := cmd.String("hostname")
	caDir := cmd.String("ca-dir")
	dbPath := cmd.String("db")
	blocklistSources := cmd.StringSlice("blocklist")
	transparent := cmd.Bool("transparent")
	dnsPort := cmd.Int("dns-port")
	dnsUpstream := cmd.String("dns-upstream")

	caCert, caKey, err := ca.LoadOrGenerate(caDir)
	if err != nil {
		return fmt.Errorf("CA setup failed: %w", err)
	}

	certs := ca.NewCache(caCert, caKey)
	caCertPEM := ca.EncodeCertPEM(caCert)
	handler := newProxyHandler(certs, caCertPEM)
	activityLog := NewActivityLog(1000)
	handler.activityLog = activityLog
	handler.blocklistSources = blocklistSources

	db, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("database setup failed: %w", err)
	}
	defer db.Close()
	handler.store = db

	portalOrigin := fmt.Sprintf("https://%s:%d", hostname, httpsPort)
	webauthnCfg := webauthn.Config{
		RPID:     hostname,
		RPName:   "ublproxy",
		RPOrigin: portalOrigin,
	}

	sm := newSessionMap()
	api := newAPIHandler(db, webauthnCfg, sm)
	api.onRulesChanged = handler.invalidateUserRules
	api.activityLog = activityLog
	handler.api = api
	handler.sessions = sm
	handler.portalOrigin = portalOrigin

	handler.reloadBaseline()

	var extraIPs []net.IP
	if lanIP := detectLANIP(); lanIP != "" {
		extraIPs = append(extraIPs, net.ParseIP(lanIP))
	}

	handler.handshakeTracker = newHandshakeTracker(hostname, extraIPs)

	// For the HTTP origin, prefer the LAN IP over "localhost" since
	// devices need a routable address to reach the proxy.
	httpHost := hostname
	if httpHost == "localhost" && len(extraIPs) > 0 {
		httpHost = extraIPs[0].String()
	}
	httpOrigin := fmt.Sprintf("http://%s:%d", httpHost, httpPort)
	handler.httpOrigin = httpOrigin

	httpsAddr := fmt.Sprintf("%s:%d", addr, httpsPort)
	httpAddr := fmt.Sprintf("%s:%d", addr, httpPort)

	if dnsPort > 0 {
		dnsAddr := fmt.Sprintf("%s:%d", addr, dnsPort)
		ds := &dnsServer{
			proxy:    handler,
			upstream: dnsUpstream,
			activity: activityLog,
		}
		go startDNS(dnsAddr, ds)
	}

	if transparent {
		return runTransparent(handler, certs, hostname, extraIPs, httpsAddr, httpAddr)
	}
	return runExplicitProxy(handler, api, certs, caCert, caCertPEM, hostname, extraIPs, portalOrigin, httpOrigin, httpsAddr, httpAddr)
}

func runExplicitProxy(handler *proxyHandler, api *apiHandler, certs *ca.Cache, caCert *x509.Certificate, caCertPEM []byte, hostname string, extraIPs []net.IP, portalOrigin, httpOrigin, httpsAddr, httpAddr string) error {
	portalH := &portalHandler{proxy: handler, api: api}
	go startPortalHTTPS(httpsAddr, hostname, extraIPs, certs, portalH)

	setupH := &setupHandler{
		proxy:        handler,
		caCert:       caCert,
		caCertPEM:    caCertPEM,
		portalOrigin: portalOrigin,
		httpOrigin:   httpOrigin,
	}
	slog.Info("ublproxy setup page", "url", "http://"+httpAddr)
	slog.Info("ublproxy mobile proxy", "url", httpOrigin)
	slog.Info("ublproxy proxy+portal", "url", portalOrigin)

	if err := http.ListenAndServe(httpAddr, setupH); err != nil {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}

func runTransparent(handler *proxyHandler, certs *ca.Cache, hostname string, extraIPs []net.IP, httpsAddr, httpAddr string) error {
	trustTracker := newCATrustTracker()

	slog.Info("ublproxy running in transparent proxy mode")

	go startTransparentHTTPS(httpsAddr, handler, certs, hostname, extraIPs, trustTracker)
	startTransparentHTTP(httpAddr, handler, trustTracker, hostname)
	return nil
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
