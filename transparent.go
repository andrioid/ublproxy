package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"ublproxy/internal/ca"
)

// caTrustTracker tracks which client IPs have successfully completed a
// TLS handshake with a MITM certificate, indicating they trust the proxy CA.
// Untrusted clients are redirected to the captive portal on HTTP requests.
type caTrustTracker struct {
	mu      sync.RWMutex
	trusted map[string]bool
}

func newCATrustTracker() *caTrustTracker {
	return &caTrustTracker{trusted: make(map[string]bool)}
}

func (t *caTrustTracker) isTrusted(ip string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.trusted[ip]
}

func (t *caTrustTracker) markTrusted(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.trusted[ip] = true
}

// extractSNI reads the TLS ClientHello from a buffered reader and returns
// the Server Name Indication (SNI) hostname. The bytes are peeked, not
// consumed — the reader can be replayed for the actual TLS handshake.
// Returns empty string if the ClientHello contains no SNI extension.
func extractSNI(br *bufio.Reader) (string, error) {
	// TLS record header: content_type(1) + version(2) + length(2)
	header, err := br.Peek(5)
	if err != nil {
		return "", fmt.Errorf("read TLS record header: %w", err)
	}

	// content_type 22 = Handshake
	if header[0] != 22 {
		return "", errors.New("not a TLS handshake record")
	}

	recordLen := int(header[3])<<8 | int(header[4])
	if recordLen < 4 || recordLen > 16384 {
		return "", fmt.Errorf("invalid TLS record length: %d", recordLen)
	}

	// Peek the full record (header + body)
	full, err := br.Peek(5 + recordLen)
	if err != nil {
		return "", fmt.Errorf("read TLS record body: %w", err)
	}

	// Handshake message starts after the 5-byte record header.
	// handshake_type(1) + length(3) + ...
	hs := full[5:]
	if hs[0] != 1 {
		return "", errors.New("not a ClientHello message")
	}

	// Skip handshake header (4 bytes: type + 3-byte length)
	if len(hs) < 4 {
		return "", errors.New("ClientHello too short")
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+hsLen {
		return "", errors.New("ClientHello truncated")
	}
	msg := hs[4 : 4+hsLen]

	return parseSNIFromClientHello(msg)
}

// parseSNIFromClientHello parses a raw ClientHello message body (after the
// 4-byte handshake header) and extracts the SNI hostname.
func parseSNIFromClientHello(msg []byte) (string, error) {
	// ClientHello structure:
	//   client_version(2) + random(32) + session_id_len(1) + session_id(...)
	//   + cipher_suites_len(2) + cipher_suites(...)
	//   + compression_methods_len(1) + compression_methods(...)
	//   + extensions_len(2) + extensions(...)

	if len(msg) < 34 {
		return "", errors.New("ClientHello too short for version+random")
	}
	pos := 34 // skip version(2) + random(32)

	// Session ID
	if pos >= len(msg) {
		return "", errors.New("ClientHello too short for session_id_len")
	}
	sessionIDLen := int(msg[pos])
	pos++
	pos += sessionIDLen

	// Cipher suites
	if pos+2 > len(msg) {
		return "", errors.New("ClientHello too short for cipher_suites_len")
	}
	cipherSuitesLen := int(msg[pos])<<8 | int(msg[pos+1])
	pos += 2
	pos += cipherSuitesLen

	// Compression methods
	if pos >= len(msg) {
		return "", errors.New("ClientHello too short for compression_methods_len")
	}
	compMethodsLen := int(msg[pos])
	pos++
	pos += compMethodsLen

	// Extensions
	if pos+2 > len(msg) {
		// No extensions — no SNI
		return "", nil
	}
	extensionsLen := int(msg[pos])<<8 | int(msg[pos+1])
	pos += 2

	end := pos + extensionsLen
	if end > len(msg) {
		return "", errors.New("extensions length exceeds message")
	}

	for pos+4 <= end {
		extType := int(msg[pos])<<8 | int(msg[pos+1])
		extLen := int(msg[pos+2])<<8 | int(msg[pos+3])
		pos += 4

		if pos+extLen > end {
			break
		}

		// Extension type 0 = server_name
		if extType == 0 {
			return parseSNIExtension(msg[pos : pos+extLen])
		}

		pos += extLen
	}

	return "", nil
}

// parseSNIExtension parses the server_name extension data.
func parseSNIExtension(data []byte) (string, error) {
	// ServerNameList: list_len(2) + entries...
	if len(data) < 2 {
		return "", nil
	}
	listLen := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) < listLen {
		return "", nil
	}

	pos := 0
	for pos+3 <= listLen {
		nameType := data[pos]
		nameLen := int(data[pos+1])<<8 | int(data[pos+2])
		pos += 3
		if pos+nameLen > listLen {
			break
		}
		// name_type 0 = host_name
		if nameType == 0 {
			return string(data[pos : pos+nameLen]), nil
		}
		pos += nameLen
	}

	return "", nil
}

// captivePortalHosts are the hostnames used by operating systems for
// captive portal / connectivity detection. In transparent mode, HTTP
// requests to these hosts from untrusted clients trigger the captive
// portal redirect.
var captivePortalHosts = map[string]bool{
	"captive.apple.com":             true,
	"connectivitycheck.gstatic.com": true,
	"connectivitycheck.android.com": true,
	"clients3.google.com":           true,
	"www.msftconnecttest.com":       true,
	"dns.msftncsi.com":              true,
	"detectportal.firefox.com":      true,
	"www.msftncsi.com":              true,
	"msftconnecttest.com":           true,
	"connectivity-check.ubuntu.com": true,
	"nmcheck.gnome.org":             true,
	"network-test.debian.org":       true,
}

func isCaptivePortalHost(host string) bool {
	// Strip port if present
	h := host
	if i := strings.LastIndex(h, ":"); i != -1 {
		h = h[:i]
	}
	return captivePortalHosts[h]
}

// transparentHTTPHandler serves intercepted plain HTTP traffic in
// transparent proxy mode. It uses the Host header to determine the
// original destination and forwards the request upstream.
// For untrusted clients hitting captive portal detection URLs, it
// returns a redirect to the setup page.
type transparentHTTPHandler struct {
	proxy        *proxyHandler
	trustTracker *caTrustTracker
	portalHost   string
}

func (h *transparentHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if host == "" {
		http.Error(w, "missing Host header", http.StatusBadRequest)
		return
	}

	// Strip port for hostname matching
	hostOnly := host
	if i := strings.LastIndex(hostOnly, ":"); i != -1 {
		hostOnly = hostOnly[:i]
	}

	// Requests to the proxy's own hostname serve the portal/setup page
	if hostOnly == h.portalHost {
		h.servePortal(w, r)
		return
	}

	clientIP := clientIPFromRequest(r)

	// Captive portal detection from untrusted clients: redirect to setup
	if !h.trustTracker.isTrusted(clientIP) && isCaptivePortalHost(host) {
		setupURL := h.proxy.httpOrigin + "/setup"
		http.Redirect(w, r, setupURL, http.StatusFound)
		return
	}

	// Forward the request upstream using the Host header as destination
	h.forwardHTTP(w, r, host)
}

// servePortal serves the setup page and related resources when clients
// access the proxy's own hostname in transparent mode.
func (h *transparentHTTPHandler) servePortal(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/ca.crt" {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="ublproxy-ca.crt"`)
		w.WriteHeader(http.StatusOK)
		w.Write(h.proxy.caCertPEM)
		return
	}
	if serveStaticFile(w, r.URL.Path) {
		return
	}
	if r.URL.Path == "/" || r.URL.Path == "/setup" {
		servePage(w, setupTmpl, setupData{
			PortalURL:   h.proxy.portalOrigin,
			HttpOrigin:  h.proxy.httpOrigin,
			Transparent: true,
		})
		return
	}
	http.NotFound(w, r)
}

// forwardHTTP forwards an HTTP request to the upstream server determined
// by the Host header. This is the transparent proxy equivalent of
// proxyHandler.handleHTTP, but the destination comes from Host instead
// of an absolute URL.
func (h *transparentHTTPHandler) forwardHTTP(w http.ResponseWriter, r *http.Request, host string) {
	targetURL := "http://" + host + r.URL.RequestURI()
	clientIP := clientIPFromRequest(r)
	credID := h.proxy.credentialForIP(clientIP)

	ctx := matchContextFromRequest(r)
	if h.proxy.shouldBlock(clientIP, targetURL, ctx) {
		h.proxy.logActivity(ActivityBlocked, host, targetURL, "", clientIP, credID)
		logBlocked(host, targetURL, "", clientIP, credID)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// WebSocket and other protocol upgrades need special handling
	if isWebSocketUpgrade(r.Header) {
		h.forwardHTTPUpgrade(w, r, targetURL)
		return
	}

	start := time.Now()

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		logError("transparent-http/new-request", err, clientIP, credID)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	copyHeaders(outReq.Header, r.Header)
	removeHopByHopHeaders(outReq.Header)

	resp, err := h.proxy.transport.RoundTrip(outReq)
	if err != nil {
		logError("transparent-http/roundtrip", err, clientIP, credID)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	insecure := true // transparent HTTP is always insecure
	if r.Method != http.MethodHead {
		if modified, ok := h.proxy.applyElementHiding(resp, host, clientIP, insecure); ok {
			copyHeaders(w.Header(), resp.Header)
			removeHopByHopHeaders(w.Header())
			w.Header().Del("Content-Length")
			w.WriteHeader(resp.StatusCode)
			w.Write(modified)
			logRequest(r.Method, targetURL, resp.StatusCode, time.Since(start), clientIP, credID)
			return
		}
	}

	copyHeaders(w.Header(), resp.Header)
	removeHopByHopHeaders(w.Header())
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)

	logRequest(r.Method, targetURL, resp.StatusCode, time.Since(start), clientIP, credID)
}

// forwardHTTPUpgrade handles WebSocket and other protocol upgrade requests
// in transparent HTTP mode. It mirrors proxyHandler.handleHTTPUpgrade but
// builds the target URL from the Host header.
func (h *transparentHTTPHandler) forwardHTTPUpgrade(w http.ResponseWriter, r *http.Request, targetURL string) {
	clientIP := clientIPFromRequest(r)
	credID := h.proxy.credentialForIP(clientIP)

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		logError("transparent-http/upgrade/new-request", err, clientIP, credID)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	copyHeaders(outReq.Header, r.Header)
	removeHopByHopHeaders(outReq.Header)

	// Re-add the upgrade headers that were stripped as hop-by-hop
	outReq.Header.Set("Connection", "Upgrade")
	outReq.Header.Set("Upgrade", r.Header.Get("Upgrade"))

	resp, err := h.proxy.transport.RoundTrip(outReq)
	if err != nil {
		logError("transparent-http/upgrade/roundtrip", err, clientIP, credID)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer resp.Body.Close()
		copyHeaders(w.Header(), resp.Header)
		removeHopByHopHeaders(w.Header())
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return
	}

	upstreamConn, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		resp.Body.Close()
		http.Error(w, "upstream does not support hijacking", http.StatusInternalServerError)
		return
	}
	defer upstreamConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		logError("transparent-http/upgrade/hijack", err, clientIP, credID)
		return
	}
	defer clientConn.Close()

	resp.Body = nil
	resp.Write(clientConn)
	clientBuf.Flush()

	bidirectionalCopy(clientConn, upstreamConn)
}

// serveTransparentTLS accepts raw TCP connections on the listener and
// handles them as transparent HTTPS proxy connections. It peeks at the
// TLS ClientHello to extract the SNI hostname, then either:
//   - serves the portal (if destination is the proxy itself)
//   - passes through (if host has @@ exception)
//   - closes the connection (if host is blocked)
//   - performs MITM and proxies the decrypted HTTP requests
func serveTransparentTLS(ln net.Listener, proxy *proxyHandler, certs *ca.Cache, portalHost string, portalIPs []net.IP, trustTracker *caTrustTracker) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			logError("transparent-tls/accept", err, "", "")
			continue
		}
		go handleTransparentTLSConn(conn, proxy, certs, portalHost, portalIPs, trustTracker)
	}
}

func handleTransparentTLSConn(conn net.Conn, proxy *proxyHandler, certs *ca.Cache, portalHost string, portalIPs []net.IP, trustTracker *caTrustTracker) {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	br := bufio.NewReader(conn)
	sni, err := extractSNI(br)
	if err != nil {
		logError("transparent-tls/sni", err, clientIP, "")
		return
	}

	if sni == "" {
		logError("transparent-tls/sni", errors.New("no SNI in ClientHello"), clientIP, "")
		return
	}

	credID := proxy.credentialForIP(clientIP)

	// Portal access: serve the management portal when client connects
	// to the proxy's own hostname or IP
	if sni == portalHost || isPortalIP(sni, portalIPs) {
		handleTransparentPortalTLS(conn, br, proxy, certs, portalHost, portalIPs, clientIP)
		return
	}

	// Blocked host: close connection
	if proxy.shouldBlockHost(clientIP, sni) {
		proxy.logActivity(ActivityBlocked, sni, "", "||"+sni+"^", clientIP, credID)
		logBlocked(sni, "", "||"+sni+"^", clientIP, credID)
		return
	}

	// Passthrough: relay raw TCP to upstream
	if proxy.isHostExcepted(clientIP, sni) {
		proxy.logActivity(ActivityPassthrough, sni, "", "@@||"+sni+"^", clientIP, credID)
		handleTransparentPassthrough(conn, br, sni, clientIP, credID)
		return
	}

	// MITM: generate cert, complete TLS handshake, proxy requests
	handleTransparentMITM(conn, br, proxy, certs, sni, clientIP, credID, trustTracker)
}

func isPortalIP(sni string, portalIPs []net.IP) bool {
	ip := net.ParseIP(sni)
	if ip == nil {
		return false
	}
	for _, portalIP := range portalIPs {
		if ip.Equal(portalIP) {
			return true
		}
	}
	return false
}

// handleTransparentPortalTLS completes a TLS handshake using the portal
// certificate and serves the management portal over HTTPS.
func handleTransparentPortalTLS(conn net.Conn, br *bufio.Reader, proxy *proxyHandler, certs *ca.Cache, portalHost string, portalIPs []net.IP, clientIP string) {
	cert, err := certs.PortalCert(portalHost, portalIPs...)
	if err != nil {
		logError("transparent-tls/portal-cert", err, clientIP, "")
		return
	}

	// Wrap the connection to replay peeked bytes
	replayConn := &replayConn{Conn: conn, reader: br}

	tlsConn := tls.Server(replayConn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
	})
	if err := tlsConn.Handshake(); err != nil {
		logError("transparent-tls/portal-handshake", err, clientIP, "")
		return
	}
	defer tlsConn.Close()

	conn.SetDeadline(time.Time{})

	// Serve portal pages over the TLS connection.
	// singleConnListener blocks the second Accept until the wrapped
	// connection is closed (client disconnect or idle timeout), so
	// Serve doesn't return before the response is fully written.
	portalH := &portalHandler{proxy: proxy, api: proxy.api}
	server := http.Server{
		Handler:     portalH,
		IdleTimeout: 5 * time.Second,
	}
	serverConn := &singleConnListener{conn: tlsConn}
	server.Serve(serverConn)
}

// handleTransparentPassthrough relays raw TCP bytes between the client
// and the upstream server. The peeked ClientHello bytes are forwarded
// to upstream so the TLS handshake completes end-to-end.
func handleTransparentPassthrough(conn net.Conn, br *bufio.Reader, sni, clientIP, credID string) {
	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(sni, "443"), 10*time.Second)
	if err != nil {
		logError("transparent-tls/passthrough-dial", err, clientIP, credID)
		return
	}
	defer upstream.Close()

	conn.SetDeadline(time.Time{})

	logPassthrough(sni, clientIP, credID)

	// Replay buffered bytes + remaining connection data to upstream
	replayReader := &readerWriter{r: br, w: conn}
	bidirectionalCopy(replayReader, upstream)
}

// handleTransparentMITM generates a MITM certificate for the SNI hostname,
// completes a TLS handshake with the client, then proxies HTTP requests
// inside the tunnel to the upstream server.
func handleTransparentMITM(conn net.Conn, br *bufio.Reader, proxy *proxyHandler, certs *ca.Cache, sni, clientIP, credID string, trustTracker *caTrustTracker) {
	tlsCert, err := certs.GetCert(sni)
	if err != nil {
		logError("transparent-tls/cert", err, clientIP, credID)
		return
	}

	// Wrap the connection to replay peeked bytes
	replayConn := &replayConn{Conn: conn, reader: br}

	tlsConn := tls.Server(replayConn, &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
	})
	if err := tlsConn.Handshake(); err != nil {
		// Client doesn't trust our CA — this is expected for unconfigured clients
		logError("transparent-tls/client-tls", err, clientIP, credID)
		return
	}
	defer tlsConn.Close()

	// Successful handshake means client trusts our CA
	trustTracker.markTrusted(clientIP)

	conn.SetDeadline(time.Time{})

	// Proxy HTTP requests inside the TLS tunnel
	proxy.proxyTLSRequests(tlsConn, sni, "443", clientIP, credID, false)
}

// replayConn wraps a net.Conn with a bufio.Reader that may have buffered
// (peeked) data. Reads come from the buffered reader first, then from the
// underlying connection. Writes go directly to the connection.
type replayConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *replayConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

// singleConnListener is a net.Listener that serves exactly one connection.
// The first Accept returns a tracked wrapper; the second Accept blocks
// until that connection is closed, then returns an error so Serve exits
// cleanly after the request is fully handled.
type singleConnListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var first bool
	l.once.Do(func() {
		first = true
		l.done = make(chan struct{})
	})
	if first {
		return &notifyCloseConn{Conn: l.conn, done: l.done}, nil
	}
	<-l.done
	return nil, errors.New("listener closed")
}

func (l *singleConnListener) Close() error   { return nil }
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

// notifyCloseConn wraps a net.Conn and signals a channel when closed.
type notifyCloseConn struct {
	net.Conn
	done      chan struct{}
	closeOnce sync.Once
}

func (c *notifyCloseConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() { close(c.done) })
	return err
}

// startTransparentHTTP starts the HTTP server for transparent proxy mode.
// It intercepts plain HTTP traffic, serves captive portal for untrusted
// clients, and forwards requests upstream for trusted clients.
func startTransparentHTTP(listenAddr string, proxy *proxyHandler, trustTracker *caTrustTracker, portalHost string) {
	handler := &transparentHTTPHandler{
		proxy:        proxy,
		trustTracker: trustTracker,
		portalHost:   portalHost,
	}

	slog.Info("ublproxy transparent HTTP", "url", "http://"+listenAddr)

	if err := http.ListenAndServe(listenAddr, handler); err != nil {
		slog.Error("transparent HTTP error", "err", err)
		os.Exit(1)
	}
}

// startTransparentHTTPS starts the transparent HTTPS proxy. It accepts
// raw TCP connections and handles TLS interception based on SNI.
func startTransparentHTTPS(listenAddr string, proxy *proxyHandler, certs *ca.Cache, portalHost string, portalIPs []net.IP, trustTracker *caTrustTracker) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		slog.Error("transparent HTTPS listen error", "err", err)
		os.Exit(1)
	}

	slog.Info("ublproxy transparent HTTPS", "addr", listenAddr)

	serveTransparentTLS(ln, proxy, certs, portalHost, portalIPs, trustTracker)
}
