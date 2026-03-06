package main

import (
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// nullRouteTTL is the TTL for blocked DNS responses. Short so that if a
// rule is removed, clients pick up the change quickly.
const nullRouteTTL = 60

// dnsServer is a DNS resolver that null-routes hostnames blocked by the
// proxy's blocklists. Non-blocked queries are forwarded to an upstream
// resolver. Intended for devices that cannot install the proxy's CA
// certificate (smart TVs, game consoles, IoT devices).
type dnsServer struct {
	proxy    *proxyHandler
	upstream string       // upstream resolver address (e.g. "1.1.1.1:53")
	activity *ActivityLog // optional activity log
}

// ServeDNS implements dns.Handler. It checks whether the queried hostname
// is blocked and either returns a null-route response or forwards the
// query upstream.
func (s *dnsServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeFormatError)
		_ = w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	hostname := strings.TrimSuffix(q.Name, ".")
	clientIP := extractDNSClientIP(w)

	blocked := s.proxy.shouldBlockHost(clientIP, hostname)

	if blocked {
		s.respondBlocked(w, r, q)
		s.logActivity(ActivityDNSBlocked, hostname, clientIP)
		slog.Debug("dns blocked", "host", hostname, "client", clientIP)
		return
	}

	s.forwardUpstream(w, r)
	slog.Debug("dns forwarded", "host", hostname, "client", clientIP)
}

// respondBlocked writes a null-route DNS response. A queries get 0.0.0.0,
// AAAA queries get ::, and all other query types for blocked hosts get an
// empty authoritative answer (preventing the host from being reachable
// via MX, SRV, etc.).
func (s *dnsServer) respondBlocked(w dns.ResponseWriter, r *dns.Msg, q dns.Question) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	switch q.Qtype {
	case dns.TypeA:
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    nullRouteTTL,
			},
			A: net.IPv4zero,
		})
	case dns.TypeAAAA:
		m.Answer = append(m.Answer, &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    nullRouteTTL,
			},
			AAAA: net.IPv6zero,
		})
	default:
		// Empty authoritative answer for other record types on blocked hosts
	}

	_ = w.WriteMsg(m)
}

// forwardUpstream sends the query to the upstream resolver and relays
// the response back to the client.
func (s *dnsServer) forwardUpstream(w dns.ResponseWriter, r *dns.Msg) {
	c := new(dns.Client)
	c.Timeout = 5 * time.Second

	resp, _, err := c.Exchange(r, s.upstream)
	if err != nil {
		slog.Warn("dns upstream error", "upstream", s.upstream, "err", err)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	_ = w.WriteMsg(resp)
}

// logActivity records a DNS event in the activity log if available.
func (s *dnsServer) logActivity(activityType, hostname, clientIP string) {
	if s.activity == nil {
		return
	}
	credID := s.proxy.credentialForIP(clientIP)
	s.activity.Add(ActivityEntry{
		Type: activityType,
		Host: hostname,
		IP:   clientIP,
		User: shortUserID(credID),
	})
}

// extractDNSClientIP extracts the client IP address from the DNS writer's
// remote address.
func extractDNSClientIP(w dns.ResponseWriter) string {
	addr := w.RemoteAddr()
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// startDNS starts UDP and TCP DNS servers on the given address. Both
// goroutines block; call this from a goroutine.
func startDNS(addr string, handler dns.Handler) {
	go func() {
		srv := &dns.Server{Addr: addr, Net: "udp", Handler: handler}
		slog.Info("dns resolver (udp)", "addr", addr)
		if err := srv.ListenAndServe(); err != nil {
			slog.Error("dns udp server error", "err", err)
		}
	}()

	srv := &dns.Server{Addr: addr, Net: "tcp", Handler: handler}
	slog.Info("dns resolver (tcp)", "addr", addr)
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("dns tcp server error", "err", err)
	}
}
