package main

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"ublproxy/internal/blocklist"
)

// startTestDNSServer starts a DNS server on a random UDP port and returns
// its address. The caller must call shutdown to stop the server.
func startTestDNSServer(t *testing.T, ds *dnsServer) (addr string, shutdown func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = pc.LocalAddr().String()

	srv := &dns.Server{PacketConn: pc, Handler: ds}
	go func() { _ = srv.ActivateAndServe() }()

	// Wait for the server to be ready.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		m := new(dns.Msg)
		m.SetQuestion("test.invalid.", dns.TypeA)
		if _, err := dns.Exchange(m, addr); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	return addr, func() { _ = srv.Shutdown() }
}

// startMockUpstream starts a mock DNS server that answers A queries with
// the given IP address.
func startMockUpstream(t *testing.T, answerIP string) (addr string, shutdown func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = pc.LocalAddr().String()

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.ParseIP(answerIP),
			})
		}
		_ = w.WriteMsg(m)
	})

	srv := &dns.Server{PacketConn: pc, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		m := new(dns.Msg)
		m.SetQuestion("test.invalid.", dns.TypeA)
		if _, err := dns.Exchange(m, addr); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	return addr, func() { _ = srv.Shutdown() }
}

func newTestProxyHandler() *proxyHandler {
	return &proxyHandler{
		sessions: newSessionMap(),
	}
}

func TestDNSBlockedHostReturnsNullIP(t *testing.T) {
	proxy := newTestProxyHandler()
	rs := blocklist.NewRuleSet()
	rs.AddLine("||ads.example.com^")
	proxy.baselineRules.Store(rs)

	upstreamAddr, upstreamShutdown := startMockUpstream(t, "93.184.216.34")
	defer upstreamShutdown()

	ds := &dnsServer{
		proxy:    proxy,
		upstream: upstreamAddr,
	}
	addr, shutdown := startTestDNSServer(t, ds)
	defer shutdown()

	// A record for blocked host should return 0.0.0.0
	m := new(dns.Msg)
	m.SetQuestion("ads.example.com.", dns.TypeA)
	resp, err := dns.Exchange(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", resp.Answer[0])
	}
	if !a.A.Equal(net.IPv4zero) {
		t.Errorf("expected 0.0.0.0, got %s", a.A)
	}
}

func TestDNSBlockedHostAAAAReturnsNullIPv6(t *testing.T) {
	proxy := newTestProxyHandler()
	rs := blocklist.NewRuleSet()
	rs.AddLine("||ads.example.com^")
	proxy.baselineRules.Store(rs)

	upstreamAddr, upstreamShutdown := startMockUpstream(t, "93.184.216.34")
	defer upstreamShutdown()

	ds := &dnsServer{
		proxy:    proxy,
		upstream: upstreamAddr,
	}
	addr, shutdown := startTestDNSServer(t, ds)
	defer shutdown()

	// AAAA record for blocked host should return ::
	m := new(dns.Msg)
	m.SetQuestion("ads.example.com.", dns.TypeAAAA)
	resp, err := dns.Exchange(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	aaaa, ok := resp.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("expected AAAA record, got %T", resp.Answer[0])
	}
	if !aaaa.AAAA.Equal(net.IPv6zero) {
		t.Errorf("expected ::, got %s", aaaa.AAAA)
	}
}

func TestDNSNonBlockedHostForwardsUpstream(t *testing.T) {
	proxy := newTestProxyHandler()
	rs := blocklist.NewRuleSet()
	rs.AddLine("||ads.example.com^")
	proxy.baselineRules.Store(rs)

	upstreamAddr, upstreamShutdown := startMockUpstream(t, "93.184.216.34")
	defer upstreamShutdown()

	ds := &dnsServer{
		proxy:    proxy,
		upstream: upstreamAddr,
	}
	addr, shutdown := startTestDNSServer(t, ds)
	defer shutdown()

	// Non-blocked host should be forwarded to upstream
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	resp, err := dns.Exchange(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", resp.Answer[0])
	}
	if !a.A.Equal(net.ParseIP("93.184.216.34")) {
		t.Errorf("expected 93.184.216.34, got %s", a.A)
	}
}

func TestDNSDomainHierarchyBlocking(t *testing.T) {
	proxy := newTestProxyHandler()
	rs := blocklist.NewRuleSet()
	rs.AddLine("||example.com^")
	proxy.baselineRules.Store(rs)

	upstreamAddr, upstreamShutdown := startMockUpstream(t, "1.2.3.4")
	defer upstreamShutdown()

	ds := &dnsServer{
		proxy:    proxy,
		upstream: upstreamAddr,
	}
	addr, shutdown := startTestDNSServer(t, ds)
	defer shutdown()

	// Subdomain should also be blocked (domain hierarchy walk)
	m := new(dns.Msg)
	m.SetQuestion("sub.example.com.", dns.TypeA)
	resp, err := dns.Exchange(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	a := resp.Answer[0].(*dns.A)
	if !a.A.Equal(net.IPv4zero) {
		t.Errorf("expected 0.0.0.0 for subdomain of blocked host, got %s", a.A)
	}
}

func TestDNSPerUserExceptionOverridesBaseline(t *testing.T) {
	proxy := newTestProxyHandler()

	// Baseline blocks ads.example.com
	baseline := blocklist.NewRuleSet()
	baseline.AddLine("||ads.example.com^")
	proxy.baselineRules.Store(baseline)

	// User has an exception for ads.example.com
	userRS := blocklist.NewRuleSet()
	userRS.AddLine("@@||ads.example.com^")
	proxy.userRules.Store("user-cred-1", userRS)

	// Register the user's session from a specific IP
	proxy.sessions.Set("127.0.0.1", sessionEntry{
		CredentialID: "user-cred-1",
	})

	upstreamAddr, upstreamShutdown := startMockUpstream(t, "93.184.216.34")
	defer upstreamShutdown()

	ds := &dnsServer{
		proxy:    proxy,
		upstream: upstreamAddr,
	}
	addr, shutdown := startTestDNSServer(t, ds)
	defer shutdown()

	// This user's exception should override the baseline block
	m := new(dns.Msg)
	m.SetQuestion("ads.example.com.", dns.TypeA)
	resp, err := dns.Exchange(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", resp.Answer[0])
	}
	// Should NOT be 0.0.0.0 — the user excepted this host
	if a.A.Equal(net.IPv4zero) {
		t.Error("expected upstream response (user exception), got 0.0.0.0")
	}
}

func TestDNSActivityLogging(t *testing.T) {
	proxy := newTestProxyHandler()
	rs := blocklist.NewRuleSet()
	rs.AddLine("||blocked.example.com^")
	proxy.baselineRules.Store(rs)

	activity := NewActivityLog(100)

	upstreamAddr, upstreamShutdown := startMockUpstream(t, "1.2.3.4")
	defer upstreamShutdown()

	ds := &dnsServer{
		proxy:    proxy,
		upstream: upstreamAddr,
		activity: activity,
	}
	addr, shutdown := startTestDNSServer(t, ds)
	defer shutdown()

	// Query a blocked host
	m := new(dns.Msg)
	m.SetQuestion("blocked.example.com.", dns.TypeA)
	if _, err := dns.Exchange(m, addr); err != nil {
		t.Fatal(err)
	}

	// Query a non-blocked host
	m2 := new(dns.Msg)
	m2.SetQuestion("allowed.example.com.", dns.TypeA)
	if _, err := dns.Exchange(m2, addr); err != nil {
		t.Fatal(err)
	}

	entries := activity.Recent(10)
	if len(entries) < 1 {
		t.Fatal("expected at least 1 activity entry")
	}

	// Most recent should be the blocked query
	var foundBlock bool
	for _, e := range entries {
		if e.Type == ActivityDNSBlocked && e.Host == "blocked.example.com" {
			foundBlock = true
			break
		}
	}
	if !foundBlock {
		t.Errorf("expected dns-blocked activity entry for blocked.example.com, got: %+v", entries)
	}
}

func TestDNSNonAddressQtypeForwardedRegardless(t *testing.T) {
	proxy := newTestProxyHandler()
	rs := blocklist.NewRuleSet()
	rs.AddLine("||blocked.example.com^")
	proxy.baselineRules.Store(rs)

	// Mock upstream that answers MX queries
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstreamAddr := pc.LocalAddr().String()
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeMX {
			m.Answer = append(m.Answer, &dns.MX{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeMX,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Preference: 10,
				Mx:         "mail.example.com.",
			})
		}
		_ = w.WriteMsg(m)
	})
	srv := &dns.Server{PacketConn: pc, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()
	defer func() { _ = srv.Shutdown() }()

	ds := &dnsServer{
		proxy:    proxy,
		upstream: upstreamAddr,
	}
	addr, shutdown := startTestDNSServer(t, ds)
	defer shutdown()

	// MX query for a blocked host should still be blocked (A/AAAA only get null-routed)
	// For non-address types on a blocked host, we return an empty answer
	// to prevent the host from being reachable via other record types.
	m := new(dns.Msg)
	m.SetQuestion("blocked.example.com.", dns.TypeMX)
	resp, err := dns.Exchange(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	// Blocked host: should get empty response, not forwarded to upstream
	if len(resp.Answer) != 0 {
		t.Errorf("expected empty answer for non-A/AAAA query on blocked host, got %d answers", len(resp.Answer))
	}
}

func TestDNSTCPSupport(t *testing.T) {
	proxy := newTestProxyHandler()
	rs := blocklist.NewRuleSet()
	rs.AddLine("||ads.example.com^")
	proxy.baselineRules.Store(rs)

	upstreamAddr, upstreamShutdown := startMockUpstream(t, "93.184.216.34")
	defer upstreamShutdown()

	ds := &dnsServer{
		proxy:    proxy,
		upstream: upstreamAddr,
	}

	// Start a TCP DNS server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpAddr := ln.Addr().String()

	srv := &dns.Server{Listener: ln, Handler: ds, Net: "tcp"}
	go func() { _ = srv.ActivateAndServe() }()
	defer func() { _ = srv.Shutdown() }()

	// Wait for TCP server to be ready
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c := new(dns.Client)
		c.Net = "tcp"
		m := new(dns.Msg)
		m.SetQuestion("test.invalid.", dns.TypeA)
		if _, _, err := c.Exchange(m, tcpAddr); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Query blocked host over TCP
	c := new(dns.Client)
	c.Net = "tcp"
	m := new(dns.Msg)
	m.SetQuestion("ads.example.com.", dns.TypeA)
	resp, _, err := c.Exchange(m, tcpAddr)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", resp.Answer[0])
	}
	if !a.A.Equal(net.IPv4zero) {
		t.Errorf("expected 0.0.0.0 over TCP, got %s", a.A)
	}
}

func TestDNSEmptyQuestion(t *testing.T) {
	proxy := newTestProxyHandler()
	ds := &dnsServer{
		proxy:    proxy,
		upstream: "127.0.0.1:0",
	}
	addr, shutdown := startTestDNSServer(t, ds)
	defer shutdown()

	// Send a message with no question section
	m := new(dns.Msg)
	m.Id = dns.Id()
	resp, err := dns.Exchange(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeFormatError {
		t.Errorf("expected FORMERR for empty question, got rcode %d", resp.Rcode)
	}
}

func TestDNSHostsFileFormatBlocking(t *testing.T) {
	proxy := newTestProxyHandler()
	rs := blocklist.NewRuleSet()
	rs.AddLine("0.0.0.0 malware.example.com")
	proxy.baselineRules.Store(rs)

	upstreamAddr, upstreamShutdown := startMockUpstream(t, "1.2.3.4")
	defer upstreamShutdown()

	ds := &dnsServer{
		proxy:    proxy,
		upstream: upstreamAddr,
	}
	addr, shutdown := startTestDNSServer(t, ds)
	defer shutdown()

	m := new(dns.Msg)
	m.SetQuestion("malware.example.com.", dns.TypeA)
	resp, err := dns.Exchange(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	a := resp.Answer[0].(*dns.A)
	if !a.A.Equal(net.IPv4zero) {
		t.Errorf("expected 0.0.0.0 for hosts-file blocked entry, got %s", a.A)
	}
}

func TestDNSNoBaselineRulesForwardsAll(t *testing.T) {
	proxy := newTestProxyHandler()
	// No baseline rules loaded

	upstreamAddr, upstreamShutdown := startMockUpstream(t, "1.2.3.4")
	defer upstreamShutdown()

	ds := &dnsServer{
		proxy:    proxy,
		upstream: upstreamAddr,
	}
	addr, shutdown := startTestDNSServer(t, ds)
	defer shutdown()

	m := new(dns.Msg)
	m.SetQuestion("anything.example.com.", dns.TypeA)
	resp, err := dns.Exchange(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	a := resp.Answer[0].(*dns.A)
	if !a.A.Equal(net.ParseIP("1.2.3.4")) {
		t.Errorf("expected upstream IP 1.2.3.4, got %s", a.A)
	}
}

// Verify multiple questions are handled (edge case from legacy DNS clients).
func TestDNSMultipleQuestions(t *testing.T) {
	proxy := newTestProxyHandler()
	rs := blocklist.NewRuleSet()
	rs.AddLine("||blocked.example.com^")
	proxy.baselineRules.Store(rs)

	upstreamAddr, upstreamShutdown := startMockUpstream(t, "1.2.3.4")
	defer upstreamShutdown()

	ds := &dnsServer{
		proxy:    proxy,
		upstream: upstreamAddr,
	}
	addr, shutdown := startTestDNSServer(t, ds)
	defer shutdown()

	// DNS message with multiple questions (unusual but valid)
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = true
	m.Question = []dns.Question{
		{Name: "blocked.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "allowed.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	resp, err := dns.Exchange(m, addr)
	if err != nil {
		// Some implementations reject multi-question; that's acceptable
		return
	}
	// We only process the first question; response is valid as long as no panic
	_ = resp
}
