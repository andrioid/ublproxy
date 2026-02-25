package main

import (
	"io"
	"net/http"
	"time"
)

// Headers that must not be forwarded between hops.
// https://www.rfc-editor.org/rfc/rfc2616#section-13.5.1
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func (p *proxyHandler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if p.blocklist.IsBlocked(r.URL.Hostname()) {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	start := time.Now()

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
	if err != nil {
		logError("http/new-request", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	copyHeaders(outReq.Header, r.Header)
	removeHopByHopHeaders(outReq.Header)

	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		logError("http/roundtrip", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	removeHopByHopHeaders(w.Header())
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)

	logRequest(r.Method, r.URL.String(), resp.StatusCode, time.Since(start))
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func removeHopByHopHeaders(h http.Header) {
	for _, header := range hopByHopHeaders {
		h.Del(header)
	}
}
