package main

import (
	_ "embed"
	"strings"
)

//go:embed static/bootstrap.js
var bootstrapJS string

//go:embed static/picker.js
var pickerJS string

// bootstrapScriptTag generates the inline <script> tag with the portal URL,
// session token, and page host embedded. Returns empty string if there is no
// session for this client (user hasn't authenticated on the portal).
func (p *proxyHandler) bootstrapScriptTag(clientIP, host string) string {
	if p.sessions == nil || p.portalOrigin == "" {
		return ""
	}

	token := p.sessions.Get(clientIP)
	if token == "" {
		return ""
	}

	script := bootstrapJS
	script = strings.ReplaceAll(script, "__UBLPROXY_PORTAL__", p.portalOrigin)
	script = strings.ReplaceAll(script, "__UBLPROXY_TOKEN__", token)
	script = strings.ReplaceAll(script, "__UBLPROXY_HOST__", host)

	return "<script>" + script + "</script>"
}
