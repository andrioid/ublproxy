package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
)

// mobileconfigTmpl generates an Apple Configuration Profile (.mobileconfig)
// that bundles the CA certificate and proxy PAC URL into a single install.
// This reduces the iOS/macOS onboarding from ~6 manual steps to 1.
var mobileconfigTmpl = template.Must(template.New("mobileconfig").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadIdentifier</key>
			<string>com.ublproxy.ca</string>
			<key>PayloadUUID</key>
			<string>{{.CertUUID}}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
			<key>PayloadDisplayName</key>
			<string>ublproxy CA</string>
			<key>PayloadDescription</key>
			<string>Installs the ublproxy CA certificate for HTTPS interception.</string>
			<key>PayloadContent</key>
			<data>{{.CACertDER}}</data>
		</dict>
		<dict>
			<key>PayloadType</key>
			<string>com.apple.proxy.http.global</string>
			<key>PayloadIdentifier</key>
			<string>com.ublproxy.proxy</string>
			<key>PayloadUUID</key>
			<string>{{.ProxyUUID}}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
			<key>PayloadDisplayName</key>
			<string>ublproxy Proxy</string>
			<key>PayloadDescription</key>
			<string>Configures automatic proxy using ublproxy PAC file.</string>
			<key>ProxyType</key>
			<string>Auto</string>
			<key>ProxyPACURL</key>
			<string>{{.PACURL}}</string>
		</dict>
	</array>
	<key>PayloadDisplayName</key>
	<string>ublproxy</string>
	<key>PayloadDescription</key>
	<string>Installs the ublproxy CA certificate and configures proxy settings for ad blocking.</string>
	<key>PayloadIdentifier</key>
	<string>com.ublproxy.profile</string>
	<key>PayloadUUID</key>
	<string>{{.ProfileUUID}}</string>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
	<key>PayloadOrganization</key>
	<string>ublproxy</string>
</dict>
</plist>
`))

type mobileconfigData struct {
	CACertDER   string // base64-encoded DER certificate
	PACURL      string
	ProfileUUID string
	CertUUID    string
	ProxyUUID   string
}

// deterministicUUID generates a UUID v5-style deterministic ID from the CA
// cert fingerprint and a namespace string. This keeps profile identity stable
// across re-downloads so iOS/macOS treats them as updates rather than duplicates.
func deterministicUUID(caCert *x509.Certificate, namespace string) string {
	h := sha256.New()
	h.Write(caCert.Raw)
	h.Write([]byte(namespace))
	sum := h.Sum(nil)
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}

func serveMobileconfig(w http.ResponseWriter, caCert *x509.Certificate, pacURL string) {
	data := mobileconfigData{
		CACertDER:   base64.StdEncoding.EncodeToString(caCert.Raw),
		PACURL:      pacURL,
		ProfileUUID: deterministicUUID(caCert, "profile"),
		CertUUID:    deterministicUUID(caCert, "cert"),
		ProxyUUID:   deterministicUUID(caCert, "proxy"),
	}

	w.Header().Set("Content-Type", "application/x-apple-asix-config")
	w.Header().Set("Content-Disposition", `attachment; filename="ublproxy.mobileconfig"`)
	w.WriteHeader(http.StatusOK)
	mobileconfigTmpl.Execute(w, data)
}
