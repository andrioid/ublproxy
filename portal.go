package main

import "net/http"

func (p *proxyHandler) handlePortal(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/ca.crt" {
		p.handlePortalCACert(w, r)
		return
	}
	if r.URL.Path == "/" {
		p.handlePortalIndex(w, r)
		return
	}
	http.NotFound(w, r)
}

func (p *proxyHandler) handlePortalIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(portalHTML))
}

func (p *proxyHandler) handlePortalCACert(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="ublproxy-ca.crt"`)
	w.WriteHeader(http.StatusOK)
	w.Write(p.caCertPEM)
}

const portalHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ublproxy</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    line-height: 1.6;
    color: #1a1a1a;
    background: #f5f5f5;
    padding: 2rem 1rem;
  }
  .container {
    max-width: 640px;
    margin: 0 auto;
    background: #fff;
    border-radius: 8px;
    padding: 2rem;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
  }
  h1 { font-size: 1.5rem; margin-bottom: 0.5rem; }
  p.subtitle { color: #666; margin-bottom: 1.5rem; }
  .download {
    display: inline-block;
    background: #2563eb;
    color: #fff;
    text-decoration: none;
    padding: 0.6rem 1.2rem;
    border-radius: 6px;
    font-weight: 500;
    margin-bottom: 1.5rem;
  }
  .download:hover { background: #1d4ed8; }
  h2 { font-size: 1.1rem; margin: 1.5rem 0 0.5rem; }
  ol { padding-left: 1.5rem; margin-bottom: 1rem; }
  li { margin-bottom: 0.3rem; }
  code {
    background: #f0f0f0;
    padding: 0.15rem 0.4rem;
    border-radius: 3px;
    font-size: 0.9em;
  }
  .section { border-top: 1px solid #eee; padding-top: 1rem; margin-top: 1rem; }
</style>
</head>
<body>
<div class="container">
  <h1>ublproxy</h1>
  <p class="subtitle">To intercept HTTPS traffic, your browser or OS must trust the ublproxy CA certificate.</p>

  <a class="download" href="/ca.crt">Download CA Certificate</a>

  <div class="section">
    <h2>Install on macOS</h2>
    <ol>
      <li>Download <a href="/ca.crt">ca.crt</a> and open it &mdash; Keychain Access will launch</li>
      <li>Add the certificate to the <strong>System</strong> keychain</li>
      <li>Find <strong>ublproxy CA</strong> in the list, double-click it</li>
      <li>Expand <strong>Trust</strong> and set <em>When using this certificate</em> to <strong>Always Trust</strong></li>
    </ol>
  </div>

  <div class="section">
    <h2>Install on Linux</h2>
    <ol>
      <li>Copy the certificate: <code>sudo cp ublproxy-ca.crt /usr/local/share/ca-certificates/</code></li>
      <li>Update the trust store: <code>sudo update-ca-certificates</code></li>
    </ol>
  </div>

  <div class="section">
    <h2>Install on Windows</h2>
    <ol>
      <li>Download <a href="/ca.crt">ca.crt</a> and double-click it</li>
      <li>Click <strong>Install Certificate</strong></li>
      <li>Select <strong>Local Machine</strong>, then <strong>Place all certificates in the following store</strong></li>
      <li>Choose <strong>Trusted Root Certification Authorities</strong> and finish the wizard</li>
    </ol>
  </div>

  <div class="section">
    <h2>Install in Firefox</h2>
    <ol>
      <li>Open <strong>Settings &rarr; Privacy &amp; Security &rarr; Certificates &rarr; View Certificates</strong></li>
      <li>Click <strong>Import</strong> and select the downloaded <a href="/ca.crt">ca.crt</a></li>
      <li>Check <strong>Trust this CA to identify websites</strong> and confirm</li>
    </ol>
  </div>
</div>
</body>
</html>`
