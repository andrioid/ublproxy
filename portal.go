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
	// Route API requests to the API handler (works on localhost where
	// HTTPS isn't required for the rule management endpoints)
	if p.api != nil && len(r.URL.Path) >= 4 && r.URL.Path[:4] == "/api" {
		p.api.ServeHTTP(w, r)
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
  h2 { font-size: 1.1rem; margin: 1.5rem 0 0.5rem; }
  ol { padding-left: 1.5rem; margin-bottom: 1rem; }
  li { margin-bottom: 0.3rem; }
  code {
    background: #f0f0f0;
    padding: 0.15rem 0.4rem;
    border-radius: 3px;
    font-size: 0.9em;
  }
  kbd {
    background: #f0f0f0;
    border: 1px solid #ccc;
    border-radius: 3px;
    padding: 0.1rem 0.4rem;
    font-size: 0.85em;
    font-family: inherit;
  }
  .section { border-top: 1px solid #eee; padding-top: 1rem; margin-top: 1rem; }
  .auth-card {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
  }
  .auth-card h2 { margin-top: 0; }
  .btn {
    display: inline-block;
    padding: 0.6rem 1.2rem;
    border-radius: 6px;
    font-weight: 500;
    font-size: 0.95rem;
    border: none;
    cursor: pointer;
    text-decoration: none;
    line-height: 1.4;
  }
  .btn:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn-primary { background: #2563eb; color: #fff; }
  .btn-primary:hover:not(:disabled) { background: #1d4ed8; }
  .btn-secondary { background: #e2e8f0; color: #1a1a1a; margin-left: 0.5rem; }
  .btn-secondary:hover:not(:disabled) { background: #cbd5e1; }
  .btn-danger { background: #ef4444; color: #fff; }
  .btn-danger:hover:not(:disabled) { background: #dc2626; }
  .auth-buttons { margin-top: 1rem; }
  .auth-msg {
    margin-top: 0.75rem;
    padding: 0.5rem 0.75rem;
    border-radius: 4px;
    font-size: 0.9rem;
    display: none;
  }
  .auth-msg.success { display: block; background: #f0fdf4; color: #166534; border: 1px solid #bbf7d0; }
  .auth-msg.error { display: block; background: #fef2f2; color: #991b1b; border: 1px solid #fecaca; }
  .auth-msg.info { display: block; background: #eff6ff; color: #1e40af; border: 1px solid #bfdbfe; }
  .auth-status { font-size: 0.9rem; color: #666; }
  .auth-status .ok { color: #166534; font-weight: 500; }
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
</style>
</head>
<body>
<div class="container">
  <h1>ublproxy</h1>
  <p class="subtitle">Ad-blocking proxy with interactive element picker.</p>

  <div class="auth-card" id="auth-card">
    <h2>Authentication</h2>
    <div class="auth-status" id="auth-status">Checking session&#8230;</div>
    <div class="auth-buttons" id="auth-buttons" style="display:none">
      <button class="btn btn-primary" id="btn-register">Register Passkey</button>
      <button class="btn btn-secondary" id="btn-login">Login</button>
    </div>
    <div id="auth-logout" style="display:none">
      <button class="btn btn-danger" id="btn-logout">Logout</button>
    </div>
    <div class="auth-msg" id="auth-msg"></div>
  </div>

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
<script>
(function() {
  'use strict';

  var TOKEN_KEY = 'ublproxy_token';
  var statusEl = document.getElementById('auth-status');
  var buttonsEl = document.getElementById('auth-buttons');
  var logoutEl = document.getElementById('auth-logout');
  var msgEl = document.getElementById('auth-msg');
  var btnRegister = document.getElementById('btn-register');
  var btnLogin = document.getElementById('btn-login');
  var btnLogout = document.getElementById('btn-logout');

  function b64urlToBytes(b64url) {
    var b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    var pad = b64.length % 4;
    if (pad) b64 += '===='.slice(pad);
    var binary = atob(b64);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  function bytesToB64url(buffer) {
    var bytes = new Uint8Array(buffer);
    var binary = '';
    for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function showMsg(text, type) {
    msgEl.textContent = text;
    msgEl.className = 'auth-msg ' + type;
  }

  function clearMsg() {
    msgEl.textContent = '';
    msgEl.className = 'auth-msg';
  }

  function showAuthenticated() {
    statusEl.innerHTML = '<span class="ok">Authenticated.</span> Press <kbd>Alt+Shift+B</kbd> on any proxied page to open the element picker.';
    buttonsEl.style.display = 'none';
    logoutEl.style.display = 'block';
  }

  function showUnauthenticated() {
    statusEl.textContent = 'Not authenticated. Register a passkey or login to enable the element picker.';
    buttonsEl.style.display = 'block';
    logoutEl.style.display = 'none';
  }

  function getToken() { return localStorage.getItem(TOKEN_KEY); }
  function setToken(t) { localStorage.setItem(TOKEN_KEY, t); }
  function clearToken() { localStorage.removeItem(TOKEN_KEY); }

  function setButtonsDisabled(v) {
    btnRegister.disabled = v;
    btnLogin.disabled = v;
    btnLogout.disabled = v;
  }

  async function checkSession() {
    var token = getToken();
    if (!token) { showUnauthenticated(); return; }
    try {
      var resp = await fetch('/api/rules', {
        headers: { 'Authorization': 'Bearer ' + token }
      });
      if (resp.ok) { showAuthenticated(); return; }
    } catch (_) {}
    clearToken();
    showUnauthenticated();
  }

  async function register() {
    clearMsg();
    if (!window.PublicKeyCredential) {
      showMsg('WebAuthn is not supported in this browser. Use a modern browser over HTTPS.', 'error');
      return;
    }
    setButtonsDisabled(true);
    showMsg('Starting registration\u2026', 'info');
    try {
      var beginResp = await fetch('/api/auth/register/begin', { method: 'POST' });
      if (!beginResp.ok) {
        var e1 = await beginResp.json();
        throw new Error(e1.error || 'Failed to start registration');
      }
      var opts = await beginResp.json();

      var publicKey = {
        challenge: b64urlToBytes(opts.challenge),
        rp: opts.rp,
        user: {
          id: b64urlToBytes(opts.user.id),
          name: opts.user.name,
          displayName: opts.user.displayName
        },
        pubKeyCredParams: opts.pubKeyCredParams,
        attestation: opts.attestation,
        authenticatorSelection: opts.authenticatorSelection
      };

      showMsg('Waiting for passkey\u2026', 'info');
      var credential = await navigator.credentials.create({ publicKey: publicKey });

      var finishBody = {
        attestationObject: bytesToB64url(credential.response.attestationObject),
        clientDataJSON: bytesToB64url(credential.response.clientDataJSON)
      };

      var finishResp = await fetch('/api/auth/register/finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(finishBody)
      });
      if (!finishResp.ok) {
        var e2 = await finishResp.json();
        throw new Error(e2.error || 'Registration failed');
      }
      var result = await finishResp.json();
      setToken(result.token);
      showMsg('Passkey registered successfully!', 'success');
      showAuthenticated();
    } catch (err) {
      if (err.name === 'NotAllowedError') {
        showMsg('Registration was cancelled.', 'error');
      } else {
        showMsg('Registration failed: ' + err.message, 'error');
      }
    } finally {
      setButtonsDisabled(false);
    }
  }

  async function login() {
    clearMsg();
    if (!window.PublicKeyCredential) {
      showMsg('WebAuthn is not supported in this browser. Use a modern browser over HTTPS.', 'error');
      return;
    }
    setButtonsDisabled(true);
    showMsg('Starting login\u2026', 'info');
    try {
      var beginResp = await fetch('/api/auth/login/begin', { method: 'POST' });
      if (!beginResp.ok) {
        var e1 = await beginResp.json();
        throw new Error(e1.error || 'Failed to start login');
      }
      var opts = await beginResp.json();

      var publicKey = {
        challenge: b64urlToBytes(opts.challenge),
        rpId: opts.rpId,
        userVerification: opts.userVerification
      };
      if (opts.allowCredentials && opts.allowCredentials.length > 0) {
        publicKey.allowCredentials = opts.allowCredentials.map(function(c) {
          return { type: c.type, id: b64urlToBytes(c.id) };
        });
      }

      showMsg('Waiting for passkey\u2026', 'info');
      var assertion = await navigator.credentials.get({ publicKey: publicKey });

      var finishBody = {
        credentialId: bytesToB64url(assertion.rawId),
        authenticatorData: bytesToB64url(assertion.response.authenticatorData),
        clientDataJSON: bytesToB64url(assertion.response.clientDataJSON),
        signature: bytesToB64url(assertion.response.signature)
      };

      var finishResp = await fetch('/api/auth/login/finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(finishBody)
      });
      if (!finishResp.ok) {
        var e2 = await finishResp.json();
        throw new Error(e2.error || 'Login failed');
      }
      var result = await finishResp.json();
      setToken(result.token);
      showMsg('Login successful!', 'success');
      showAuthenticated();
    } catch (err) {
      if (err.name === 'NotAllowedError') {
        showMsg('Login was cancelled.', 'error');
      } else {
        showMsg('Login failed: ' + err.message, 'error');
      }
    } finally {
      setButtonsDisabled(false);
    }
  }

  async function logout() {
    clearMsg();
    setButtonsDisabled(true);
    try {
      var token = getToken();
      if (token) {
        await fetch('/api/auth/logout', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer ' + token }
        });
      }
    } catch (_) {}
    clearToken();
    showMsg('Logged out.', 'info');
    showUnauthenticated();
    setButtonsDisabled(false);
  }

  btnRegister.addEventListener('click', register);
  btnLogin.addEventListener('click', login);
  btnLogout.addEventListener('click', logout);

  checkSession();
})();
</script>
</body>
</html>`
