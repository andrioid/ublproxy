/* ublproxy shared JavaScript */
(function() {
  'use strict';

  var TOKEN_KEY = 'ublproxy_token';

  // --- Token management ---
  function getToken() { return localStorage.getItem(TOKEN_KEY); }
  function setToken(t) { localStorage.setItem(TOKEN_KEY, t); }
  function clearToken() { localStorage.removeItem(TOKEN_KEY); }

  function authHeaders() {
    return { 'Authorization': 'Bearer ' + getToken(), 'Content-Type': 'application/json' };
  }

  // --- Base64url helpers (for WebAuthn) ---
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

  // --- DOM helpers ---
  function show(el) { el.classList.remove('hidden'); }
  function hide(el) { el.classList.add('hidden'); }

  function showMsg(el, text, type) {
    el.textContent = text;
    el.className = 'msg ' + type;
  }

  function clearMsg(el) {
    el.textContent = '';
    el.className = 'msg';
  }

  // --- Navigation ---
  function initNav() {
    var currentPath = location.pathname;
    var links = document.querySelectorAll('.nav-link');
    links.forEach(function(link) {
      if (link.getAttribute('href') === currentPath) {
        link.classList.add('active');
      }
    });
  }

  // --- Auth state ---
  // Each page calls ublproxy.checkSession(onAuth, onUnauth)
  // onAuth() is called when user is authenticated
  // onUnauth() is called when user is not authenticated
  async function checkSession(onAuth, onUnauth) {
    var token = getToken();
    var navStatus = document.getElementById('nav-status');
    var navLogout = document.getElementById('nav-logout');
    var navLinks = document.querySelectorAll('.nav-link[data-auth]');

    if (!token) {
      if (navStatus) navStatus.textContent = 'Not signed in';
      if (navLogout) hide(navLogout);
      navLinks.forEach(function(l) { hide(l); });
      if (onUnauth) onUnauth();
      return;
    }

    try {
      var resp = await fetch('/api/rules', { headers: { 'Authorization': 'Bearer ' + token } });
      if (resp.ok) {
        if (navStatus) navStatus.innerHTML = '<span class="ok">Signed in</span>';
        if (navLogout) show(navLogout);
        navLinks.forEach(function(l) { show(l); });
        if (onAuth) onAuth();
        return;
      }
    } catch (_) {}

    clearToken();
    if (navStatus) navStatus.textContent = 'Not signed in';
    if (navLogout) hide(navLogout);
    navLinks.forEach(function(l) { hide(l); });
    if (onUnauth) onUnauth();
  }

  // --- WebAuthn Register ---
  async function register(msgEl, onSuccess) {
    clearMsg(msgEl);
    if (!window.PublicKeyCredential) {
      showMsg(msgEl, 'WebAuthn is not supported in this browser. Use a modern browser over HTTPS.', 'error');
      return;
    }
    showMsg(msgEl, 'Starting registration\u2026', 'info');
    try {
      var beginResp = await fetch('/api/auth/register/begin', { method: 'POST' });
      if (!beginResp.ok) { var e = await beginResp.json(); throw new Error(e.error || 'Failed to start registration'); }
      var opts = await beginResp.json();
      var publicKey = {
        challenge: b64urlToBytes(opts.challenge),
        rp: opts.rp,
        user: { id: b64urlToBytes(opts.user.id), name: opts.user.name, displayName: opts.user.displayName },
        pubKeyCredParams: opts.pubKeyCredParams,
        attestation: opts.attestation,
        authenticatorSelection: opts.authenticatorSelection
      };
      showMsg(msgEl, 'Waiting for passkey\u2026', 'info');
      var credential = await navigator.credentials.create({ publicKey: publicKey });
      var finishBody = {
        attestationObject: bytesToB64url(credential.response.attestationObject),
        clientDataJSON: bytesToB64url(credential.response.clientDataJSON)
      };
      var finishResp = await fetch('/api/auth/register/finish', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(finishBody)
      });
      if (!finishResp.ok) { var e2 = await finishResp.json(); throw new Error(e2.error || 'Registration failed'); }
      var result = await finishResp.json();
      setToken(result.token);
      showMsg(msgEl, 'Passkey registered successfully!', 'success');
      if (onSuccess) onSuccess();
    } catch (err) {
      showMsg(msgEl, err.name === 'NotAllowedError' ? 'Registration was cancelled.' : 'Registration failed: ' + err.message, 'error');
    }
  }

  // --- WebAuthn Login ---
  async function login(msgEl, onSuccess) {
    clearMsg(msgEl);
    if (!window.PublicKeyCredential) {
      showMsg(msgEl, 'WebAuthn is not supported in this browser. Use a modern browser over HTTPS.', 'error');
      return;
    }
    showMsg(msgEl, 'Starting login\u2026', 'info');
    try {
      var beginResp = await fetch('/api/auth/login/begin', { method: 'POST' });
      if (!beginResp.ok) { var e = await beginResp.json(); throw new Error(e.error || 'Failed to start login'); }
      var opts = await beginResp.json();
      var publicKey = { challenge: b64urlToBytes(opts.challenge), rpId: opts.rpId, userVerification: opts.userVerification };
      if (opts.allowCredentials && opts.allowCredentials.length > 0) {
        publicKey.allowCredentials = opts.allowCredentials.map(function(c) { return { type: c.type, id: b64urlToBytes(c.id) }; });
      }
      showMsg(msgEl, 'Waiting for passkey\u2026', 'info');
      var assertion = await navigator.credentials.get({ publicKey: publicKey });
      var finishBody = {
        credentialId: bytesToB64url(assertion.rawId),
        authenticatorData: bytesToB64url(assertion.response.authenticatorData),
        clientDataJSON: bytesToB64url(assertion.response.clientDataJSON),
        signature: bytesToB64url(assertion.response.signature)
      };
      var finishResp = await fetch('/api/auth/login/finish', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(finishBody)
      });
      if (!finishResp.ok) { var e2 = await finishResp.json(); throw new Error(e2.error || 'Login failed'); }
      var result = await finishResp.json();
      setToken(result.token);
      showMsg(msgEl, 'Login successful!', 'success');
      if (onSuccess) onSuccess();
    } catch (err) {
      showMsg(msgEl, err.name === 'NotAllowedError' ? 'Login was cancelled.' : 'Login failed: ' + err.message, 'error');
    }
  }

  // --- Logout ---
  async function logout() {
    try {
      var token = getToken();
      if (token) { await fetch('/api/auth/logout', { method: 'POST', headers: { 'Authorization': 'Bearer ' + token } }); }
    } catch (_) {}
    clearToken();
    location.href = '/';
  }

  // --- Expose API ---
  window.ublproxy = {
    getToken: getToken,
    setToken: setToken,
    clearToken: clearToken,
    authHeaders: authHeaders,
    b64urlToBytes: b64urlToBytes,
    bytesToB64url: bytesToB64url,
    show: show,
    hide: hide,
    showMsg: showMsg,
    clearMsg: clearMsg,
    checkSession: checkSession,
    register: register,
    login: login,
    logout: logout,
    initNav: initNav
  };

  // Auto-init nav on load
  initNav();

  // Bind logout button
  var logoutBtn = document.getElementById('nav-logout');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', function(e) {
      e.preventDefault();
      logout();
    });
  }
})();
