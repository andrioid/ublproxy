package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"ublproxy/pkg/store"
	"ublproxy/pkg/webauthn"
)

const (
	// Maximum request body size for API endpoints (1 MB)
	maxAPIBodySize = 1 << 20
	// Maximum number of pending challenges before rejecting new ones
	maxPendingChallenges = 1000
	// Challenges expire after 5 minutes
	challengeTTL = 5 * time.Minute
)

// challengeEntry wraps a challenge with a creation timestamp for TTL expiry.
type challengeEntry struct {
	challenge webauthn.Challenge
	createdAt time.Time
}

// apiHandler handles all /api/* routes on the portal.
type apiHandler struct {
	store       *store.Store
	webauthnCfg webauthn.Config
	sessions    *sessionMap

	// onRulesChanged is called after any rule mutation (create/delete/patch)
	// to invalidate the cached per-user RuleSet. The argument is the
	// credential ID whose rules changed.
	onRulesChanged func(credentialID string)

	// challenges stores pending WebAuthn challenges keyed by base64url
	// challenge value. Challenges are single-use and expire after challengeTTL.
	challenges   map[string]challengeEntry
	challengesMu sync.Mutex
}

func newAPIHandler(s *store.Store, cfg webauthn.Config, sm *sessionMap) *apiHandler {
	return &apiHandler{
		store:       s,
		webauthnCfg: cfg,
		sessions:    sm,
		challenges:  make(map[string]challengeEntry),
	}
}

func (a *apiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// CORS: reflect the requesting origin. Injected scripts run on arbitrary
	// proxied pages (e.g. https://example.com) and make cross-origin requests
	// to the portal (e.g. https://127.0.0.1:8443). All state-changing endpoints
	// require a Bearer token, so reflecting the origin is safe — the token is
	// never auto-sent by the browser.
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = a.webauthnCfg.RPOrigin
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Vary", "Origin")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api")

	// Auth routes (no session required)
	if strings.HasPrefix(path, "/auth/") {
		a.routeAuth(w, r, path)
		return
	}

	// All other routes require authentication
	sess := a.authenticate(r)
	if sess == nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{"unauthorized"})
		return
	}

	// Picker script (served with auth so only authenticated users can load it)
	if path == "/picker.js" && r.Method == http.MethodGet {
		a.handlePickerJS(w, r)
		return
	}

	// Rule routes
	if strings.HasPrefix(path, "/rules") {
		a.routeRules(w, r, path, sess)
		return
	}

	// Subscription routes
	if strings.HasPrefix(path, "/subscriptions") {
		a.routeSubscriptions(w, r, path, sess)
		return
	}

	http.NotFound(w, r)
}

// authenticate extracts and validates the session token from the Authorization
// header. Returns nil if the token is missing or invalid.
func (a *apiHandler) authenticate(r *http.Request) *store.Session {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return nil
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	sess, err := a.store.ValidateSession(token)
	if err != nil {
		return nil
	}
	return sess
}

// storeChallenge saves a challenge for later verification. Returns the
// base64url-encoded challenge string, or empty string if the challenge
// store is full (DoS protection).
func (a *apiHandler) storeChallenge(c webauthn.Challenge) string {
	key := c.Base64()
	now := time.Now()

	a.challengesMu.Lock()
	defer a.challengesMu.Unlock()

	// Evict expired challenges
	for k, entry := range a.challenges {
		if now.Sub(entry.createdAt) > challengeTTL {
			delete(a.challenges, k)
		}
	}

	// Reject if too many pending challenges (DoS protection)
	if len(a.challenges) >= maxPendingChallenges {
		return ""
	}

	a.challenges[key] = challengeEntry{challenge: c, createdAt: now}
	return key
}

// consumeChallenge retrieves and removes a challenge. Returns false if the
// challenge was not found, already used, or expired.
func (a *apiHandler) consumeChallenge(b64 string) (webauthn.Challenge, bool) {
	a.challengesMu.Lock()
	entry, ok := a.challenges[b64]
	if ok {
		delete(a.challenges, b64)
	}
	a.challengesMu.Unlock()
	if !ok {
		return webauthn.Challenge{}, false
	}
	// Check TTL
	if time.Since(entry.createdAt) > challengeTTL {
		return webauthn.Challenge{}, false
	}
	return entry.challenge, true
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) error {
	// Limit body size to prevent memory exhaustion from large payloads
	r.Body = http.MaxBytesReader(w, r.Body, maxAPIBodySize)
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

func jsonDecode(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

// handlePickerJS serves the element picker JavaScript. This is loaded by the
// bootstrap script when the user presses the keyboard shortcut (Alt+Shift+B).
// Requires authentication via Bearer token.
func (a *apiHandler) handlePickerJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(pickerJS))
}
