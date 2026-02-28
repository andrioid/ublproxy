package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"ublproxy/internal/store"
	"ublproxy/internal/webauthn"
)

var testAPIConfig = webauthn.Config{
	RPID:     "localhost",
	RPName:   "test",
	RPOrigin: "https://localhost:8443",
}

func testAPI(t *testing.T) *apiHandler {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return newAPIHandler(s, testAPIConfig, newSessionMap())
}

// doRequest sends a request to the API handler and returns the response.
func doRequest(t *testing.T, api *apiHandler, method, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()
	var reqBody *bytes.Buffer
	if body != nil {
		b, _ := json.Marshal(body)
		reqBody = bytes.NewBuffer(b)
	} else {
		reqBody = &bytes.Buffer{}
	}

	req := httptest.NewRequest(method, path, reqBody)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	return rec
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(v); err != nil {
		t.Fatalf("decode response: %v (body: %s)", err, rec.Body.String())
	}
}

// TestFullPasskeyFlow tests registration -> login -> rule CRUD -> logout.
func TestFullPasskeyFlow(t *testing.T) {
	api := testAPI(t)

	// --- Registration ---

	// Step 1: Begin registration
	rec := doRequest(t, api, "POST", "/api/auth/register/begin", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("register/begin: status %d, body: %s", rec.Code, rec.Body.String())
	}

	var beginResp struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"rp"`
	}
	decodeJSON(t, rec, &beginResp)

	if beginResp.Challenge == "" {
		t.Fatal("challenge is empty")
	}
	if beginResp.RP.ID != "localhost" {
		t.Errorf("RP ID = %q, want %q", beginResp.RP.ID, "localhost")
	}

	// Step 2: Generate a credential client-side (simulated)
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	credID := []byte("test-credential-id")

	challengeBytes, _ := base64.RawURLEncoding.DecodeString(beginResp.Challenge)
	var challenge webauthn.Challenge
	copy(challenge[:], challengeBytes)

	attestObj, clientDataJSON := buildTestRegistration(t, privateKey, credID, challenge)

	// Step 3: Finish registration
	finishBody := map[string]string{
		"attestationObject": base64.RawURLEncoding.EncodeToString(attestObj),
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientDataJSON),
	}
	rec = doRequest(t, api, "POST", "/api/auth/register/finish", finishBody, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("register/finish: status %d, body: %s", rec.Code, rec.Body.String())
	}

	var tokenResp struct {
		Token string `json:"token"`
	}
	decodeJSON(t, rec, &tokenResp)
	regToken := tokenResp.Token
	if regToken == "" {
		t.Fatal("registration token is empty")
	}

	// --- Rules (using registration token) ---

	// Create a rule
	rec = doRequest(t, api, "POST", "/api/rules", map[string]string{
		"rule":   "example.com##.ad-banner",
		"domain": "example.com",
	}, regToken)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create rule: status %d, body: %s", rec.Code, rec.Body.String())
	}

	var ruleResp struct {
		ID      int64  `json:"id"`
		Rule    string `json:"rule"`
		Domain  string `json:"domain"`
		Enabled bool   `json:"enabled"`
	}
	decodeJSON(t, rec, &ruleResp)
	if ruleResp.Rule != "example.com##.ad-banner" {
		t.Errorf("rule = %q", ruleResp.Rule)
	}
	if !ruleResp.Enabled {
		t.Error("new rule should be enabled")
	}
	ruleID := ruleResp.ID

	// List rules
	rec = doRequest(t, api, "GET", "/api/rules", nil, regToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("list rules: status %d", rec.Code)
	}
	var rules []struct {
		ID int64 `json:"id"`
	}
	decodeJSON(t, rec, &rules)
	if len(rules) != 1 {
		t.Errorf("rules count = %d, want 1", len(rules))
	}

	// Disable rule
	enabled := false
	rec = doRequest(t, api, "PATCH", "/api/rules/"+itoa(ruleID), map[string]*bool{
		"enabled": &enabled,
	}, regToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch rule: status %d, body: %s", rec.Code, rec.Body.String())
	}

	// Delete rule
	rec = doRequest(t, api, "DELETE", "/api/rules/"+itoa(ruleID), nil, regToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete rule: status %d", rec.Code)
	}

	// Verify empty
	rec = doRequest(t, api, "GET", "/api/rules", nil, regToken)
	decodeJSON(t, rec, &rules)
	if len(rules) != 0 {
		t.Errorf("rules count after delete = %d, want 0", len(rules))
	}

	// --- Logout ---
	rec = doRequest(t, api, "POST", "/api/auth/logout", nil, regToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout: status %d", rec.Code)
	}

	// Token should no longer work
	rec = doRequest(t, api, "GET", "/api/rules", nil, regToken)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("rules after logout: status %d, want 401", rec.Code)
	}

	// --- Login ---

	// Begin login
	rec = doRequest(t, api, "POST", "/api/auth/login/begin", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("login/begin: status %d, body: %s", rec.Code, rec.Body.String())
	}

	var loginBegin struct {
		Challenge        string `json:"challenge"`
		AllowCredentials []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	}
	decodeJSON(t, rec, &loginBegin)

	if len(loginBegin.AllowCredentials) != 1 {
		t.Fatalf("allowCredentials count = %d, want 1", len(loginBegin.AllowCredentials))
	}

	// Build assertion
	loginChallengeBytes, _ := base64.RawURLEncoding.DecodeString(loginBegin.Challenge)
	var loginChallenge webauthn.Challenge
	copy(loginChallenge[:], loginChallengeBytes)

	authData, loginClientDataJSON, sig := buildTestAssertion(t, privateKey, loginChallenge, 1)

	loginFinishBody := map[string]string{
		"credentialId":      loginBegin.AllowCredentials[0].ID,
		"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(loginClientDataJSON),
		"signature":         base64.RawURLEncoding.EncodeToString(sig),
	}

	rec = doRequest(t, api, "POST", "/api/auth/login/finish", loginFinishBody, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("login/finish: status %d, body: %s", rec.Code, rec.Body.String())
	}

	decodeJSON(t, rec, &tokenResp)
	if tokenResp.Token == "" {
		t.Fatal("login token is empty")
	}

	// Verify login token works
	rec = doRequest(t, api, "GET", "/api/rules", nil, tokenResp.Token)
	if rec.Code != http.StatusOK {
		t.Fatalf("rules with login token: status %d", rec.Code)
	}
}

func TestRulesRequireAuth(t *testing.T) {
	api := testAPI(t)

	rec := doRequest(t, api, "GET", "/api/rules", nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("rules without auth: status %d, want 401", rec.Code)
	}

	rec = doRequest(t, api, "POST", "/api/rules", map[string]string{"rule": "test"}, "bad-token")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("rules with bad token: status %d, want 401", rec.Code)
	}
}

func TestCORSPreflight(t *testing.T) {
	api := testAPI(t)

	req := httptest.NewRequest("OPTIONS", "/api/auth/register/begin", nil)
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("CORS preflight: status %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Error("missing Access-Control-Allow-Methods header")
	}
	// Without Origin header, falls back to portal origin
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != testAPIConfig.RPOrigin {
		t.Errorf("CORS origin without Origin header = %q, want %q", got, testAPIConfig.RPOrigin)
	}
}

func TestCORSReflectsRequestOrigin(t *testing.T) {
	api := testAPI(t)

	// Preflight from a proxied page origin
	req := httptest.NewRequest("OPTIONS", "/api/rules", nil)
	req.Header.Set("Origin", "https://example.com")
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://example.com" {
		t.Errorf("CORS origin = %q, want %q", got, "https://example.com")
	}
	if got := rec.Header().Get("Vary"); !strings.Contains(got, "Origin") {
		t.Errorf("Vary header = %q, should contain Origin", got)
	}
}

func TestPickerJSRequiresAuth(t *testing.T) {
	api := testAPI(t)

	// Without auth
	rec := doRequest(t, api, "GET", "/api/picker.js", nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("picker.js without auth: status %d, want 401", rec.Code)
	}

	// With auth
	token := registerAndGetToken(t, api)
	rec = doRequest(t, api, "GET", "/api/picker.js", nil, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("picker.js with auth: status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/javascript" {
		t.Errorf("Content-Type = %q, want application/javascript", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "generateSelector") {
		t.Error("picker.js should contain selector generation code")
	}
	if !strings.Contains(body, "Shadow") || !strings.Contains(body, "attachShadow") {
		t.Error("picker.js should use Shadow DOM")
	}
}

func TestCreateRuleEmptyRule(t *testing.T) {
	api := testAPI(t)
	token := registerAndGetToken(t, api)

	rec := doRequest(t, api, "POST", "/api/rules", map[string]string{
		"rule":   "",
		"domain": "example.com",
	}, token)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("create empty rule: status %d, want 400", rec.Code)
	}
}

// --- Helpers ---

func registerAndGetToken(t *testing.T, api *apiHandler) string {
	t.Helper()

	rec := doRequest(t, api, "POST", "/api/auth/register/begin", nil, "")
	var beginResp struct {
		Challenge string `json:"challenge"`
	}
	decodeJSON(t, rec, &beginResp)

	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	challengeBytes, _ := base64.RawURLEncoding.DecodeString(beginResp.Challenge)
	var challenge webauthn.Challenge
	copy(challenge[:], challengeBytes)

	attestObj, clientDataJSON := buildTestRegistration(t, privateKey, []byte("test-cred"), challenge)

	rec = doRequest(t, api, "POST", "/api/auth/register/finish", map[string]string{
		"attestationObject": base64.RawURLEncoding.EncodeToString(attestObj),
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientDataJSON),
	}, "")

	var tokenResp struct {
		Token string `json:"token"`
	}
	decodeJSON(t, rec, &tokenResp)
	return tokenResp.Token
}

func buildTestRegistration(t *testing.T, key *ecdsa.PrivateKey, credID []byte, challenge webauthn.Challenge) ([]byte, []byte) {
	t.Helper()

	clientData := map[string]any{
		"type":      "webauthn.create",
		"challenge": challenge.Base64(),
		"origin":    testAPIConfig.RPOrigin,
	}
	clientDataJSON, _ := json.Marshal(clientData)

	rpIDHash := sha256.Sum256([]byte(testAPIConfig.RPID))
	authData := make([]byte, 0, 200)
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, 0x41) // flags: UP | AT
	authData = append(authData, 0, 0, 0, 0)

	aaguid := make([]byte, 16)
	authData = append(authData, aaguid...)

	credIDLen := make([]byte, 2)
	binary.BigEndian.PutUint16(credIDLen, uint16(len(credID)))
	authData = append(authData, credIDLen...)
	authData = append(authData, credID...)

	x := padTo32Bytes(key.PublicKey.X.Bytes())
	y := padTo32Bytes(key.PublicKey.Y.Bytes())
	coseKey := map[int]any{
		1: 2, 3: -7, -1: 1, -2: x, -3: y,
	}
	coseKeyBytes, _ := cbor.Marshal(coseKey)
	authData = append(authData, coseKeyBytes...)

	attObj := map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	}
	attObjBytes, _ := cbor.Marshal(attObj)
	return attObjBytes, clientDataJSON
}

func buildTestAssertion(t *testing.T, key *ecdsa.PrivateKey, challenge webauthn.Challenge, signCount uint32) ([]byte, []byte, []byte) {
	t.Helper()

	clientData := map[string]any{
		"type":      "webauthn.get",
		"challenge": challenge.Base64(),
		"origin":    testAPIConfig.RPOrigin,
	}
	clientDataJSON, _ := json.Marshal(clientData)

	rpIDHash := sha256.Sum256([]byte(testAPIConfig.RPID))
	authData := make([]byte, 37)
	copy(authData, rpIDHash[:])
	authData[32] = 0x01 // UP
	binary.BigEndian.PutUint32(authData[33:], signCount)

	clientDataHash := sha256.Sum256(clientDataJSON)
	verifyData := make([]byte, 37+32)
	copy(verifyData, authData)
	copy(verifyData[37:], clientDataHash[:])

	hash := sha256.Sum256(verifyData)
	sig, _ := ecdsa.SignASN1(rand.Reader, key, hash[:])

	return authData, clientDataJSON, sig
}

func padTo32Bytes(b []byte) []byte {
	if len(b) >= 32 {
		return b[:32]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

func itoa(i int64) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
