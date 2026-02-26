package main

import (
	"encoding/base64"
	"net/http"

	"ublproxy/pkg/webauthn"
)

func (a *apiHandler) routeAuth(w http.ResponseWriter, r *http.Request, path string) {
	switch {
	case path == "/auth/register/begin" && r.Method == http.MethodPost:
		a.handleRegisterBegin(w, r)
	case path == "/auth/register/finish" && r.Method == http.MethodPost:
		a.handleRegisterFinish(w, r)
	case path == "/auth/login/begin" && r.Method == http.MethodPost:
		a.handleLoginBegin(w, r)
	case path == "/auth/login/finish" && r.Method == http.MethodPost:
		a.handleLoginFinish(w, r)
	case path == "/auth/logout" && r.Method == http.MethodPost:
		a.handleLogout(w, r)
	default:
		http.NotFound(w, r)
	}
}

// --- Registration ---

type registerBeginResponse struct {
	Challenge              string                 `json:"challenge"`
	RP                     rpEntity               `json:"rp"`
	User                   userEntity             `json:"user"`
	PubKeyCredParams       []pubKeyCredParam      `json:"pubKeyCredParams"`
	Attestation            string                 `json:"attestation"`
	AuthenticatorSelection authenticatorSelection `json:"authenticatorSelection"`
}

type rpEntity struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

type userEntity struct {
	// For passkey-only auth, the user ID is a random opaque handle.
	// The browser needs one to create the credential, but we don't
	// use it for anything meaningful on the server.
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type pubKeyCredParam struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

type authenticatorSelection struct {
	ResidentKey      string `json:"residentKey"`
	UserVerification string `json:"userVerification"`
}

func (a *apiHandler) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	challenge, err := webauthn.NewChallenge()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{"failed to generate challenge"})
		return
	}

	key := a.storeChallenge(challenge)
	if key == "" {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{"too many pending challenges, try again later"})
		return
	}

	// Generate a random user ID (the browser requires one, but we identify
	// users by their credential ID, not this handle)
	userHandle := make([]byte, 16)
	copy(userHandle, challenge[:16])

	resp := registerBeginResponse{
		Challenge: key,
		RP: rpEntity{
			Name: a.webauthnCfg.RPName,
			ID:   a.webauthnCfg.RPID,
		},
		User: userEntity{
			ID:          base64.RawURLEncoding.EncodeToString(userHandle),
			Name:        "ublproxy user",
			DisplayName: "ublproxy user",
		},
		PubKeyCredParams: []pubKeyCredParam{
			{Type: "public-key", Alg: -7}, // ES256
		},
		Attestation: "none",
		AuthenticatorSelection: authenticatorSelection{
			ResidentKey:      "preferred",
			UserVerification: "preferred",
		},
	}

	writeJSON(w, http.StatusOK, resp)
}

type registerFinishRequest struct {
	AttestationObject string `json:"attestationObject"` // base64url
	ClientDataJSON    string `json:"clientDataJSON"`    // base64url
}

func (a *apiHandler) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	var req registerFinishRequest
	if err := readJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"invalid request body"})
		return
	}

	attestationObject, err := base64.RawURLEncoding.DecodeString(req.AttestationObject)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"invalid attestationObject encoding"})
		return
	}

	clientDataJSON, err := base64.RawURLEncoding.DecodeString(req.ClientDataJSON)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"invalid clientDataJSON encoding"})
		return
	}

	// Extract the challenge from clientDataJSON to look up the stored challenge
	var cd struct {
		Challenge string `json:"challenge"`
	}
	if err := jsonDecode(clientDataJSON, &cd); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"invalid clientDataJSON"})
		return
	}

	challenge, ok := a.consumeChallenge(cd.Challenge)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorResponse{"unknown or expired challenge"})
		return
	}

	cred, err := webauthn.VerifyRegistration(a.webauthnCfg, attestationObject, clientDataJSON, challenge)
	if err != nil {
		logError("webauthn/register", err)
		writeJSON(w, http.StatusBadRequest, errorResponse{"registration verification failed"})
		return
	}

	// Store credential
	credID := cred.CredentialIDBase64()
	if err := a.store.SaveCredential(credID, cred.PublicKey); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{"failed to save credential"})
		return
	}

	// Create session
	sess, err := a.store.CreateSession(credID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{"failed to create session"})
		return
	}

	// Associate session with client IP for script injection and per-user rules
	if a.sessions != nil {
		a.sessions.Set(clientIPFromRequest(r), sessionEntry{
			Token:        sess.Token,
			CredentialID: credID,
		})
	}

	writeJSON(w, http.StatusOK, map[string]string{"token": sess.Token})
}

// --- Authentication ---

type loginBeginResponse struct {
	Challenge        string                 `json:"challenge"`
	RPID             string                 `json:"rpId"`
	AllowCredentials []credentialDescriptor `json:"allowCredentials"`
	UserVerification string                 `json:"userVerification"`
}

type credentialDescriptor struct {
	Type string `json:"type"`
	ID   string `json:"id"` // base64url credential ID
}

func (a *apiHandler) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	challenge, err := webauthn.NewChallenge()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{"failed to generate challenge"})
		return
	}

	key := a.storeChallenge(challenge)
	if key == "" {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{"too many pending challenges, try again later"})
		return
	}

	// List all known credential IDs so the browser can offer them
	credIDs, err := a.store.ListCredentialIDs()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{"failed to list credentials"})
		return
	}

	allow := make([]credentialDescriptor, len(credIDs))
	for i, id := range credIDs {
		allow[i] = credentialDescriptor{Type: "public-key", ID: id}
	}

	resp := loginBeginResponse{
		Challenge:        key,
		RPID:             a.webauthnCfg.RPID,
		AllowCredentials: allow,
		UserVerification: "preferred",
	}

	writeJSON(w, http.StatusOK, resp)
}

type loginFinishRequest struct {
	CredentialID      string `json:"credentialId"`      // base64url
	AuthenticatorData string `json:"authenticatorData"` // base64url
	ClientDataJSON    string `json:"clientDataJSON"`    // base64url
	Signature         string `json:"signature"`         // base64url
}

func (a *apiHandler) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	var req loginFinishRequest
	if err := readJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"invalid request body"})
		return
	}

	// Decode all base64url fields
	authData, err := base64.RawURLEncoding.DecodeString(req.AuthenticatorData)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"invalid authenticatorData encoding"})
		return
	}
	clientDataJSON, err := base64.RawURLEncoding.DecodeString(req.ClientDataJSON)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"invalid clientDataJSON encoding"})
		return
	}
	sig, err := base64.RawURLEncoding.DecodeString(req.Signature)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"invalid signature encoding"})
		return
	}

	// Extract challenge from clientDataJSON
	var cd struct {
		Challenge string `json:"challenge"`
	}
	if err := jsonDecode(clientDataJSON, &cd); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"invalid clientDataJSON"})
		return
	}

	challenge, ok := a.consumeChallenge(cd.Challenge)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorResponse{"unknown or expired challenge"})
		return
	}

	// Look up credential
	cred, err := a.store.GetCredential(req.CredentialID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{"unknown credential"})
		return
	}

	// Verify assertion signature
	signCount, err := webauthn.VerifyAuthentication(
		a.webauthnCfg, authData, clientDataJSON, sig, cred.PublicKey, challenge,
	)
	if err != nil {
		logError("webauthn/login", err)
		writeJSON(w, http.StatusUnauthorized, errorResponse{"authentication failed"})
		return
	}

	// Update sign count
	a.store.UpdateSignCount(req.CredentialID, signCount)

	// Create session
	sess, err := a.store.CreateSession(req.CredentialID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{"failed to create session"})
		return
	}

	// Associate session with client IP for script injection and per-user rules
	if a.sessions != nil {
		a.sessions.Set(clientIPFromRequest(r), sessionEntry{
			Token:        sess.Token,
			CredentialID: req.CredentialID,
		})
	}

	writeJSON(w, http.StatusOK, map[string]string{"token": sess.Token})
}

// --- Logout ---

func (a *apiHandler) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess := a.authenticate(r)
	if sess == nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{"unauthorized"})
		return
	}
	a.store.DeleteSession(sess.Token)
	if a.sessions != nil {
		a.sessions.Delete(clientIPFromRequest(r))
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
