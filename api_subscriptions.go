package main

import (
	"net/http"
	"strconv"
	"strings"

	"ublproxy/pkg/store"
)

func (a *apiHandler) routeSubscriptions(w http.ResponseWriter, r *http.Request, path string, sess *store.Session) {
	switch {
	case path == "/subscriptions" && r.Method == http.MethodGet:
		a.handleListSubscriptions(w, r, sess)
	case path == "/subscriptions" && r.Method == http.MethodPost:
		a.handleCreateSubscription(w, r, sess)
	case path == "/subscriptions/refresh" && r.Method == http.MethodPost:
		a.handleRefreshSubscriptions(w, r, sess)
	case strings.HasPrefix(path, "/subscriptions/") && r.Method == http.MethodDelete:
		a.handleDeleteSubscription(w, r, path, sess)
	case strings.HasPrefix(path, "/subscriptions/") && r.Method == http.MethodPatch:
		a.handlePatchSubscription(w, r, path, sess)
	default:
		http.NotFound(w, r)
	}
}

type subscriptionResponse struct {
	ID        int64  `json:"id"`
	URL       string `json:"url"`
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	IsDefault bool   `json:"isDefault"`
	CreatedAt string `json:"createdAt"`
}

func toSubscriptionResponse(s store.Subscription) subscriptionResponse {
	return subscriptionResponse{
		ID:        s.ID,
		URL:       s.URL,
		Name:      s.Name,
		Enabled:   s.Enabled,
		IsDefault: s.IsDefault,
		CreatedAt: s.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}
}

func (a *apiHandler) handleListSubscriptions(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	subs, err := a.store.ListSubscriptions(sess.CredentialID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{"failed to list subscriptions"})
		return
	}

	resp := make([]subscriptionResponse, len(subs))
	for i, s := range subs {
		resp[i] = toSubscriptionResponse(s)
	}

	writeJSON(w, http.StatusOK, resp)
}

type createSubscriptionRequest struct {
	URL  string `json:"url"`
	Name string `json:"name"`
}

func (a *apiHandler) handleCreateSubscription(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	var req createSubscriptionRequest
	if err := readJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"invalid request body"})
		return
	}

	if req.URL == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{"url is required"})
		return
	}
	if !strings.HasPrefix(req.URL, "http://") && !strings.HasPrefix(req.URL, "https://") {
		writeJSON(w, http.StatusBadRequest, errorResponse{"url must start with http:// or https://"})
		return
	}

	sub, err := a.store.CreateSubscription(sess.CredentialID, req.URL, req.Name)
	if err != nil {
		// UNIQUE constraint violation means duplicate
		if strings.Contains(err.Error(), "UNIQUE") {
			writeJSON(w, http.StatusConflict, errorResponse{"subscription already exists"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, errorResponse{"failed to create subscription"})
		return
	}

	a.triggerReload(sess.CredentialID)
	writeJSON(w, http.StatusCreated, toSubscriptionResponse(*sub))
}

func (a *apiHandler) handleDeleteSubscription(w http.ResponseWriter, r *http.Request, path string, sess *store.Session) {
	id, err := parseSubscriptionID(path)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"invalid subscription ID"})
		return
	}

	if err := a.store.DeleteSubscription(id, sess.CredentialID); err != nil {
		writeJSON(w, http.StatusNotFound, errorResponse{"subscription not found"})
		return
	}

	a.triggerReload(sess.CredentialID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type patchSubscriptionRequest struct {
	Enabled *bool `json:"enabled"`
}

func (a *apiHandler) handlePatchSubscription(w http.ResponseWriter, r *http.Request, path string, sess *store.Session) {
	id, err := parseSubscriptionID(path)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"invalid subscription ID"})
		return
	}

	var req patchSubscriptionRequest
	if err := readJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"invalid request body"})
		return
	}

	if req.Enabled == nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"enabled field is required"})
		return
	}

	if err := a.store.SetSubscriptionEnabled(id, sess.CredentialID, *req.Enabled); err != nil {
		writeJSON(w, http.StatusNotFound, errorResponse{"subscription not found"})
		return
	}

	a.triggerReload(sess.CredentialID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleRefreshSubscriptions forces re-download of all cached blocklists.
func (a *apiHandler) handleRefreshSubscriptions(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	if err := a.store.ClearBlocklistCache(); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{"failed to clear cache"})
		return
	}

	a.triggerReload(sess.CredentialID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func parseSubscriptionID(path string) (int64, error) {
	idStr := strings.TrimPrefix(path, "/subscriptions/")
	return strconv.ParseInt(idStr, 10, 64)
}
