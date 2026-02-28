package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"ublproxy/internal/store"
)

func (a *apiHandler) routeRules(w http.ResponseWriter, r *http.Request, path string, sess *store.Session) {
	switch {
	case path == "/rules" && r.Method == http.MethodGet:
		a.handleListRules(w, r, sess)
	case path == "/rules" && r.Method == http.MethodPost:
		a.handleCreateRule(w, r, sess)
	case strings.HasPrefix(path, "/rules/") && r.Method == http.MethodDelete:
		a.handleDeleteRule(w, r, path, sess)
	case strings.HasPrefix(path, "/rules/") && r.Method == http.MethodPatch:
		a.handlePatchRule(w, r, path, sess)
	default:
		http.NotFound(w, r)
	}
}

type ruleResponse struct {
	ID        int64  `json:"id"`
	Rule      string `json:"rule"`
	Domain    string `json:"domain"`
	Enabled   bool   `json:"enabled"`
	CreatedAt string `json:"createdAt"`
}

func toRuleResponse(r store.Rule) ruleResponse {
	return ruleResponse{
		ID:        r.ID,
		Rule:      r.Rule,
		Domain:    r.Domain,
		Enabled:   r.Enabled,
		CreatedAt: r.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}
}

func (a *apiHandler) handleListRules(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	rules, err := a.store.ListRules(sess.CredentialID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{"failed to list rules"})
		return
	}

	resp := make([]ruleResponse, len(rules))
	for i, r := range rules {
		resp[i] = toRuleResponse(r)
	}

	writeJSON(w, http.StatusOK, resp)
}

type createRuleRequest struct {
	Rule   string `json:"rule"`
	Domain string `json:"domain"`
}

func (a *apiHandler) handleCreateRule(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	var req createRuleRequest
	if err := readJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"invalid request body"})
		return
	}

	if req.Rule == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{"rule is required"})
		return
	}

	rule, err := a.store.CreateRule(sess.CredentialID, req.Rule, req.Domain)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{"failed to create rule"})
		return
	}

	a.triggerReload(sess.CredentialID)
	writeJSON(w, http.StatusCreated, toRuleResponse(*rule))
}

func (a *apiHandler) handleDeleteRule(w http.ResponseWriter, r *http.Request, path string, sess *store.Session) {
	id, err := parseRuleID(path)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"invalid rule ID"})
		return
	}

	if err := a.store.DeleteRule(id, sess.CredentialID); err != nil {
		writeJSON(w, http.StatusNotFound, errorResponse{"rule not found"})
		return
	}

	a.triggerReload(sess.CredentialID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type patchRuleRequest struct {
	Enabled *bool `json:"enabled"`
}

func (a *apiHandler) handlePatchRule(w http.ResponseWriter, r *http.Request, path string, sess *store.Session) {
	id, err := parseRuleID(path)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"invalid rule ID"})
		return
	}

	var req patchRuleRequest
	if err := readJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"invalid request body"})
		return
	}

	if req.Enabled == nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"enabled field is required"})
		return
	}

	if err := a.store.SetRuleEnabled(id, sess.CredentialID, *req.Enabled); err != nil {
		writeJSON(w, http.StatusNotFound, errorResponse{"rule not found"})
		return
	}

	a.triggerReload(sess.CredentialID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// triggerReload calls the onRulesChanged callback if set, passing the
// credential ID whose rules changed so only that user's cache is invalidated.
func (a *apiHandler) triggerReload(credentialID string) {
	if a.onRulesChanged != nil {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "panic in onRulesChanged: %v\n", r)
				}
			}()
			a.onRulesChanged(credentialID)
		}()
	}
}

// parseRuleID extracts the rule ID from a path like "/rules/123".
func parseRuleID(path string) (int64, error) {
	idStr := strings.TrimPrefix(path, "/rules/")
	return strconv.ParseInt(idStr, 10, 64)
}
