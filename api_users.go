package main

import (
	"net/http"
	"strings"
	"time"

	"ublproxy/internal/store"
)

func (a *apiHandler) routeUsers(w http.ResponseWriter, r *http.Request, path string, sess *store.Session) {
	if !a.isAdmin(sess) {
		writeJSON(w, http.StatusForbidden, errorResponse{"admin access required"})
		return
	}

	if path == "/users" && r.Method == http.MethodGet {
		a.handleListUsers(w)
		return
	}

	// PATCH /users/:id
	if r.Method == http.MethodPatch {
		id := strings.TrimPrefix(path, "/users/")
		if id != "" && id != path {
			a.handlePatchUser(w, r, id, sess)
			return
		}
	}

	http.NotFound(w, r)
}

type userResponse struct {
	ID        string `json:"id"`
	IsAdmin   bool   `json:"is_admin"`
	CreatedAt string `json:"created_at"`
}

func (a *apiHandler) handleListUsers(w http.ResponseWriter) {
	creds, err := a.store.ListCredentials()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{"failed to list users"})
		return
	}
	users := make([]userResponse, len(creds))
	for i, c := range creds {
		users[i] = userResponse{
			ID:        c.ID,
			IsAdmin:   c.IsAdmin,
			CreatedAt: c.CreatedAt.Format(time.RFC3339),
		}
	}
	writeJSON(w, http.StatusOK, users)
}

func (a *apiHandler) handlePatchUser(w http.ResponseWriter, r *http.Request, id string, sess *store.Session) {
	if id == sess.CredentialID {
		writeJSON(w, http.StatusForbidden, errorResponse{"cannot modify own admin status"})
		return
	}

	var body struct {
		IsAdmin *bool `json:"is_admin"`
	}
	if err := readJSON(w, r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"invalid request body"})
		return
	}
	if body.IsAdmin == nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"is_admin is required"})
		return
	}

	if err := a.store.SetAdmin(id, *body.IsAdmin); err != nil {
		writeJSON(w, http.StatusNotFound, errorResponse{"user not found"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"is_admin": *body.IsAdmin})
}
