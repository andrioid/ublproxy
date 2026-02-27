package main

import (
	"net/http"
	"strconv"
)

func (a *apiHandler) handleActivity(w http.ResponseWriter, r *http.Request) {
	if a.activityLog == nil {
		writeJSON(w, http.StatusOK, []ActivityEntry{})
		return
	}

	limit := 100
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 1000 {
		limit = 1000
	}

	entries := a.activityLog.Recent(limit)
	if entries == nil {
		entries = []ActivityEntry{}
	}
	writeJSON(w, http.StatusOK, entries)
}

func (a *apiHandler) handleActivityStats(w http.ResponseWriter, r *http.Request) {
	if a.activityLog == nil {
		writeJSON(w, http.StatusOK, map[string]int{})
		return
	}
	writeJSON(w, http.StatusOK, a.activityLog.Stats())
}
