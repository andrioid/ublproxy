package main

import (
	"log/slog"
	"os"
	"strings"
	"time"
)

// setupLogging configures the default slog logger with the given level.
// Valid levels: "debug", "info", "warn", "error". Returns an error for
// unrecognized levels.
func setupLogging(level string) error {
	var slevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		slevel = slog.LevelDebug
	case "info":
		slevel = slog.LevelInfo
	case "warn":
		slevel = slog.LevelWarn
	case "error":
		slevel = slog.LevelError
	default:
		slevel = slog.LevelInfo
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slevel,
	})
	slog.SetDefault(slog.New(handler))
	return nil
}

// shortUserID returns the first 8 characters of a credential ID,
// or "anon" if the credential ID is empty (unauthenticated).
func shortUserID(credentialID string) string {
	if credentialID == "" {
		return "anon"
	}
	if len(credentialID) > 8 {
		return credentialID[:8]
	}
	return credentialID
}

// truncateRule shortens a rule string to maxLen, appending "..." if truncated.
func truncateRule(rule string, maxLen int) string {
	if len(rule) <= maxLen {
		return rule
	}
	return rule[:maxLen] + "..."
}

// logRequest logs a completed HTTP request at Debug level.
// Only visible when --log-level=debug.
func logRequest(method, url string, status int, duration time.Duration, clientIP, credentialID string) {
	slog.Debug("request",
		"method", method,
		"url", url,
		"status", status,
		"duration", duration.Round(time.Millisecond),
		"ip", clientIP,
		"user", shortUserID(credentialID),
	)
}

// logError logs an operational error at Error level.
func logError(context string, err error, clientIP, credentialID string) {
	slog.Error(context,
		"err", err,
		"ip", clientIP,
		"user", shortUserID(credentialID),
	)
}

// logBlocked logs a blocked request at Info level.
func logBlocked(host, url, rule, clientIP, credentialID string) {
	attrs := []any{
		"host", host,
		"ip", clientIP,
		"user", shortUserID(credentialID),
	}
	if url != "" {
		attrs = append(attrs, "url", url)
	}
	if rule != "" {
		attrs = append(attrs, "rule", rule)
	}
	slog.Info("blocked", attrs...)
}

// logElementHidden logs a CSS element hiding injection at Debug level.
func logElementHidden(host, rule, clientIP, credentialID string) {
	slog.Debug("element-hidden",
		"host", host,
		"rule", rule,
		"ip", clientIP,
		"user", shortUserID(credentialID),
	)
}

// logPassthrough logs a passthrough tunnel at Debug level.
func logPassthrough(host, clientIP, credentialID string) {
	slog.Debug("passthrough",
		"host", host,
		"ip", clientIP,
		"user", shortUserID(credentialID),
	)
}
