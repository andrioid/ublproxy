package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestShortUserID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "anon"},
		{"AbCdEfGhIjKlMnOp", "AbCdEfGh"},
		{"short", "short"},
		{"exactly8", "exactly8"},
	}
	for _, tt := range tests {
		got := shortUserID(tt.input)
		if got != tt.want {
			t.Errorf("shortUserID(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// withLogCapture sets up a slog logger that writes to a buffer at the given
// level, runs fn, then restores the previous default logger.
func withLogCapture(level slog.Level, fn func()) string {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: level})
	prev := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(prev)
	fn()
	return buf.String()
}

func TestLogRequestIsDebugLevel(t *testing.T) {
	// At info level, logRequest should produce no output
	output := withLogCapture(slog.LevelInfo, func() {
		logRequest("GET", "https://example.com/page", 200, 45*time.Millisecond, "192.168.1.5", "AbCdEfGhIjKl")
	})
	if output != "" {
		t.Errorf("logRequest at info level should produce no output, got: %s", output)
	}

	// At debug level, logRequest should produce output
	output = withLogCapture(slog.LevelDebug, func() {
		logRequest("GET", "https://example.com/page", 200, 45*time.Millisecond, "192.168.1.5", "AbCdEfGhIjKl")
	})
	if output == "" {
		t.Error("logRequest at debug level should produce output")
	}
	if !strings.Contains(output, "level=DEBUG") {
		t.Errorf("expected level=DEBUG, got: %s", output)
	}
	if !strings.Contains(output, "ip=192.168.1.5") {
		t.Errorf("expected ip=192.168.1.5, got: %s", output)
	}
	if !strings.Contains(output, "user=AbCdEfGh") {
		t.Errorf("expected user=AbCdEfGh (truncated), got: %s", output)
	}
}

func TestLogBlockedIsInfoLevel(t *testing.T) {
	output := withLogCapture(slog.LevelInfo, func() {
		logBlocked("ads.example.com", "https://ads.example.com/banner.js", "||ads.example.com^", "10.0.0.1", "CredIDxyz12345")
	})
	if !strings.Contains(output, "level=INFO") {
		t.Errorf("expected level=INFO, got: %s", output)
	}
	if !strings.Contains(output, "msg=blocked") {
		t.Errorf("expected msg=blocked, got: %s", output)
	}
	if !strings.Contains(output, "ip=10.0.0.1") {
		t.Errorf("expected ip=10.0.0.1, got: %s", output)
	}
	if !strings.Contains(output, "user=CredIDxy") {
		t.Errorf("expected user=CredIDxy (truncated), got: %s", output)
	}
}

func TestLogPassthroughIsDebugLevel(t *testing.T) {
	// At info level, logPassthrough should produce no output
	output := withLogCapture(slog.LevelInfo, func() {
		logPassthrough("bank.example.com", "192.168.1.10", "")
	})
	if output != "" {
		t.Errorf("logPassthrough at info level should produce no output, got: %s", output)
	}

	// At debug level, logPassthrough should produce output
	output = withLogCapture(slog.LevelDebug, func() {
		logPassthrough("bank.example.com", "192.168.1.10", "")
	})
	if !strings.Contains(output, "level=DEBUG") {
		t.Errorf("expected level=DEBUG, got: %s", output)
	}
	if !strings.Contains(output, "msg=passthrough") {
		t.Errorf("expected msg=passthrough, got: %s", output)
	}
	if !strings.Contains(output, "user=anon") {
		t.Errorf("expected user=anon for empty credential, got: %s", output)
	}
}

func TestLogElementHiddenIsDebugLevel(t *testing.T) {
	// At info level, logElementHidden should produce no output
	output := withLogCapture(slog.LevelInfo, func() {
		logElementHidden("example.com", "192.168.1.5", "CredABCD1234")
	})
	if output != "" {
		t.Errorf("logElementHidden at info level should produce no output, got: %s", output)
	}

	// At debug level, logElementHidden should produce output
	output = withLogCapture(slog.LevelDebug, func() {
		logElementHidden("example.com", "192.168.1.5", "CredABCD1234")
	})
	if !strings.Contains(output, "level=DEBUG") {
		t.Errorf("expected level=DEBUG, got: %s", output)
	}
	if !strings.Contains(output, "msg=element-hidden") {
		t.Errorf("expected msg=element-hidden, got: %s", output)
	}
	if !strings.Contains(output, "host=example.com") {
		t.Errorf("expected host=example.com, got: %s", output)
	}
}

func TestLogErrorIsErrorLevel(t *testing.T) {
	output := withLogCapture(slog.LevelInfo, func() {
		logError("connect/roundtrip", errForTest("dial tcp: timeout"), "192.168.1.5", "SomeCredID")
	})
	if !strings.Contains(output, "level=ERROR") {
		t.Errorf("expected level=ERROR, got: %s", output)
	}
	if !strings.Contains(output, "ip=192.168.1.5") {
		t.Errorf("expected ip=192.168.1.5, got: %s", output)
	}
}

func TestLogErrorSuppressedAtWarnLevel(t *testing.T) {
	// logError is ERROR level -- should NOT appear when level is set higher
	// (there is no level higher than ERROR in slog, so this test just
	// verifies it appears at warn level, which is lower than error)
	output := withLogCapture(slog.LevelWarn, func() {
		logError("test/context", errForTest("some error"), "1.2.3.4", "")
	})
	if !strings.Contains(output, "level=ERROR") {
		t.Errorf("logError should still appear at warn level, got: %s", output)
	}
}

type errForTest string

func (e errForTest) Error() string { return string(e) }
