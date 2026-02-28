package blocklist_test

import (
	"net/http"
	"testing"

	"ublproxy/internal/blocklist"
)

func TestInferResourceTypeFromSecFetchDest(t *testing.T) {
	tests := []struct {
		dest string
		want blocklist.ResourceType
	}{
		{"document", blocklist.ResourceDocument},
		{"script", blocklist.ResourceScript},
		{"style", blocklist.ResourceStylesheet},
		{"image", blocklist.ResourceImage},
		{"font", blocklist.ResourceFont},
		{"iframe", blocklist.ResourceSubdocument},
		{"frame", blocklist.ResourceSubdocument},
		{"audio", blocklist.ResourceMedia},
		{"video", blocklist.ResourceMedia},
		{"object", blocklist.ResourceObject},
		{"embed", blocklist.ResourceObject},
		{"websocket", blocklist.ResourceWebSocket},
		{"empty", blocklist.ResourceXMLHTTPRequest},
	}

	for _, tt := range tests {
		t.Run("sec-fetch-dest="+tt.dest, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://example.com/file", nil)
			req.Header.Set("Sec-Fetch-Dest", tt.dest)
			got := blocklist.InferResourceType(req)
			if got != tt.want {
				t.Errorf("Sec-Fetch-Dest=%q: got %d, want %d", tt.dest, got, tt.want)
			}
		})
	}
}

func TestInferResourceTypeFromAcceptHeader(t *testing.T) {
	tests := []struct {
		name   string
		accept string
		xhr    string // X-Requested-With header
		want   blocklist.ResourceType
	}{
		{"html document", "text/html,application/xhtml+xml", "", blocklist.ResourceDocument},
		{"image", "image/webp,image/png,image/*;q=0.8", "", blocklist.ResourceImage},
		{"css", "text/css,*/*;q=0.1", "", blocklist.ResourceStylesheet},
		{"xhr with header", "*/*", "XMLHttpRequest", blocklist.ResourceXMLHTTPRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://example.com/file", nil)
			// No Sec-Fetch-Dest — falls through to Accept
			req.Header.Set("Accept", tt.accept)
			if tt.xhr != "" {
				req.Header.Set("X-Requested-With", tt.xhr)
			}
			got := blocklist.InferResourceType(req)
			if got != tt.want {
				t.Errorf("Accept=%q: got %d, want %d", tt.accept, got, tt.want)
			}
		})
	}
}

func TestInferResourceTypeFromURLExtension(t *testing.T) {
	tests := []struct {
		url  string
		want blocklist.ResourceType
	}{
		{"http://example.com/ads/tracker.js", blocklist.ResourceScript},
		{"http://example.com/ads/tracker.mjs", blocklist.ResourceScript},
		{"http://example.com/style/main.css", blocklist.ResourceStylesheet},
		{"http://example.com/images/banner.png", blocklist.ResourceImage},
		{"http://example.com/images/banner.jpg", blocklist.ResourceImage},
		{"http://example.com/images/logo.svg", blocklist.ResourceImage},
		{"http://example.com/images/photo.webp", blocklist.ResourceImage},
		{"http://example.com/fonts/roboto.woff2", blocklist.ResourceFont},
		{"http://example.com/fonts/roboto.ttf", blocklist.ResourceFont},
		{"http://example.com/media/video.mp4", blocklist.ResourceMedia},
		{"http://example.com/media/audio.mp3", blocklist.ResourceMedia},
		{"http://example.com/page", 0}, // no extension — unknown
		{"http://example.com/api/data?format=json", 0},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			req, _ := http.NewRequest("GET", tt.url, nil)
			// No Sec-Fetch-Dest, no Accept — falls through to extension
			got := blocklist.InferResourceType(req)
			if got != tt.want {
				t.Errorf("URL=%q: got %d, want %d", tt.url, got, tt.want)
			}
		})
	}
}

func TestInferResourceTypePriority(t *testing.T) {
	// Sec-Fetch-Dest takes priority over Accept and URL extension
	req, _ := http.NewRequest("GET", "http://example.com/file.js", nil)
	req.Header.Set("Sec-Fetch-Dest", "image")
	req.Header.Set("Accept", "text/html")

	got := blocklist.InferResourceType(req)
	if got != blocklist.ResourceImage {
		t.Errorf("expected Sec-Fetch-Dest to win, got %d", got)
	}
}
