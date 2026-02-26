package blocklist

import (
	"net/http"
	"path"
	"strings"
)

// InferResourceType determines the resource type of a request using browser
// hints. Priority: Sec-Fetch-Dest header (most reliable), Accept header
// heuristics, URL file extension (last resort).
func InferResourceType(req *http.Request) ResourceType {
	if rt := fromSecFetchDest(req); rt != 0 {
		return rt
	}
	if rt := fromAcceptHeader(req); rt != 0 {
		return rt
	}
	return fromURLExtension(req.URL.Path)
}

// Sec-Fetch-Dest is set by all modern browsers and is the most reliable
// signal for resource type. Values defined by the Fetch metadata spec:
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Sec-Fetch-Dest
func fromSecFetchDest(req *http.Request) ResourceType {
	dest := strings.ToLower(req.Header.Get("Sec-Fetch-Dest"))
	switch dest {
	case "document":
		return ResourceDocument
	case "script":
		return ResourceScript
	case "style":
		return ResourceStylesheet
	case "image":
		return ResourceImage
	case "font":
		return ResourceFont
	case "iframe", "frame":
		return ResourceSubdocument
	case "audio", "video", "track":
		return ResourceMedia
	case "object", "embed":
		return ResourceObject
	case "websocket":
		return ResourceWebSocket
	case "empty":
		// "empty" is used for fetch/XHR, ping, beacon, etc.
		return ResourceXMLHTTPRequest
	}
	return 0
}

// Accept header heuristics for older browsers that don't send Sec-Fetch-Dest.
func fromAcceptHeader(req *http.Request) ResourceType {
	accept := req.Header.Get("Accept")
	if accept == "" {
		return 0
	}

	// XHR often sends X-Requested-With alongside Accept: */*
	if req.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		return ResourceXMLHTTPRequest
	}

	// text/html is document or subdocument — we can't distinguish here,
	// so we use document (more common). Exception rules with $document
	// will still work correctly.
	if strings.Contains(accept, "text/html") {
		return ResourceDocument
	}
	if strings.HasPrefix(accept, "image/") {
		return ResourceImage
	}
	if strings.Contains(accept, "text/css") {
		return ResourceStylesheet
	}

	return 0
}

// URL extension fallback for when no headers provide a signal.
var extensionToType = map[string]ResourceType{
	".js":    ResourceScript,
	".mjs":   ResourceScript,
	".css":   ResourceStylesheet,
	".png":   ResourceImage,
	".jpg":   ResourceImage,
	".jpeg":  ResourceImage,
	".gif":   ResourceImage,
	".svg":   ResourceImage,
	".webp":  ResourceImage,
	".ico":   ResourceImage,
	".avif":  ResourceImage,
	".woff":  ResourceFont,
	".woff2": ResourceFont,
	".ttf":   ResourceFont,
	".otf":   ResourceFont,
	".eot":   ResourceFont,
	".mp4":   ResourceMedia,
	".webm":  ResourceMedia,
	".ogg":   ResourceMedia,
	".mp3":   ResourceMedia,
	".m4a":   ResourceMedia,
	".flac":  ResourceMedia,
	".swf":   ResourceObject,
}

func fromURLExtension(urlPath string) ResourceType {
	// Strip query string if present in path
	if idx := strings.IndexByte(urlPath, '?'); idx >= 0 {
		urlPath = urlPath[:idx]
	}
	ext := strings.ToLower(path.Ext(urlPath))
	if rt, ok := extensionToType[ext]; ok {
		return rt
	}
	return 0
}
