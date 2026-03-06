package blocklist

import "encoding/base64"

// RedirectResource holds the content and MIME type for a neutered resource
// served in place of blocked requests.
type RedirectResource struct {
	ContentType string
	Body        []byte
}

// LookupRedirectResource returns the neutered resource for a given name.
// Returns false if the resource name is not recognized.
func LookupRedirectResource(name string) (RedirectResource, bool) {
	r, ok := redirectResources[name]
	return r, ok
}

// b64 decodes a base64 string into bytes. Panics on invalid input
// (only used with compile-time constants).
func b64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic("invalid base64 in redirect resource: " + err.Error())
	}
	return b
}

// redirectResources maps resource names (and aliases) to their content.
// Data is from uBlock Origin's resources library:
// https://github.com/gorhill/uBlock/wiki/Resources-Library
var redirectResources = map[string]RedirectResource{
	// 1x1 transparent GIF (43 bytes)
	"1x1.gif": {
		ContentType: "image/gif",
		Body:        b64("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"),
	},
	"1x1-transparent.gif": {
		ContentType: "image/gif",
		Body:        b64("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"),
	},

	// 2x2 transparent PNG (68 bytes)
	"2x2.png": {
		ContentType: "image/png",
		Body: b64("iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAYAAABytg0kAAAAC0lEQVQI" +
			"12NgAAIAASAAo3BkQgAAAABJRU5ErkJggg=="),
	},
	"2x2-transparent.png": {
		ContentType: "image/png",
		Body: b64("iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAYAAABytg0kAAAAC0lEQVQI" +
			"12NgAAIAASAAo3BkQgAAAABJRU5ErkJggg=="),
	},

	// 3x2 transparent PNG (68 bytes)
	"3x2.png": {
		ContentType: "image/png",
		Body: b64("iVBORw0KGgoAAAANSUhEUgAAAAMAAAACCAYAAACddGYaAAAAC0lEQVQI" +
			"12NgwAUAABoAASRETuUAAAAASUVORK5CYII="),
	},
	"3x2-transparent.png": {
		ContentType: "image/png",
		Body: b64("iVBORw0KGgoAAAANSUhEUgAAAAMAAAACCAYAAACddGYaAAAAC0lEQVQI" +
			"12NgwAUAABoAASRETuUAAAAASUVORK5CYII="),
	},

	// 32x32 transparent PNG (116 bytes)
	"32x32.png": {
		ContentType: "image/png",
		Body: b64("iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAGklEQVRY" +
			"R+3BAQEAAACCIP+vbkhAAQAAAO8GECAAAUDigjEAAAAASUVORK5CYII="),
	},
	"32x32-transparent.png": {
		ContentType: "image/png",
		Body: b64("iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAGklEQVRY" +
			"R+3BAQEAAACCIP+vbkhAAQAAAO8GECAAAUDigjEAAAAASUVORK5CYII="),
	},

	// Empty JavaScript
	"noopjs": {
		ContentType: "application/javascript",
		Body:        []byte("(function(){})();\n"),
	},
	"noop.js": {
		ContentType: "application/javascript",
		Body:        []byte("(function(){})();\n"),
	},

	// Empty CSS
	"noop.css": {
		ContentType: "text/css",
		Body:        []byte{},
	},
	"noopcss": {
		ContentType: "text/css",
		Body:        []byte{},
	},

	// Empty HTML (for iframes)
	"noop.html": {
		ContentType: "text/html",
		Body:        []byte("<!DOCTYPE html>\n"),
	},
	"noopframe": {
		ContentType: "text/html",
		Body:        []byte("<!DOCTYPE html>\n"),
	},

	// Empty text
	"noop.txt": {
		ContentType: "text/plain",
		Body:        []byte{},
	},
	"nooptxt": {
		ContentType: "text/plain",
		Body:        []byte{},
	},

	// Empty JSON
	"noop.json": {
		ContentType: "application/json",
		Body:        []byte("{}\n"),
	},

	// Completely empty response (zero bytes, no content type)
	"empty": {
		ContentType: "",
		Body:        []byte{},
	},
	"none": {
		ContentType: "",
		Body:        []byte{},
	},

	// Empty VAST 2.0 XML
	"noop-vast2.xml": {
		ContentType: "text/xml",
		Body:        []byte(`<VAST version="2.0"></VAST>`),
	},

	// Empty VAST 3.0 XML
	"noop-vast3.xml": {
		ContentType: "text/xml",
		Body:        []byte(`<VAST version="3.0"></VAST>`),
	},

	// Empty VAST 4.0 XML
	"noop-vast4.xml": {
		ContentType: "text/xml",
		Body:        []byte(`<VAST version="4.0"></VAST>`),
	},

	// Empty VMAP 1.0 XML
	"noop-vmap1.xml": {
		ContentType: "text/xml",
		Body: []byte(`<vmap:VMAP xmlns:vmap="http://www.iab.net/videosuite/vmap"` +
			` version="1.0"></vmap:VMAP>`),
	},
}

func init() {
	// Minimal silent MP3: single MPEG1 Layer3 frame (128kbps 44100Hz stereo, 417 bytes)
	// Frame header 0xFFFB9004 followed by zero-filled audio data
	mp3Frame := make([]byte, 417)
	mp3Frame[0] = 0xFF
	mp3Frame[1] = 0xFB
	mp3Frame[2] = 0x90
	mp3Frame[3] = 0x04
	redirectResources["noop-0.1s.mp3"] = RedirectResource{
		ContentType: "audio/mpeg",
		Body:        mp3Frame,
	}
	redirectResources["noop-0.5s.mp3"] = RedirectResource{
		ContentType: "audio/mpeg",
		Body:        mp3Frame,
	}

	// Minimal valid MP4 (ftyp + moov boxes, 144 bytes)
	mp4Data := b64("AAAAHGZ0eXBpc29tAAACAGlzb21pc28ybXA0MQAAAHRtb292AAAAbG12aGQAAAAAAAAAAAAAAAAAAAPoAAAAAAABAAABAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC")
	redirectResources["noopmp4-1s"] = RedirectResource{
		ContentType: "video/mp4",
		Body:        mp4Data,
	}
	redirectResources["noop-1s.mp4"] = RedirectResource{
		ContentType: "video/mp4",
		Body:        mp4Data,
	}
}
