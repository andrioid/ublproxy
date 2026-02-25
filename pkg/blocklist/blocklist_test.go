package blocklist_test

import (
	"os"
	"path/filepath"
	"testing"

	"ublproxy/pkg/blocklist"
)

func TestParseLine(t *testing.T) {
	tests := []struct {
		input    string
		wantHost string
		wantOK   bool
	}{
		// Adblock domain anchor format
		{"||ads.example.com^", "ads.example.com", true},
		{"||tracker.net^", "tracker.net", true},
		{"||ads.example.com^$third-party", "ads.example.com", true},
		{"||ads.example.com^$script,image,domain=example.com", "ads.example.com", true},

		// Hosts-file format
		{"0.0.0.0 ads.example.com", "ads.example.com", true},
		{"127.0.0.1 ads.example.com", "ads.example.com", true},
		{"0.0.0.0 ads.example.com # inline comment", "ads.example.com", true},
		{"127.0.0.1 tracker.net", "tracker.net", true},

		// Plain hostname
		{"ads.example.com", "ads.example.com", true},
		{"tracker.net", "tracker.net", true},

		// Comments — should be skipped
		{"! this is an adblock comment", "", false},
		{"# this is a hosts-file comment", "", false},

		// Blank / whitespace
		{"", "", false},
		{"   ", "", false},
		{"\t", "", false},

		// Adblock header
		{"[Adblock Plus 2.0]", "", false},
		{"[Adblock]", "", false},

		// Exception rules — not supported yet
		{"@@||ads.example.com^", "", false},
		{"@@||ads.example.com^$document", "", false},

		// URL pattern rules — not a hostname block, skip
		{"/banner/*/img^", "", false},
		{"||ads.example.com/path^", "", false},

		// Element hiding / snippet rules — skip
		{"example.com##.advert", "", false},
		{"example.com#$#log Hello", "", false},

		// Hosts-file loopback entries — skip
		{"0.0.0.0 0.0.0.0", "", false},
		{"127.0.0.1 localhost", "", false},
		{"::1 localhost", "", false},
		{"0.0.0.0 local", "", false},
	}

	for _, tt := range tests {
		host, ok := blocklist.ParseLine(tt.input)
		if ok != tt.wantOK || host != tt.wantHost {
			t.Errorf("ParseLine(%q) = (%q, %v), want (%q, %v)",
				tt.input, host, ok, tt.wantHost, tt.wantOK)
		}
	}
}

func TestIsBlocked(t *testing.T) {
	bl := blocklist.New()
	bl.Add("ads.example.com")
	bl.Add("tracker.net")

	tests := []struct {
		host string
		want bool
	}{
		// Exact matches
		{"ads.example.com", true},
		{"tracker.net", true},

		// Subdomain matches
		{"foo.ads.example.com", true},
		{"bar.foo.ads.example.com", true},
		{"sub.tracker.net", true},

		// Non-matching
		{"example.com", false},
		{"other.com", false},
		{"notads.example.com", false},
		{"adsexample.com", false},

		// Empty
		{"", false},
	}

	for _, tt := range tests {
		if got := bl.IsBlocked(tt.host); got != tt.want {
			t.Errorf("IsBlocked(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestIsBlockedNilSafe(t *testing.T) {
	var bl *blocklist.Blocklist

	if bl.IsBlocked("anything.com") {
		t.Error("nil Blocklist.IsBlocked should return false")
	}
}

func TestLoadFile(t *testing.T) {
	content := `! EasyList header
[Adblock Plus 2.0]
! Homepage: https://easylist.to/

||ads.example.com^
||tracker.net^$third-party
0.0.0.0 malware.example.org
127.0.0.1 spyware.test
# a comment
@@||allowed.example.com^

example.com##.ad-banner
/banner/*/img^
`

	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	bl := blocklist.New()
	if err := bl.LoadFile(path); err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	blocked := []string{
		"ads.example.com",
		"sub.ads.example.com",
		"tracker.net",
		"malware.example.org",
		"spyware.test",
	}
	for _, host := range blocked {
		if !bl.IsBlocked(host) {
			t.Errorf("expected %q to be blocked", host)
		}
	}

	notBlocked := []string{
		"example.com",
		"allowed.example.com",
		"other.com",
	}
	for _, host := range notBlocked {
		if bl.IsBlocked(host) {
			t.Errorf("expected %q to NOT be blocked", host)
		}
	}
}
