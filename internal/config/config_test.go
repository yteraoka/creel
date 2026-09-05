package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	p := filepath.Join(t.TempDir(), "creel.yaml")
	if err := os.WriteFile(p, []byte("rules:\n  - domain: example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Listen != DefaultListen || c.OutputDir != DefaultOutputDir || c.MaxBodySize != DefaultMaxBodySize {
		t.Errorf("defaults not applied: %+v", c)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	p := filepath.Join(t.TempDir(), "creel.yaml")
	if err := os.WriteFile(p, []byte("listne: :8080\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("want error for misspelled key, got nil")
	}
}

func TestLoadRejectsBadOnExist(t *testing.T) {
	p := filepath.Join(t.TempDir(), "creel.yaml")
	if err := os.WriteFile(p, []byte("on_exist: clobber\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("want error for unknown on_exist, got nil")
	}
}

func TestDirHonoursXDG(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/xdg")
	dir, err := Dir()
	if err != nil {
		t.Fatal(err)
	}
	if dir != filepath.Join("/xdg", "creel") {
		t.Errorf("Dir = %q", dir)
	}

	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "/home/someone")
	dir, err = Dir()
	if err != nil {
		t.Fatal(err)
	}
	if dir != filepath.Join("/home/someone", ".config", "creel") {
		t.Errorf("Dir = %q", dir)
	}
}

func TestDefaultPath(t *testing.T) {
	// A config.yaml in the working directory wins.
	work := t.TempDir()
	t.Chdir(work)
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home)
	userConfig := filepath.Join(home, "creel", FileName)
	if err := os.MkdirAll(filepath.Dir(userConfig), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userConfig, []byte("listen: :1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, FileName), []byte("listen: :2\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	p, found, err := DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if !found || p != FileName {
		t.Fatalf("DefaultPath = %q, %v; want %q, true", p, found, FileName)
	}

	// Without one there, the user directory is used.
	if err := os.Remove(filepath.Join(work, FileName)); err != nil {
		t.Fatal(err)
	}
	p, found, err = DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if !found || p != userConfig {
		t.Fatalf("DefaultPath = %q, %v; want %q, true", p, found, userConfig)
	}

	// With neither, the user path is reported as missing.
	if err := os.Remove(userConfig); err != nil {
		t.Fatal(err)
	}
	p, found, err = DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if found || p != userConfig {
		t.Fatalf("DefaultPath = %q, %v; want %q, false", p, found, userConfig)
	}
}

func TestMatch(t *testing.T) {
	c := &Config{Rules: []Rule{
		{Name: "api", Domain: "*.example.com", Path: "/api/**", ContentType: "application/json"},
		{Name: "images", Domain: "example.com", ContentType: "image/*"},
		{Name: "any", Domain: "catch.test"},
	}}

	tests := []struct {
		name        string
		host        string
		path        string
		contentType string
		want        string
	}{
		{"wildcard domain and deep path", "api.example.com", "/api/v1/users", "application/json", "api"},
		{"host case is ignored", "API.Example.com", "/api/x", "application/json", "api"},
		{"content type must match", "api.example.com", "/api/v1/users", "text/html", ""},
		{"path must match", "api.example.com", "/static/app.js", "application/json", ""},
		{"wildcard does not cross a label", "a.b.example.com", "/api/x", "application/json", ""},
		{"trailing dot is ignored", "api.example.com.", "/api/x", "application/json", "api"},
		{"content type wildcard", "example.com", "/logo.png", "image/png", "images"},
		{"empty fields match anything", "catch.test", "/whatever", "application/pdf", "any"},
		{"no rule matches", "other.test", "/", "text/html", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ""
			if r := c.Match(tt.host, tt.path, tt.contentType); r != nil {
				got = r.Name
			}
			if got != tt.want {
				t.Errorf("Match(%q, %q, %q) = %q, want %q", tt.host, tt.path, tt.contentType, got, tt.want)
			}
		})
	}
}

func TestMatchPath(t *testing.T) {
	tests := []struct {
		pattern, path string
		want          bool
	}{
		{"", "/anything", true},
		{"/api/*", "/api/users", true},
		{"/api/*", "/api/v1/users", false},
		{"/api/**", "/api/v1/users", true},
		{"/api/**", "/api/", true},
		{"**/*.json", "/a/b/c.json", true},
		{"**/*.json", "/a/b/c.txt", false},
		{"/**/edit", "/posts/1/edit", true},
		{"/Case", "/case", false},
	}
	for _, tt := range tests {
		if got := matchPath(tt.pattern, tt.path); got != tt.want {
			t.Errorf("matchPath(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
		}
	}
}

func TestMatchDomain(t *testing.T) {
	tests := []struct {
		pattern, host string
		want          bool
	}{
		{"", "anything.test", true},
		{"example.com", "example.com", true},
		{"example.com", "api.example.com", false},
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "a.b.example.com", false},
		{"*.example.com", "example.com", false},
		{"**.example.com", "a.b.example.com", true},
		{"**.example.com", "example.com", true},
		{"api-*.example.com", "api-v2.example.com", true},
		{"127.0.0.1", "127.0.0.1", true},
	}
	for _, tt := range tests {
		if got := matchDomain(tt.pattern, tt.host); got != tt.want {
			t.Errorf("matchDomain(%q, %q) = %v, want %v", tt.pattern, tt.host, got, tt.want)
		}
	}
}

func TestMatchesDomain(t *testing.T) {
	c := &Config{Rules: []Rule{{Domain: "*.example.com"}}}
	if !c.MatchesDomain("api.example.com") {
		t.Error("want api.example.com to be intercepted")
	}
	if c.MatchesDomain("example.org") {
		t.Error("want example.org to be tunnelled untouched")
	}
}
