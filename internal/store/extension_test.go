package store

import (
	"path/filepath"
	"testing"
)

func TestExtensionFor(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		file        string
		want        string
	}{
		{"json without an extension", "application/json", "users", ".json"},
		{"html index", "text/html", "index", ".html"},
		{"jpeg prefers .jpg", "image/jpeg", "photo", ".jpg"},
		{"already the same extension", "application/json", "data.json", ""},
		{"already an alternative extension", "text/html", "page.htm", ""},
		{"extension case is ignored", "image/png", "LOGO.PNG", ""},
		{"a different extension is kept and tagged", "text/html", "index.php", ".html"},
		{"structured suffix", "application/vnd.api+json", "resource", ".json"},
		{"generic binary gets nothing", "application/octet-stream", "blob", ""},
		{"unknown type gets nothing", "application/x-nonsense", "thing", ""},
		{"no content type", "", "thing", ""},
		{"parameters are tolerated", "application/json; charset=utf-8", "users", ".json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extensionFor(tt.contentType, tt.file); got != tt.want {
				t.Errorf("extensionFor(%q, %q) = %q, want %q", tt.contentType, tt.file, got, tt.want)
			}
		})
	}
}

func TestPathAddsExtension(t *testing.T) {
	s, err := New(t.TempDir(), Overwrite, true)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		host, path, query, contentType string
		want                           string
	}{
		{"example.com", "/api/v1/users", "", "application/json", "example.com/api/v1/users.json"},
		{"example.com", "/", "", "text/html", "example.com/index.html"},
		{"example.com", "/dir/", "", "text/html", "example.com/dir/index.html"},
		{"example.com", "/logo.png", "", "image/png", "example.com/logo.png"},
		{"example.com", "/search", "q=go", "application/json", "example.com/search_61f03144.json"},
		{"example.com", "/a", "", "", "example.com/a"},
	}
	for _, tt := range tests {
		got, err := filepath.Rel(s.Root(), s.Path(tt.host, tt.path, tt.query, tt.contentType))
		if err != nil {
			t.Fatal(err)
		}
		if filepath.ToSlash(got) != tt.want {
			t.Errorf("Path(%q, %q, %q, %q) = %q, want %q",
				tt.host, tt.path, tt.query, tt.contentType, got, tt.want)
		}
	}
}

func TestPathWithoutTheOptionIsUnchanged(t *testing.T) {
	s, err := New(t.TempDir(), Overwrite, false)
	if err != nil {
		t.Fatal(err)
	}
	got, err := filepath.Rel(s.Root(), s.Path("example.com", "/api/v1/users", "", "application/json"))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.ToSlash(got) != "example.com/api/v1/users" {
		t.Errorf("Path = %q, want the path mirrored as-is", got)
	}
}
