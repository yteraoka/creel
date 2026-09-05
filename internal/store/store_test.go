package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newStore(t *testing.T, policy ExistPolicy) *Store {
	t.Helper()
	s, err := New(t.TempDir(), policy, false)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPathMirrorsDomainAndPath(t *testing.T) {
	s := newStore(t, Overwrite)
	tests := []struct {
		host, path, query string
		want              string
	}{
		{"example.com", "/a/b.json", "", "example.com/a/b.json"},
		{"example.com:8443", "/a/b.json", "", "example.com/a/b.json"},
		{"example.com", "/", "", "example.com/index"},
		{"example.com", "/dir/", "", "example.com/dir/index"},
		{"example.com", "/a/../../etc/passwd", "", "example.com/a/etc/passwd"},
		{"example.com", "/a//b", "", "example.com/a/b"},
		{"example.com", "/a:b?c", "", "example.com/a_b_c"},
	}
	for _, tt := range tests {
		got, err := filepath.Rel(s.Root(), s.Path(tt.host, tt.path, tt.query, ""))
		if err != nil {
			t.Fatal(err)
		}
		if filepath.ToSlash(got) != tt.want {
			t.Errorf("Path(%q, %q) = %q, want %q", tt.host, tt.path, got, tt.want)
		}
	}
}

func TestPathSeparatesQueries(t *testing.T) {
	s := newStore(t, Overwrite)
	a := s.Path("example.com", "/search", "q=1", "")
	b := s.Path("example.com", "/search", "q=2", "")
	plain := s.Path("example.com", "/search", "", "")
	if a == b || a == plain {
		t.Errorf("queries collided: %q %q %q", a, b, plain)
	}
	if !strings.HasPrefix(filepath.Base(a), "search_") {
		t.Errorf("query file name lost its path: %q", a)
	}
}

func TestSaveWritesFile(t *testing.T) {
	s := newStore(t, Overwrite)
	name, err := s.Save("example.com", "/api/v1/users", "", "", []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("content = %q, want %q", got, "hello")
	}
}

func TestSavePolicies(t *testing.T) {
	t.Run("overwrite", func(t *testing.T) {
		s := newStore(t, Overwrite)
		first, _ := s.Save("h.test", "/a", "", "", []byte("one"))
		second, err := s.Save("h.test", "/a", "", "", []byte("two"))
		if err != nil {
			t.Fatal(err)
		}
		if first != second {
			t.Fatalf("wrote a new file %q, want %q", second, first)
		}
		if b, _ := os.ReadFile(first); string(b) != "two" {
			t.Errorf("content = %q, want %q", b, "two")
		}
	})

	t.Run("skip", func(t *testing.T) {
		s := newStore(t, Skip)
		first, _ := s.Save("h.test", "/a", "", "", []byte("one"))
		second, err := s.Save("h.test", "/a", "", "", []byte("two"))
		if err != nil {
			t.Fatal(err)
		}
		if second != "" {
			t.Errorf("Save = %q, want \"\" for a kept file", second)
		}
		if b, _ := os.ReadFile(first); string(b) != "one" {
			t.Errorf("content = %q, want %q", b, "one")
		}
	})

	t.Run("number", func(t *testing.T) {
		s := newStore(t, Number)
		first, _ := s.Save("h.test", "/a", "", "", []byte("one"))
		second, err := s.Save("h.test", "/a", "", "", []byte("two"))
		if err != nil {
			t.Fatal(err)
		}
		if second != first+".1" {
			t.Errorf("Save = %q, want %q", second, first+".1")
		}
	})
}

func TestSaveHandlesFileDirectoryCollisions(t *testing.T) {
	s := newStore(t, Overwrite)

	// /a arrives first as a file, then /a/b needs /a to be a directory.
	file, err := s.Save("h.test", "/a", "", "", []byte("file"))
	if err != nil {
		t.Fatal(err)
	}
	nested, err := s.Save("h.test", "/a/b", "", "", []byte("nested"))
	if err != nil {
		t.Fatalf("nested save: %v", err)
	}
	if b, _ := os.ReadFile(file); string(b) != "file" {
		t.Errorf("original file was clobbered: %q", b)
	}
	if b, _ := os.ReadFile(nested); string(b) != "nested" {
		t.Errorf("nested content = %q", b)
	}

	// The reverse order: /c/d exists, then /c itself is fetched.
	if _, err := s.Save("h.test", "/c/d", "", "", []byte("nested")); err != nil {
		t.Fatal(err)
	}
	parent, err := s.Save("h.test", "/c", "", "", []byte("parent"))
	if err != nil {
		t.Fatalf("parent save: %v", err)
	}
	if b, _ := os.ReadFile(parent); string(b) != "parent" {
		t.Errorf("parent content = %q", b)
	}
}

func TestSanitizeLongSegment(t *testing.T) {
	long := strings.Repeat("x", 400)
	got := sanitize(long)
	if len(got) > maxSegment {
		t.Errorf("segment length = %d, want <= %d", len(got), maxSegment)
	}
	if sanitize(long) != got || sanitize(long+"y") == got {
		t.Error("long segment names must be stable and distinct")
	}
}

func TestNewRejectsUnknownPolicy(t *testing.T) {
	if _, err := New(t.TempDir(), "clobber", false); err == nil {
		t.Fatal("want error, got nil")
	}
}
