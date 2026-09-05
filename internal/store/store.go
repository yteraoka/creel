// Package store writes captured response bodies to disk, mirroring the
// request's domain and path.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ExistPolicy decides what happens when the target file already exists.
type ExistPolicy string

const (
	// Overwrite replaces the existing file. This is the default.
	Overwrite ExistPolicy = "overwrite"
	// Skip keeps the existing file and drops the new body.
	Skip ExistPolicy = "skip"
	// Number writes alongside it as "name.1", "name.2" and so on.
	Number ExistPolicy = "number"
)

// maxSegment bounds a single path element so long paths stay within the
// per-component limit of common filesystems.
const maxSegment = 120

// Store saves bodies under a root directory.
type Store struct {
	root   string
	policy ExistPolicy
}

// New returns a Store writing under root.
func New(root string, policy ExistPolicy) (*Store, error) {
	switch policy {
	case "":
		policy = Overwrite
	case Overwrite, Skip, Number:
	default:
		return nil, fmt.Errorf("unknown on_exist policy %q", policy)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	return &Store{root: abs, policy: policy}, nil
}

// Root returns the absolute output directory.
func (s *Store) Root() string { return s.root }

// Save writes body for a request to host/urlPath?query. It returns the file
// written, or "" when an existing file was kept because of the skip policy.
func (s *Store) Save(host, urlPath, query string, body []byte) (string, error) {
	target := s.Path(host, urlPath, query)

	dir, err := s.makeDir(filepath.Dir(target))
	if err != nil {
		return "", err
	}
	target = filepath.Join(dir, filepath.Base(target))

	// A path that is a file for one request and a directory prefix for
	// another, such as /a and /a/b: keep the shorter one inside the
	// directory.
	if fi, err := os.Stat(target); err == nil && fi.IsDir() {
		target = filepath.Join(target, "index")
	}

	switch s.policy {
	case Skip:
		if _, err := os.Stat(target); err == nil {
			return "", nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	case Number:
		target, err = nextFree(target)
		if err != nil {
			return "", err
		}
	}

	if err := os.WriteFile(target, body, 0o644); err != nil {
		return "", err
	}
	return target, nil
}

// Path returns the file a response for host/urlPath?query maps to, without
// touching the filesystem.
func (s *Store) Path(host, urlPath, query string) string {
	elems := []string{s.root, sanitize(hostOnly(host))}

	segs := strings.Split(strings.TrimPrefix(urlPath, "/"), "/")
	last := len(segs) - 1
	for i, seg := range segs {
		switch seg {
		case "", ".", "..":
			// "" is a trailing or doubled slash: the last one becomes the
			// directory index, the rest are dropped along with any attempt
			// to climb out of the output directory.
			if i == last {
				elems = append(elems, "index")
			}
			continue
		}
		elems = append(elems, sanitize(seg))
	}
	if len(elems) == 2 {
		elems = append(elems, "index")
	}

	p := filepath.Join(elems...)
	if query != "" {
		// Queries differing only in parameters must not collide, but a raw
		// query makes a poor file name, so tag the path with a digest.
		p += "_" + digest(query)
	}
	return p
}

// makeDir creates dir, stepping around ancestors that already exist as files
// by giving those a parallel ".d" directory.
func (s *Store) makeDir(dir string) (string, error) {
	rel, err := filepath.Rel(s.root, dir)
	if err != nil {
		return "", err
	}
	cur := s.root
	if err := os.MkdirAll(cur, 0o755); err != nil {
		return "", err
	}
	if rel == "." {
		return cur, nil
	}
	for _, seg := range strings.Split(rel, string(filepath.Separator)) {
		next := filepath.Join(cur, seg)
		if fi, err := os.Stat(next); err == nil && !fi.IsDir() {
			next += ".d"
		}
		if err := os.MkdirAll(next, 0o755); err != nil {
			return "", err
		}
		cur = next
	}
	return cur, nil
}

// nextFree returns p, or the first unused "p.N" when p is taken.
func nextFree(p string) (string, error) {
	for i := 0; ; i++ {
		candidate := p
		if i > 0 {
			candidate = fmt.Sprintf("%s.%d", p, i)
		}
		_, err := os.Stat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			return candidate, nil
		}
		if err != nil {
			return "", err
		}
	}
}

// hostOnly strips a port from host, leaving IPv6 brackets off.
func hostOnly(host string) string {
	host = strings.ToLower(strings.Trim(host, "[]"))
	if i := strings.LastIndex(host, "]:"); i >= 0 {
		return strings.Trim(host[:i+1], "[]")
	}
	if strings.Count(host, ":") == 1 {
		return host[:strings.Index(host, ":")]
	}
	return host
}

// sanitize turns one URL path segment into a safe file name.
func sanitize(seg string) string {
	var b strings.Builder
	for _, r := range seg {
		switch {
		case r < 0x20, r == 0x7f:
			b.WriteByte('_')
		case strings.ContainsRune(`/\:*?"<>|`, r):
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" || out == "." || out == ".." {
		return "_"
	}
	if len(out) > maxSegment {
		// Keep the head readable and the whole thing unique.
		out = out[:maxSegment-9] + "_" + digest(out)
	}
	return out
}

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}
