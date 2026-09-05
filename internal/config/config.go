// Package config loads the YAML configuration that drives which responses creel
// saves to disk.
package config

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v4"
)

// Config is the top level of the YAML configuration file.
type Config struct {
	// Listen is the address the proxy listens on, e.g. "127.0.0.1:8080".
	Listen string `yaml:"listen"`
	// OutputDir is the directory saved response bodies are written under.
	OutputDir string `yaml:"output_dir"`
	// MITMAll intercepts TLS for every host instead of only the hosts that
	// some rule's domain pattern can match.
	MITMAll bool `yaml:"mitm_all"`
	// OnExist is what to do when the target file already exists:
	// "overwrite" (default), "skip" or "number".
	OnExist string `yaml:"on_exist"`
	// AddExtension appends an extension derived from the response's
	// Content-Type when the URL path does not already carry a fitting one,
	// so /api/v1/users returning JSON is saved as users.json.
	AddExtension bool `yaml:"add_extension"`
	// MaxBodySize caps how many bytes of a response body are buffered for
	// saving. Larger bodies are passed through to the client unsaved.
	// Zero selects DefaultMaxBodySize.
	MaxBodySize int64 `yaml:"max_body_size"`
	// Rules are matched in order; the first match decides that a response is
	// saved. An empty rule list saves nothing.
	Rules []Rule `yaml:"rules"`
}

// Rule selects responses by request domain, request path and response
// Content-Type. An empty field matches anything.
type Rule struct {
	// Name is an optional label used in log output.
	Name string `yaml:"name"`
	// Domain is a glob pattern matched against the request host without port.
	// "*" stands for one label and "**" for any number, so "*.example.com"
	// matches api.example.com but not a.b.example.com, which
	// "**.example.com" matches along with example.com itself.
	Domain string `yaml:"domain"`
	// Path is a glob pattern matched against the request path. "*" does not
	// cross "/" boundaries; use "**" for that, e.g. "/api/**".
	Path string `yaml:"path"`
	// ContentType is a glob pattern matched against the response Content-Type
	// with its parameters stripped, e.g. "application/json" or "image/*".
	ContentType string `yaml:"content_type"`
	// MinSize skips responses whose saved body would be smaller than this
	// many bytes. Zero saves whatever size arrives.
	MinSize int64 `yaml:"min_size"`
}

// FileName is the name creel looks for when no config file is given.
const FileName = "config.yaml"

// Dir is $HOME/.config/creel, honouring XDG_CONFIG_HOME when set. It holds
// the configuration file and the CA.
func Dir() (string, error) {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "creel"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "creel"), nil
}

// DefaultPath returns the configuration file to read when none was given:
// config.yaml in the working directory if it exists, otherwise the one in
// Dir(). The second return value reports whether that file exists.
func DefaultPath() (string, bool, error) {
	if _, err := os.Stat(FileName); err == nil {
		return FileName, true, nil
	}
	dir, err := Dir()
	if err != nil {
		return "", false, err
	}
	p := filepath.Join(dir, FileName)
	_, err = os.Stat(p)
	return p, err == nil, nil
}

// Load reads and validates the configuration file at p.
func Load(p string) (*Config, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return &c, nil
}

// Defaults applied to fields left empty in the configuration file.
const (
	DefaultMaxBodySize = 64 << 20
	DefaultListen      = "127.0.0.1:8080"
	DefaultOutputDir   = "captured"
)

func (c *Config) validate() error {
	for i, r := range c.Rules {
		if r.MinSize < 0 {
			return fmt.Errorf("rules[%d].min_size: must not be negative", i)
		}
	}
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.OutputDir == "" {
		c.OutputDir = DefaultOutputDir
	}
	switch c.OnExist {
	case "", "overwrite", "skip", "number":
	default:
		return fmt.Errorf("on_exist: want overwrite, skip or number, got %q", c.OnExist)
	}
	if c.MaxBodySize < 0 {
		return fmt.Errorf("max_body_size: must not be negative")
	}
	if c.MaxBodySize == 0 {
		c.MaxBodySize = DefaultMaxBodySize
	}
	for i, r := range c.Rules {
		for _, f := range []struct{ name, pat string }{
			{"domain", r.Domain},
			{"path", r.Path},
			{"content_type", r.ContentType},
		} {
			if _, err := path.Match(strings.ReplaceAll(f.pat, "**", "*"), ""); err != nil {
				return fmt.Errorf("rules[%d].%s: bad pattern %q: %w", i, f.name, f.pat, err)
			}
		}
	}
	return nil
}

// MatchesDomain reports whether any rule can match host, which is used at
// CONNECT time to decide whether a TLS connection is worth intercepting.
func (c *Config) MatchesDomain(host string) bool {
	for _, r := range c.Rules {
		if matchDomain(r.Domain, host) {
			return true
		}
	}
	return false
}

// SizeUnknown asks Match to ignore size conditions, for the point in a
// response where the body has not been read yet.
const SizeUnknown = -1

// Match returns the first rule matching the request host, request path,
// response content type and body size, or nil when the response should not be
// saved. Pass SizeUnknown as size before the body has arrived.
func (c *Config) Match(host, reqPath, contentType string, size int64) *Rule {
	host = strings.ToLower(host)
	contentType = strings.ToLower(contentType)
	for i := range c.Rules {
		r := &c.Rules[i]
		if matchDomain(r.Domain, host) &&
			matchPath(r.Path, reqPath) &&
			matchGlob(r.ContentType, contentType) &&
			matchSize(r.MinSize, size) {
			return r
		}
	}
	return nil
}

// matchSize reports whether a body of the given size passes the rule's
// minimum. An unknown size passes, so a rule stays a candidate until its body
// has been read.
func matchSize(minSize, size int64) bool {
	return size == SizeUnknown || size >= minSize
}

// matchDomain matches a host against a domain pattern where "*" covers a
// single label and "**" any number of them; an empty pattern matches anything.
func matchDomain(pattern, host string) bool {
	if pattern == "" {
		return true
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return matchLabels(strings.Split(strings.ToLower(pattern), "."), strings.Split(host, "."))
}

func matchLabels(pattern, labels []string) bool {
	if len(pattern) == 0 {
		return len(labels) == 0
	}
	if pattern[0] == "**" {
		for i := 0; i <= len(labels); i++ {
			if matchLabels(pattern[1:], labels[i:]) {
				return true
			}
		}
		return false
	}
	if len(labels) == 0 || !matchCase(pattern[0], labels[0]) {
		return false
	}
	return matchLabels(pattern[1:], labels[1:])
}

// matchGlob matches pattern against s ignoring case; an empty pattern matches
// anything. It is used for content types, which are case-insensitive.
func matchGlob(pattern, s string) bool {
	return matchCase(strings.ToLower(pattern), strings.ToLower(s))
}

// matchCase is matchGlob without case folding, for case-sensitive paths.
func matchCase(pattern, s string) bool {
	if pattern == "" {
		return true
	}
	ok, err := path.Match(pattern, s)
	return err == nil && ok
}

// matchPath matches a path pattern where "**" spans "/" separators.
func matchPath(pattern, s string) bool {
	if pattern == "" {
		return true
	}
	if !strings.Contains(pattern, "**") {
		return matchCase(pattern, s)
	}
	// Split on "**"; each chunk between the wildcards must match in order,
	// with arbitrary text (separators included) allowed between them.
	parts := strings.Split(pattern, "**")
	rest := s
	for i, part := range parts {
		if part == "" {
			continue
		}
		var ok bool
		switch {
		case i == 0:
			rest, ok = consumePrefix(part, rest)
		case i == len(parts)-1:
			ok = consumeSuffix(part, rest)
		default:
			rest, ok = consumeAnywhere(part, rest)
		}
		if !ok {
			return false
		}
	}
	return true
}

// consumePrefix matches part against the start of s, returning the remainder.
func consumePrefix(part, s string) (string, bool) {
	for i := len(s); i >= 0; i-- {
		if matchCase(part, s[:i]) {
			return s[i:], true
		}
	}
	return "", false
}

// consumeSuffix reports whether part matches the end of s.
func consumeSuffix(part, s string) bool {
	for i := 0; i <= len(s); i++ {
		if matchCase(part, s[i:]) {
			return true
		}
	}
	return false
}

// consumeAnywhere matches part somewhere in s, returning what follows it.
func consumeAnywhere(part, s string) (string, bool) {
	for i := 0; i <= len(s); i++ {
		for j := len(s); j >= i; j-- {
			if matchCase(part, s[i:j]) {
				return s[j:], true
			}
		}
	}
	return "", false
}
