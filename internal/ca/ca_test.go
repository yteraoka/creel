package ca

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateCreatesThenReuses(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "creel")

	first, created, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("created = false on an empty directory")
	}
	if !first.Certificate().IsCA {
		t.Error("generated certificate is not a CA")
	}

	fi, err := os.Stat(filepath.Join(dir, KeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("key mode = %v, want 0600", perm)
	}

	second, created, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Error("created = true for an existing CA")
	}
	if !second.Certificate().Equal(first.Certificate()) {
		t.Error("reloaded a different certificate")
	}
}

func TestLeafVerifiesAgainstTheCA(t *testing.T) {
	root, _, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := root.Leaf("api.example.com:443")
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(root.Certificate())
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{
		DNSName: "api.example.com",
		Roots:   pool,
	}); err != nil {
		t.Errorf("verify: %v", err)
	}
	if len(leaf.Certificate) != 2 {
		t.Errorf("chain length = %d, want leaf + CA", len(leaf.Certificate))
	}
}

func TestLeafIsCachedPerHost(t *testing.T) {
	root, _, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a, err := root.Leaf("example.com")
	if err != nil {
		t.Fatal(err)
	}
	b, err := root.Leaf("EXAMPLE.com.")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Error("want the same cached certificate for the same host")
	}
	c, err := root.Leaf("other.test")
	if err != nil {
		t.Fatal(err)
	}
	if c == a {
		t.Error("want a distinct certificate per host")
	}
}

func TestLeafForIPAddress(t *testing.T) {
	root, _, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := root.Leaf("127.0.0.1:8443")
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.Leaf.IPAddresses) != 1 || !leaf.Leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("IP SANs = %v, want 127.0.0.1", leaf.Leaf.IPAddresses)
	}
	if len(leaf.Leaf.DNSNames) != 0 {
		t.Errorf("DNS SANs = %v, want none", leaf.Leaf.DNSNames)
	}
}

func TestTLSConfigFallsBackWithoutSNI(t *testing.T) {
	root, _, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := root.TLSConfig("fallback.test:443")
	cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if got := cert.Leaf.Subject.CommonName; got != "fallback.test" {
		t.Errorf("common name = %q, want fallback.test", got)
	}
}

func TestLoadRejectsCorruptFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, CertFile), []byte("not a pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, KeyFile), []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreate(dir); err == nil {
		t.Fatal("want an error for a corrupt CA, got nil")
	}
}

func TestDefaultDirHonoursXDG(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/xdg")
	dir, err := DefaultDir()
	if err != nil {
		t.Fatal(err)
	}
	if dir != filepath.Join("/xdg", "creel") {
		t.Errorf("DefaultDir = %q", dir)
	}

	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "/home/someone")
	dir, err = DefaultDir()
	if err != nil {
		t.Fatal(err)
	}
	if dir != filepath.Join("/home/someone", ".config", "creel") {
		t.Errorf("DefaultDir = %q", dir)
	}
}
