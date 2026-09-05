package proxy

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yteraoka/creel/internal/ca"
	"github.com/yteraoka/creel/internal/config"
	"github.com/yteraoka/creel/internal/store"
)

// origin serves the fixtures the proxy tests fetch through creel.
func originHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		io.WriteString(w, `{"users":["ada"]}`)
	})
	mux.HandleFunc("/api/v1/gzipped", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		io.WriteString(gz, `{"compressed":true}`)
	})
	mux.HandleFunc("/page.html", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, "<h1>not json</h1>")
	})
	mux.HandleFunc("/api/v1/huge", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(bytes.Repeat([]byte("x"), 4096))
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, _ := io.ReadAll(r.Body)
		io.WriteString(w, r.Method+" "+string(body))
	})
	return mux
}

type harness struct {
	proxyURL  *url.URL
	outputDir string
	client    *http.Client
}

// newHarness starts an origin server, a creel proxy in front of it and a
// client configured to use that proxy and to trust creel's CA.
func newHarness(t *testing.T, cfg *config.Config, origin *httptest.Server) *harness {
	t.Helper()

	root, _, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	cfg.OutputDir = out
	if cfg.MaxBodySize == 0 {
		cfg.MaxBodySize = config.DefaultMaxBodySize
	}
	st, err := store.New(out, store.ExistPolicy(cfg.OnExist), cfg.AddExtension)
	if err != nil {
		t.Fatal(err)
	}

	p := New(cfg, root, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if origin.TLS != nil {
		pool := x509.NewCertPool()
		pool.AddCert(origin.Certificate())
		p.SetUpstreamTLSConfig(&tls.Config{RootCAs: pool})
	}

	proxySrv := httptest.NewServer(p)
	t.Cleanup(proxySrv.Close)
	proxyURL, err := url.Parse(proxySrv.URL)
	if err != nil {
		t.Fatal(err)
	}

	clientPool := x509.NewCertPool()
	clientPool.AddCert(root.Certificate())
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: clientPool},
	}}
	t.Cleanup(client.CloseIdleConnections)

	return &harness{proxyURL: proxyURL, outputDir: out, client: client}
}

func (h *harness) get(t *testing.T, rawURL string) (*http.Response, string) {
	t.Helper()
	resp, err := h.client.Get(rawURL)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body of %s: %v", rawURL, err)
	}
	return resp, string(body)
}

// waitSaved waits for the proxy to finish writing want files. Saving happens
// just after the client has seen the last byte of the body, so a test that
// looks immediately can catch a half-written directory.
func (h *harness) waitSaved(t *testing.T, want int) []string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var files []string
	for {
		files = h.saved(t)
		if len(files) == want {
			// Nothing should appear afterwards either.
			time.Sleep(50 * time.Millisecond)
			if files = h.saved(t); len(files) == want {
				return files
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("saved files = %v, want %d", files, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (h *harness) saved(t *testing.T) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(h.outputDir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			rel, err := filepath.Rel(h.outputDir, p)
			if err != nil {
				return err
			}
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func jsonRules() []config.Rule {
	return []config.Rule{{Name: "json", Domain: "127.0.0.1", Path: "/api/**", ContentType: "application/json"}}
}

func TestHTTPSInterceptSavesMatchingBody(t *testing.T) {
	origin := httptest.NewTLSServer(originHandler())
	defer origin.Close()
	h := newHarness(t, &config.Config{Rules: jsonRules()}, origin)

	resp, body := h.get(t, origin.URL+"/api/v1/users")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if body != `{"users":["ada"]}` {
		t.Fatalf("body = %q", body)
	}

	files := h.waitSaved(t, 1)
	if !strings.HasSuffix(files[0], "/api/v1/users") {
		t.Fatalf("saved files = %v, want 127.0.0.1/api/v1/users", files)
	}
	got, err := os.ReadFile(filepath.Join(h.outputDir, files[0]))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Errorf("saved %q, want %q", got, body)
	}
}

func TestAddExtensionNamesFilesByContentType(t *testing.T) {
	origin := httptest.NewTLSServer(originHandler())
	defer origin.Close()
	h := newHarness(t, &config.Config{AddExtension: true, Rules: jsonRules()}, origin)

	if _, body := h.get(t, origin.URL+"/api/v1/users"); body != `{"users":["ada"]}` {
		t.Fatalf("body = %q", body)
	}
	files := h.waitSaved(t, 1)
	if !strings.HasSuffix(files[0], "/api/v1/users.json") {
		t.Errorf("saved %v, want the path with a .json extension", files)
	}
}

func TestNonMatchingResponsesAreNotSaved(t *testing.T) {
	origin := httptest.NewTLSServer(originHandler())
	defer origin.Close()
	h := newHarness(t, &config.Config{Rules: jsonRules()}, origin)

	if _, body := h.get(t, origin.URL+"/page.html"); body != "<h1>not json</h1>" {
		t.Fatalf("body = %q", body)
	}
	h.waitSaved(t, 0)
}

func TestGzippedBodyIsSavedDecoded(t *testing.T) {
	origin := httptest.NewTLSServer(originHandler())
	defer origin.Close()
	h := newHarness(t, &config.Config{Rules: jsonRules()}, origin)

	// The client asks for gzip, so the proxy must pass the compressed bytes
	// through untouched while saving the decoded copy.
	req, err := http.NewRequest(http.MethodGet, origin.URL+"/api/v1/gzipped", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if enc := resp.Header.Get("Content-Encoding"); enc != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", enc)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"compressed":true}` {
		t.Fatalf("client body = %q", body)
	}

	files := h.waitSaved(t, 1)
	got, err := os.ReadFile(filepath.Join(h.outputDir, files[0]))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"compressed":true}` {
		t.Errorf("saved %q, want the decoded JSON", got)
	}
}

func TestPlainHTTPIsProxiedAndSaved(t *testing.T) {
	origin := httptest.NewServer(originHandler())
	defer origin.Close()
	h := newHarness(t, &config.Config{Rules: jsonRules()}, origin)

	if _, body := h.get(t, origin.URL+"/api/v1/users"); body != `{"users":["ada"]}` {
		t.Fatalf("body = %q", body)
	}
	h.waitSaved(t, 1)
}

func TestUnmatchedHostIsTunnelledNotIntercepted(t *testing.T) {
	origin := httptest.NewTLSServer(originHandler())
	defer origin.Close()

	// No rule can match this host, so creel must splice the TLS session
	// through: the client then sees the origin's own certificate.
	h := newHarness(t, &config.Config{Rules: []config.Rule{{Domain: "nowhere.test"}}}, origin)

	pool := x509.NewCertPool()
	pool.AddCert(origin.Certificate())
	h.client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: pool}

	resp, body := h.get(t, origin.URL+"/api/v1/users")
	if resp.StatusCode != http.StatusOK || body != `{"users":["ada"]}` {
		t.Fatalf("status = %d, body = %q", resp.StatusCode, body)
	}
	h.waitSaved(t, 0)
}

func TestMITMAllInterceptsEveryHost(t *testing.T) {
	origin := httptest.NewTLSServer(originHandler())
	defer origin.Close()
	h := newHarness(t, &config.Config{MITMAll: true, Rules: jsonRules()}, origin)

	if _, body := h.get(t, origin.URL+"/api/v1/users"); body != `{"users":["ada"]}` {
		t.Fatalf("body = %q", body)
	}
	h.waitSaved(t, 1)
}

func TestOversizedBodyIsForwardedButNotSaved(t *testing.T) {
	origin := httptest.NewTLSServer(originHandler())
	defer origin.Close()
	h := newHarness(t, &config.Config{MaxBodySize: 1024, Rules: jsonRules()}, origin)

	if _, body := h.get(t, origin.URL+"/api/v1/huge"); len(body) != 4096 {
		t.Fatalf("body length = %d, want 4096", len(body))
	}
	h.waitSaved(t, 0)
}

func TestRequestBodyAndMethodReachOrigin(t *testing.T) {
	origin := httptest.NewTLSServer(originHandler())
	defer origin.Close()
	// Intercepted with no rules: nothing is saved, everything still flows.
	h := newHarness(t, &config.Config{MITMAll: true}, origin)

	resp, err := h.client.Post(origin.URL+"/echo", "text/plain", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "POST payload" {
		t.Errorf("origin saw %q, want %q", body, "POST payload")
	}
}

func TestKeepAliveServesSeveralRequestsPerConnection(t *testing.T) {
	origin := httptest.NewTLSServer(originHandler())
	defer origin.Close()
	h := newHarness(t, &config.Config{Rules: jsonRules()}, origin)

	for i := 0; i < 3; i++ {
		if _, body := h.get(t, origin.URL+"/api/v1/users"); body != `{"users":["ada"]}` {
			t.Fatalf("request %d: body = %q", i, body)
		}
	}
}

func TestDirectRequestIsRejected(t *testing.T) {
	origin := httptest.NewServer(originHandler())
	defer origin.Close()
	h := newHarness(t, &config.Config{Rules: jsonRules()}, origin)

	// Not proxied: a plain request straight to the proxy's own address.
	resp, err := http.Get(h.proxyURL.String() + "/api/v1/users")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}
