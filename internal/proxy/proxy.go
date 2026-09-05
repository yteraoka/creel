// Package proxy implements the HTTP forward proxy, including TLS interception
// for the hosts the configuration cares about.
package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/yteraoka/creel/internal/ca"
	"github.com/yteraoka/creel/internal/config"
	"github.com/yteraoka/creel/internal/store"
)

// hopByHop headers are consumed by the proxy and never forwarded.
var hopByHop = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// Proxy serves proxy requests on behalf of clients.
type Proxy struct {
	cfg       *config.Config
	ca        *ca.CA
	store     *store.Store
	log       *slog.Logger
	transport *http.Transport
	dialer    *net.Dialer
}

// New returns a Proxy using cfg, signing intercepted connections with root and
// saving matched bodies through st.
func New(cfg *config.Config, root *ca.CA, st *store.Store, log *slog.Logger) *Proxy {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	return &Proxy{
		cfg:    cfg,
		ca:     root,
		store:  st,
		log:    log,
		dialer: dialer,
		transport: &http.Transport{
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   15 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			// Pass the client's Accept-Encoding through untouched; any
			// compression is undone only for the copy we save.
			DisableCompression: true,
		},
	}
}

// SetUpstreamTLSConfig replaces the TLS settings used when connecting to
// origin servers. Call it before serving starts.
func (p *Proxy) SetUpstreamTLSConfig(c *tls.Config) {
	p.transport.TLSClientConfig = c
}

// ServeHTTP handles one proxied request: CONNECT sets up a tunnel, anything
// else is a plain HTTP forward.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	if !r.URL.IsAbs() {
		http.Error(w, "creel is a forward proxy; configure it as your client's HTTP proxy", http.StatusBadRequest)
		return
	}
	p.forward(w, r)
}

// handleConnect either intercepts the TLS session or splices bytes through
// untouched when no rule could ever match the host.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	intercept := p.cfg.MITMAll || p.cfg.MatchesDomain(hostWithoutPort(host))

	clientConn, err := hijack(w)
	if err != nil {
		p.log.Error("hijack failed", "host", host, "err", err)
		http.Error(w, "proxy cannot hijack this connection", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	if !intercept {
		p.tunnel(clientConn, host)
		return
	}

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	tlsConn := tls.Server(clientConn, p.ca.TLSConfig(host))
	if err := tlsConn.Handshake(); err != nil {
		p.log.Debug("tls handshake with client failed", "host", host, "err", err)
		return
	}

	authority := strings.TrimSuffix(host, ":443")
	p.serveConn(tlsConn, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Scheme = "https"
		r.URL.Host = authority
		if r.Host == "" {
			r.Host = authority
		}
		p.forward(w, r)
	}))
}

// tunnel connects to host and copies bytes in both directions.
func (p *Proxy) tunnel(clientConn net.Conn, host string) {
	upstream, err := p.dialer.Dial("tcp", withPort(host, "443"))
	if err != nil {
		p.log.Warn("tunnel dial failed", "host", host, "err", err)
		_, _ = fmt.Fprintf(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer upstream.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	splice(clientConn, upstream)
}

// forward performs the upstream request and streams the response back,
// keeping a copy of the body when a rule matches.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request) {
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	outReq.Header = r.Header.Clone()
	stripHopByHop(outReq.Header)

	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		p.log.Warn("upstream request failed", "url", r.URL.String(), "err", err)
		http.Error(w, "creel: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusSwitchingProtocols {
		p.forwardUpgrade(w, resp)
		return
	}

	// The body has not arrived yet, so any size condition is settled later,
	// in save.
	rule := p.cfg.Match(hostWithoutPort(r.URL.Host), r.URL.Path,
		contentTypeOf(resp.Header), config.SizeUnknown)

	respHeader := w.Header()
	for k, vs := range resp.Header {
		respHeader[k] = append([]string(nil), vs...)
	}
	stripHopByHop(respHeader)
	w.WriteHeader(resp.StatusCode)

	var body io.Reader = resp.Body
	var capture *capturingReader
	if rule != nil {
		capture = &capturingReader{r: resp.Body, limit: p.cfg.MaxBodySize}
		body = capture
	}
	if _, err := io.Copy(&flushWriter{w: w}, body); err != nil {
		p.log.Debug("response copy interrupted", "url", r.URL.String(), "err", err)
		return
	}
	copyTrailers(w, resp)

	if capture == nil {
		return
	}
	if capture.truncated {
		p.log.Warn("body too large to save",
			"url", r.URL.String(), "max_body_size", p.cfg.MaxBodySize)
		return
	}
	p.save(r, resp, capture.buf)
}

// save decodes a captured body and writes it, unless the size the rules ask
// for rules it out.
func (p *Proxy) save(r *http.Request, resp *http.Response, body []byte) {
	decoded, err := decodeBody(resp.Header.Get("Content-Encoding"), body)
	if err != nil {
		p.log.Warn("cannot decode body, saving as received",
			"url", r.URL.String(), "encoding", resp.Header.Get("Content-Encoding"), "err", err)
		decoded = body
	}

	// Now that the size is known, a min_size can rule this rule out and let
	// another one take the response.
	rule := p.cfg.Match(hostWithoutPort(r.URL.Host), r.URL.Path,
		contentTypeOf(resp.Header), int64(len(decoded)))
	if rule == nil {
		p.log.Debug("body smaller than min_size, not saving",
			"url", r.URL.String(), "bytes", len(decoded))
		return
	}

	name, err := p.store.Save(hostWithoutPort(r.URL.Host), r.URL.Path, r.URL.RawQuery,
		contentTypeOf(resp.Header), decoded)
	if err != nil {
		p.log.Error("save failed", "url", r.URL.String(), "err", err)
		return
	}
	if name == "" {
		p.log.Debug("kept existing file", "url", r.URL.String())
		return
	}
	p.log.Info("saved",
		"url", r.URL.String(),
		"rule", ruleName(rule),
		"content_type", contentTypeOf(resp.Header),
		"bytes", len(decoded),
		"file", name)
}

// forwardUpgrade splices the connection after a 101 response so protocol
// upgrades such as WebSocket keep working.
func (p *Proxy) forwardUpgrade(w http.ResponseWriter, resp *http.Response) {
	upstream, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		http.Error(w, "creel: upstream upgrade not supported", http.StatusBadGateway)
		return
	}
	clientConn, err := hijack(w)
	if err != nil {
		http.Error(w, "creel: cannot hijack for upgrade", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// resp.Write would try to copy the body, which for a 101 is the
	// connection itself, so write the head by hand.
	if _, err := fmt.Fprintf(clientConn, "HTTP/1.1 %s\r\n", resp.Status); err != nil {
		return
	}
	if err := resp.Header.Write(clientConn); err != nil {
		return
	}
	if _, err := clientConn.Write([]byte("\r\n")); err != nil {
		return
	}
	splice(clientConn, upstream)
}

// serveConn runs an HTTP server over a single already-established connection.
func (p *Proxy) serveConn(conn net.Conn, h http.Handler) {
	ln := newSingleConnListener(conn)
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       90 * time.Second,
		ErrorLog:          slog.NewLogLogger(p.log.Handler(), slog.LevelDebug),
	}
	_ = srv.Serve(ln)
}

// capturingReader passes bytes through while keeping a copy, giving up once
// the copy would exceed limit.
type capturingReader struct {
	r         io.Reader
	limit     int64
	buf       []byte
	truncated bool
}

func (c *capturingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 && !c.truncated {
		if int64(len(c.buf))+int64(n) > c.limit {
			c.truncated = true
			c.buf = nil
		} else {
			c.buf = append(c.buf, p[:n]...)
		}
	}
	return n, err
}

// flushWriter pushes each chunk to the client so streamed responses are not
// held back by the proxy.
type flushWriter struct{ w http.ResponseWriter }

func (f *flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if flusher, ok := f.w.(http.Flusher); ok {
		flusher.Flush()
	}
	return n, err
}

func hijack(w http.ResponseWriter) (net.Conn, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("ResponseWriter does not support hijacking")
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	if buf.Reader.Buffered() > 0 {
		// Data the server already read on behalf of the next request must
		// not be lost; put it back in front of the connection.
		pending := make([]byte, buf.Reader.Buffered())
		if _, err := io.ReadFull(buf.Reader, pending); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return &prefixConn{Conn: conn, pending: pending}, nil
	}
	return conn, nil
}

// splice copies between two connections until either side is done.
func splice(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		closeWrite(b)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		closeWrite(a)
	}()
	wg.Wait()
}

func closeWrite(c io.Closer) {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

func stripHopByHop(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopByHop {
		h.Del(name)
	}
}

func copyTrailers(w http.ResponseWriter, resp *http.Response) {
	for k, vs := range resp.Trailer {
		for _, v := range vs {
			w.Header().Add(http.TrailerPrefix+k, v)
		}
	}
}

// contentTypeOf returns the media type without its parameters.
func contentTypeOf(h http.Header) string {
	ct := h.Get("Content-Type")
	if ct == "" {
		return ""
	}
	if mt, _, err := mime.ParseMediaType(ct); err == nil {
		return mt
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		return strings.TrimSpace(ct[:i])
	}
	return strings.TrimSpace(ct)
}

func ruleName(r *config.Rule) string {
	if r.Name != "" {
		return r.Name
	}
	return strings.TrimSpace(r.Domain + " " + r.Path)
}

// hostWithoutPort drops the port from an authority, handling IPv6 literals.
func hostWithoutPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return strings.Trim(host, "[]")
}

// withPort adds a default port when the authority has none.
func withPort(host, port string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), port)
}
