package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"strings"
)

// decodeBody undoes the Content-Encoding of a captured body so the saved file
// holds the real content. Encodings the standard library cannot decode, such
// as br and zstd, are returned untouched.
func decodeBody(encoding string, body []byte) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return body, nil
	case "gzip", "x-gzip":
		r, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return io.ReadAll(r)
	case "deflate":
		// Servers disagree on whether "deflate" means zlib or raw deflate.
		if r, err := zlib.NewReader(bytes.NewReader(body)); err == nil {
			defer r.Close()
			if out, err := io.ReadAll(r); err == nil {
				return out, nil
			}
		}
		return io.ReadAll(flate.NewReader(bytes.NewReader(body)))
	default:
		return body, nil
	}
}
