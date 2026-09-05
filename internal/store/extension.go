package store

import (
	"mime"
	"path/filepath"
	"sort"
	"strings"
)

// preferredExt pins the extension for the types that appear most often, both
// because mime.ExtensionsByType picks odd ones for some of them (".jpe" for
// image/jpeg) and because its answers depend on the system's mime.types
// files, which differ between machines.
var preferredExt = map[string]string{
	"application/javascript":   ".js",
	"application/json":         ".json",
	"application/pdf":          ".pdf",
	"application/xhtml+xml":    ".xhtml",
	"application/xml":          ".xml",
	"application/zip":          ".zip",
	"image/avif":               ".avif",
	"image/gif":                ".gif",
	"image/jpeg":               ".jpg",
	"image/png":                ".png",
	"image/svg+xml":            ".svg",
	"image/webp":               ".webp",
	"text/css":                 ".css",
	"text/csv":                 ".csv",
	"text/html":                ".html",
	"text/javascript":          ".js",
	"text/plain":               ".txt",
	"text/xml":                 ".xml",
	"application/octet-stream": "",
}

// extensionFor returns the extension to append to name for a response of the
// given content type, or "" when name already carries a fitting one or the
// type has no known extension.
func extensionFor(contentType, name string) string {
	contentType = strings.ToLower(strings.TrimSpace(contentType))
	if contentType == "" {
		return ""
	}

	want, known := preferredExt[contentType]
	if !known {
		want = lookupExt(contentType)
	}
	if want == "" {
		return ""
	}

	// Leave a name that already says what it holds alone, accepting any of
	// the type's extensions: /a.htm stays /a.htm for text/html.
	have := strings.ToLower(filepath.Ext(name))
	if have == want {
		return ""
	}
	for _, alt := range candidates(contentType) {
		if have == alt {
			return ""
		}
	}
	return want
}

// lookupExt asks the mime package, falling back to the structured suffix of
// types such as application/vnd.api+json.
func lookupExt(contentType string) string {
	if exts := candidates(contentType); len(exts) > 0 {
		return exts[0]
	}
	if i := strings.LastIndex(contentType, "+"); i >= 0 {
		if ext := "." + contentType[i+1:]; ext != "." {
			return ext
		}
	}
	return ""
}

// candidates lists the extensions registered for a content type, in a stable
// order.
func candidates(contentType string) []string {
	exts, err := mime.ExtensionsByType(contentType)
	if err != nil || len(exts) == 0 {
		return nil
	}
	for i, e := range exts {
		exts[i] = strings.ToLower(e)
	}
	sort.Strings(exts)
	return exts
}
