package app

import (
	"net/http"
	"path"
	"regexp"
	"strings"
)

var tplinkAssetVersion = regexp.MustCompile(`^[0-9]{8,20}$`)

// Firmware-versioned public assets contain no session data. Keep caches
// private to the browser; dynamic pages and SLP results retain upstream policy.
func cacheTPLinkStatic(resp *http.Response) {
	r := resp.Request
	if r == nil || r.Method != "GET" || resp.StatusCode != 200 || !strings.HasPrefix(r.URL.Path, "/web-static/") || strings.Contains(r.URL.Path, "..") || len(resp.Header.Values("Set-Cookie")) != 0 {
		return
	}
	query := r.URL.Query()
	if len(query) != 1 || len(query["random"]) != 1 || !tplinkAssetVersion.MatchString(query.Get("random")) {
		return
	}
	switch strings.ToLower(path.Ext(r.URL.Path)) {
	case ".js", ".css", ".png", ".gif", ".jpg", ".jpeg", ".ico", ".woff", ".woff2":
		resp.Header.Set("Cache-Control", "private, max-age=86400, immutable")
		resp.Header.Del("Pragma")
		resp.Header.Del("Expires")
	}
}
