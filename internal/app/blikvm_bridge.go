package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/html"
)

var blikvmStoreDefinition = regexp.MustCompile(`\bconst\s+([A-Za-z_$][\w$]*)\s*=\s*[A-Za-z_$][\w$]*\("app",`)
var javascriptIdentifier = regexp.MustCompile(`^[A-Za-z_$][\w$]*$`)

func (a *App) serveBlikvmBridge(w http.ResponseWriter, r *http.Request, s Service, g *gatewaySession) bool {
	if !strings.HasPrefix(r.URL.Path, "/__webconsole/blikvm/") {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	if r.URL.Path == "/__webconsole/blikvm/logout" {
		if r.Method != "POST" || r.Header.Get("Origin") != a.cfg.deviceOrigin(s.Slug) {
			http.Error(w, "请求无效", 403)
			return true
		}
		var body struct {
			CSRF string `json:"csrf"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&body) != nil || !constantEqual(body.CSRF, g.CSRF) {
			http.Error(w, "请求无效", 403)
			return true
		}
		g.authMu.Lock()
		g.Manual = true
		g.Version++
		saveBlikvmSession(&http.Client{Jar: g.Jar}, s, blikvmAuth{})
		g.authMu.Unlock()
		g.disconnect()
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	if r.Method != "GET" {
		w.WriteHeader(405)
		return true
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	switch r.URL.Path {
	case "/__webconsole/blikvm/bootstrap.js":
		auth := blikvmSession(&http.Client{Jar: g.Jar}, s)
		data, _ := json.Marshal(map[string]any{"authenticated": auth.Token != "", "username": auth.Username, "role": auth.Role, "csrf": g.CSRF, "expires": g.Expires.UnixMilli()})
		_, _ = fmt.Fprintf(w, `(()=>{
const session=%s;
window.__webconsoleBlikvm=session;
const remove=Storage.prototype.removeItem, clear=Storage.prototype.clear;
if(session.authenticated){localStorage.setItem('token','%s');localStorage.setItem('sessionExpiration',String(session.expires));}
else{remove.call(localStorage,'token');}
function logout(){session.authenticated=false;fetch('/__webconsole/blikvm/logout',{method:'POST',credentials:'same-origin',keepalive:true,headers:{'Content-Type':'application/json'},body:JSON.stringify({csrf:session.csrf})}).catch(()=>{});}
Storage.prototype.removeItem=function(key){remove.call(this,key);if(this===localStorage&&key==='token')logout();};
Storage.prototype.clear=function(){clear.call(this);if(this===localStorage)logout();};
})();`, data, blikvmBrowserMarker)
	case "/__webconsole/blikvm/app.js":
		module, export := r.URL.Query().Get("module"), r.URL.Query().Get("store")
		if !validBlikvmModule(module) || !javascriptIdentifier.MatchString(export) {
			http.Error(w, "页面模块无效", 400)
			return true
		}
		encoded, _ := json.Marshal(module)
		_, _ = fmt.Fprintf(w, `import{%s as useStore}from %s;
const session=window.__webconsoleBlikvm;
if(session?.authenticated){const store=useStore();store.account.user=session.username;store.account.userRole=session.role;store.loginDialog=false;await store.initializeApp();}
`, export, encoded)
	default:
		http.NotFound(w, r)
	}
	return true
}

func validBlikvmModule(path string) bool {
	u, err := url.Parse(path)
	return err == nil && u.Scheme == "" && u.Host == "" && u.RawQuery == "" && u.Fragment == "" && strings.HasPrefix(u.Path, "/assets/") && strings.HasSuffix(u.Path, ".js") && !strings.ContainsAny(path, "\\\r\n") && !strings.Contains(u.Path, "..")
}

// Replace only the native SPA entry module. Its real Pinia export is read from
// the public bundle, so asset hashes and minified export names are not fixed.
// Bootstrap executes first; the native app then receives account/role state
// while all actual bearer credentials remain on the gateway.
func bridgeBlikvmHTML(resp *http.Response, s Service, g *gatewaySession, transport http.RoundTripper) error {
	if resp.StatusCode != 200 || resp.Request.Method != "GET" || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		return nil
	}
	if resp.Header.Get("Content-Encoding") != "" {
		return &proxyLoginError{errBliProtocol}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	_ = resp.Body.Close()
	if err != nil || len(b) > 1<<20 {
		return &proxyLoginError{errBliProtocol}
	}
	doc, err := html.Parse(bytes.NewReader(b))
	if err != nil {
		return &proxyLoginError{errBliProtocol}
	}
	var head, entry *html.Node
	var src string
	var visit func(*html.Node)
	visit = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "head" {
			head = n
		}
		if n.Type == html.ElementNode && n.Data == "script" && entry == nil {
			var kind, source string
			for _, attr := range n.Attr {
				if attr.Key == "type" {
					kind = attr.Val
				}
				if attr.Key == "src" {
					source = attr.Val
				}
			}
			if kind == "module" && source != "" {
				entry, src = n, source
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(doc)
	if head == nil || entry == nil {
		return &proxyLoginError{errBliProtocol}
	}
	boot := &html.Node{Type: html.ElementNode, Data: "script", Attr: []html.Attribute{{Key: "src", Val: "/__webconsole/blikvm/bootstrap.js"}}}
	head.InsertBefore(boot, head.FirstChild)
	auth := blikvmSession(&http.Client{Jar: g.Jar}, s)
	if auth.Token != "" {
		asset, err := url.Parse(src)
		if err != nil {
			return &proxyLoginError{errBliProtocol}
		}
		target := resp.Request.URL.ResolveReference(asset)
		origin, _ := url.Parse(s.UpstreamURL)
		if !sameDeviceOrigin(target, origin) || !validBlikvmModule(target.RequestURI()) {
			return &proxyLoginError{errBliProtocol}
		}
		public, _ := http.NewRequestWithContext(resp.Request.Context(), "GET", target.String(), nil)
		public.Header.Set("Accept-Encoding", "identity")
		moduleResponse, err := transport.RoundTrip(public)
		if err != nil {
			return connectionError(err)
		}
		code, readErr := io.ReadAll(io.LimitReader(moduleResponse.Body, (2<<20)+1))
		_ = moduleResponse.Body.Close()
		if readErr != nil || len(code) > 2<<20 || moduleResponse.StatusCode != 200 || moduleResponse.Header.Get("Content-Encoding") != "" {
			return &proxyLoginError{errBliProtocol}
		}
		export, err := blikvmStoreExport(code)
		if err != nil {
			return &proxyLoginError{err}
		}
		for i, attr := range entry.Attr {
			if attr.Key == "src" {
				entry.Attr[i].Val = "/__webconsole/blikvm/app.js?" + url.Values{"module": {target.RequestURI()}, "store": {export}}.Encode()
			}
		}
	}
	var output bytes.Buffer
	if html.Render(&output, doc) != nil {
		return &proxyLoginError{errBliProtocol}
	}
	resp.Body = io.NopCloser(bytes.NewReader(output.Bytes()))
	resp.ContentLength = int64(output.Len())
	resp.Header.Set("Content-Length", strconv.Itoa(output.Len()))
	resp.Header.Set("Cache-Control", "no-store")
	resp.Header.Del("ETag")
	resp.Header.Del("Last-Modified")
	return nil
}

func blikvmStoreExport(code []byte) (string, error) {
	store := blikvmStoreDefinition.FindSubmatch(code)
	if len(store) != 2 {
		return "", errBliProtocol
	}
	start := bytes.LastIndex(code, []byte("export{"))
	if start < 0 {
		return "", errBliProtocol
	}
	pattern := regexp.MustCompile(`(?:\{|,)\s*` + regexp.QuoteMeta(string(store[1])) + `\s+as\s+([A-Za-z_$][\w$]*)\s*(?:,|\})`)
	match := pattern.FindSubmatch(code[start:])
	if len(match) != 2 {
		return "", errBliProtocol
	}
	return string(match[1]), nil
}
