package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/net/html"
)

func (a *App) serveNativeBridge(w http.ResponseWriter, r *http.Request, s Service, g *gatewaySession) bool {
	if !strings.HasPrefix(r.URL.Path, "/__webconsole/native/") {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	if r.URL.Path == "/__webconsole/native/logout" {
		var input struct {
			CSRF string `json:"csrf"`
		}
		if r.Method != "POST" || r.Header.Get("Origin") != a.cfg.deviceOrigin(s.Slug) || json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&input) != nil || !constantEqual(input.CSRF, g.CSRF) {
			http.Error(w, "请求无效", 403)
			return true
		}
		g.authMu.Lock()
		g.Manual = true
		g.Version++
		clearNativeSession(&http.Client{Jar: g.Jar}, s)
		g.authMu.Unlock()
		g.disconnect()
		w.WriteHeader(204)
		return true
	}
	if r.URL.Path != "/__webconsole/native/bootstrap.js" {
		http.NotFound(w, r)
		return true
	}
	if r.Method != "GET" {
		w.WriteHeader(405)
		return true
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	g.authMu.Lock()
	auth := nativeSession(&http.Client{Jar: g.Jar}, s)
	config, _ := json.Marshal(map[string]any{"kind": s.Type, "authenticated": auth.Token != "", "csrf": g.CSRF, "generation": g.Version, "expires": g.Expires.Format(http.TimeFormat)})
	g.authMu.Unlock()
	_, _ = fmt.Fprintf(w, `(()=>{
const config=%s, marker=%q;
const remove=Storage.prototype.removeItem;
function cookie(name,value){document.cookie=name+'='+encodeURIComponent(value)+';path=/;SameSite=Strict;expires='+config.expires+(location.protocol==='https:'?';Secure':'');}
function logout(){config.authenticated=false;cookie('wc_native_manual',config.csrf);fetch('/__webconsole/native/logout',{method:'POST',credentials:'same-origin',keepalive:true,headers:{'Content-Type':'application/json'},body:JSON.stringify({csrf:config.csrf})}).catch(()=>{});}
if(config.kind==='glinet'){
 if(config.authenticated){localStorage.setItem('gl-kvm-token-keys',JSON.stringify({glkvm:marker}));localStorage.setItem('gl-kvm-token-key',marker);cookie('auth_token',marker);}
 else{remove.call(localStorage,'gl-kvm-token-keys');remove.call(localStorage,'gl-kvm-token-key');document.cookie='auth_token=;path=/;expires=Thu, 01 Jan 1970 00:00:00 GMT';}
}
if(config.kind==='pve'){
 remove.call(localStorage,'ProxmoxUser');
 if(config.authenticated)cookie('PVEAuthCookie',marker);else document.cookie='PVEAuthCookie=;path=/;expires=Thu, 01 Jan 1970 00:00:00 GMT';
 let proto=document,desc;while(proto&&!desc){desc=Object.getOwnPropertyDescriptor(proto,'cookie');proto=Object.getPrototypeOf(proto);}
 if(desc?.get&&desc?.set){Object.defineProperty(document,'cookie',{configurable:true,get(){return desc.get.call(document);},set(value){desc.set.call(document,value);if(/^PVEAuthCookie=;/i.test(value))logout();}});}
}
if(config.kind==='tplink'){
 if(config.authenticated)localStorage.setItem('token',marker);else remove.call(localStorage,'token');
 Storage.prototype.removeItem=function(key){remove.call(this,key);if(this===localStorage&&key==='token')logout();};
}
if(config.kind==='esxi'){
 let state={};try{state=JSON.parse(localStorage.getItem('vmware_esx_host_state')||'{}')||{};}catch{}
 const host=location.hostname+':'+(location.port||(location.protocol==='https:'?'443':'80'));
 const session=config.csrf+':'+config.generation;
 if(state.webconsoleSession!==session){state.filters=[];state.longpoll_version='';}
 state.webconsoleSession=session;
 state.vmware_esx_host=host;state.hostname=location.hostname;state.csrf_token=marker;
 localStorage.setItem('vmware_esx_host_state',JSON.stringify(state));cookie('vmware_esx_host',host);
}
})();`, config, nativeBrowserMarker)
	return true
}

func (a *App) prepareNativePage(r *http.Request, s Service, g *gatewaySession) error {
	g.authMu.Lock()
	if !g.Manual {
		g.authMu.Unlock()
		return a.ensureLogin(r.Context(), s, g, nil)
	}
	defer g.authMu.Unlock()
	c, err := clientFor(s, g)
	if err != nil {
		return err
	}
	defer c.Transport.(*http.Transport).CloseIdleConnections()
	err = adapterFor(s.Type).Check(r.Context(), c, s)
	if err == errNeedsLogin {
		clearNativeSession(c, s)
		return nil
	}
	if err != nil {
		logDeviceFailure(a.log, "device session check failed", s, "manual_session_check", err)
	}
	return err
}

func nativeEntryRedirect(s Service, r *http.Request) bool {
	switch s.Type {
	case "tplink":
		return r.URL.Path == "/login.htm" || r.URL.Path == "/mobile_login.htm"
	case "xiaomi":
		return r.URL.Path == "/" || r.URL.Path == "/cgi-bin/luci/web" || r.URL.Path == "/cgi-bin/luci/web/home"
	case "esxi":
		return r.URL.Path == "/"
	}
	return false
}

func manualEntry(s Service) string {
	switch s.Type {
	case "blikvm":
		return "/"
	case "tplink":
		return "/login.htm"
	case "xiaomi":
		return "/cgi-bin/luci/web"
	default:
		return s.EntryPath
	}
}

func bridgeNativeResponse(resp *http.Response, s Service, g *gatewaySession) error {
	if resp.StatusCode != 200 {
		return nil
	}
	contentType := resp.Header.Get("Content-Type")
	isHTML := strings.HasPrefix(contentType, "text/html")
	isDocument := isHTML && resp.Request.Method == "GET" && documentNavigation(resp.Request)
	mask := s.Type == "xiaomi" && (isHTML || strings.Contains(contentType, "javascript") || strings.Contains(contentType, "json"))
	if !isDocument && !mask {
		return nil
	}
	if resp.Header.Get("Content-Encoding") != "" {
		return &proxyLoginError{errNativeProtocol}
	}
	b := responsePrefix(resp, (4<<20)+1)
	if len(b) > 4<<20 {
		return nil
	}
	auth := nativeSession(&http.Client{Jar: g.Jar}, s)
	if mask && auth.Token != "" {
		b = bytes.ReplaceAll(b, []byte(auth.Token), []byte(nativeBrowserMarker))
	}
	if isDocument {
		doc, err := html.Parse(bytes.NewReader(b))
		if err != nil {
			return &proxyLoginError{errNativeProtocol}
		}
		var head *html.Node
		var visit func(*html.Node)
		visit = func(n *html.Node) {
			if n.Type == html.ElementNode && n.Data == "head" {
				head = n
			}
			for child := n.FirstChild; child != nil; child = child.NextSibling {
				visit(child)
			}
		}
		visit(doc)
		if head != nil {
			head.InsertBefore(&html.Node{Type: html.ElementNode, Data: "script", Attr: []html.Attribute{{Key: "src", Val: "/__webconsole/native/bootstrap.js"}}}, head.FirstChild)
			var output bytes.Buffer
			if html.Render(&output, doc) != nil {
				return &proxyLoginError{errNativeProtocol}
			}
			b = output.Bytes()
		}
	}
	replaceResponseBody(resp, b)
	return nil
}

func nativeRedirectLocation(value string, s Service, g *gatewaySession) string {
	auth := nativeSession(&http.Client{Jar: g.Jar}, s)
	if auth.Token != "" && (s.Type == "tplink" || s.Type == "xiaomi") {
		value = strings.ReplaceAll(value, auth.Token, nativeBrowserMarker)
	}
	return value
}

func (a *App) ensureESXiCSRF(s Service, g *gatewaySession) {
	if s.Type != "esxi" {
		return
	}
	g.authMu.Lock()
	defer g.authMu.Unlock()
	c := &http.Client{Jar: g.Jar}
	auth := nativeSession(c, s)
	if auth.CSRF == "" {
		auth.CSRF = token()
		saveNativeSession(c, s, auth)
	}
}

func (a *App) consumeNativeLogoutMarker(w http.ResponseWriter, r *http.Request, s Service, g *gatewaySession) {
	if r.Method != "GET" || !documentNavigation(r) {
		return
	}
	marker, err := r.Cookie("wc_native_manual")
	if err != nil || !constantEqual(marker.Value, g.CSRF) {
		return
	}
	g.authMu.Lock()
	g.Manual = true
	g.Version++
	clearNativeSession(&http.Client{Jar: g.Jar}, s)
	g.authMu.Unlock()
	g.disconnect()
	http.SetCookie(w, &http.Cookie{Name: "wc_native_manual", Path: "/", MaxAge: -1, Secure: !a.cfg.DevHTTP, SameSite: http.SameSiteStrictMode})
}

func nativeGatewayCookies(header http.Header, s Service, devHTTP bool) {
	cookies := (&http.Response{Header: header}).Cookies()
	header.Del("Set-Cookie")
	for _, cookie := range cookies {
		if s.Type == "glinet" && cookie.Name == "auth_token" {
			cookie.Value = nativeBrowserMarker
			cookie.HttpOnly = false
		}
		if s.Type == "esxi" && cookie.Name == "vmware_soap_session" {
			continue
		}
		if s.Type == "pve" && cookie.Name == "PVEAuthCookie" && !pveChallenge(cookie.Value) {
			cookie.Value = nativeBrowserMarker
			cookie.HttpOnly = false
		}
		cookie.Domain = ""
		cookie.Secure = !devHTTP
		header.Add("Set-Cookie", cookie.String())
	}
}
