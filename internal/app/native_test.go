package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

const slpSalt = "RDpbLfCPsJZ7fiv"
const slpAlphabet = "yLwVl0zKqws7LgKPRQ84Mdt708T1qQ3Ha7xv3H7NyU84p21BriUWBU43odz3iP4rBL3cD02KZciXTysVXiV8ngg6vL48rPJyAUw0HurW20xqxv9aYb4M9wK1Ae0wlro510qXeU07kV57fQMc8L6aLgMLwygtc0F10a0Dg70TOoouyFhdysuRMO51yY5ZlOZZLEal1h0t9YQW0Ko7oBwmCAHoic4HYbUyVeU3sfQ1xtXcPcf1aT303wAQhv66qzW"
const miFixtureKey = "a2ffa5c9be07488bbb04a3a47d3c5f6a"

type fakeNative struct {
	server                       *httptest.Server
	kind                         string
	generation, logins, controls atomic.Int32
	interactive                  atomic.Bool
	variablePassword             bool
}

func (f *fakeNative) authToken() string {
	if f.kind == "pve" {
		return fmt.Sprintf("PVE:root@pam:000::signature%d", f.generation.Load())
	}
	return fmt.Sprintf("%032x", f.generation.Load())
}
func soapReply(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/xml")
	_, _ = io.WriteString(w, `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body>`+body+`</soapenv:Body></soapenv:Envelope>`)
}
func (f *fakeNative) deny(w http.ResponseWriter) {
	switch f.kind {
	case "esxi":
		w.WriteHeader(500)
		soapReply(w, `<soapenv:Fault><detail><NotAuthenticatedFault/></detail></soapenv:Fault>`)
	case "tplink":
		jsonReply(w, 401, map[string]int{"error_code": -40401})
	case "xiaomi":
		jsonReply(w, 200, map[string]int{"code": 401})
	default:
		w.WriteHeader(401)
	}
}
func newNative(t *testing.T, kind string) *fakeNative {
	t.Helper()
	f := &fakeNative{kind: kind}
	f.generation.Store(1)
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, cookie := range r.Cookies() {
			if internalCookie(cookie.Name) {
				t.Error("internal cookie reached a device")
			}
		}
		if r.Method == "GET" && (r.URL.Path == "/" || r.URL.Path == "/ui/" || r.URL.Path == "/login.htm" || r.URL.Path == "/cgi-bin/luci/web" || strings.Contains(r.URL.Path, "/web/home")) {
			w.Header().Set("Content-Type", "text/html")
			if kind == "tplink" && r.URL.Path == "/login.htm" {
				_, _ = io.WriteString(w, `<html><head><meta data-interface-type="SLP"></head><body>orgAuthPwd</body></html>`)
				return
			}
			if kind == "xiaomi" && r.URL.Path == "/cgi-bin/luci/web" {
				_, _ = io.WriteString(w, `<html><script>var newEncryptMode=parseInt('1');var Encrypt={key:'`+miFixtureKey+`'};var deviceId='00:e0:4c:68:00:4d';var login='/cgi-bin/luci/api/xqsystem/login';</script></html>`)
				return
			}
			_, _ = io.WriteString(w, `<html><head></head><body>native dashboard</body></html>`)
			return
		}
		if r.URL.Path == "/web-static/js/su/su.js" {
			if f.variablePassword {
				_, _ = fmt.Fprintf(w, `$.su.orgAuthPwd = function(pwd) { var strDe = %q; var dic = %q + %q; return this.securityEncode(pwd, strDe, dic); };`, slpSalt, slpAlphabet[:100], slpAlphabet[100:])
				return
			}
			_, _ = io.WriteString(w, `a.su.orgAuthPwd=function(a){return this.securityEncode(a,"`+slpSalt+`","`+slpAlphabet+`")};`)
			return
		}
		if r.URL.Path == "/sdk/vimServiceVersions.xml" {
			_, _ = io.WriteString(w, `<namespaces><namespace><name>urn:vim25</name><version>8.0.3.0</version></namespace></namespaces>`)
			return
		}
		var data map[string]json.RawMessage
		var method string
		var root *soapNode
		operation := ""
		if kind == "esxi" {
			b, _ := io.ReadAll(r.Body)
			root, _ = decodeSOAP(b)
			if root != nil {
				operation = root.child("Body").Children[0].Name
			}
		}
		if kind == "tplink" {
			_ = json.NewDecoder(r.Body).Decode(&data)
			_ = json.Unmarshal(data["method"], &method)
		}
		if kind == "esxi" && operation == "RetrieveServiceContent" {
			soapReply(w, `<RetrieveServiceContentResponse><returnval><sessionManager>ha-sessionmgr</sessionManager><propertyCollector>ha-property-collector</propertyCollector><about><apiVersion>8.0.3.0</apiVersion></about></returnval></RetrieveServiceContentResponse>`)
			return
		}
		login := kind == "pve" && pveLoginPath(r.URL.Path) || kind == "esxi" && operation == "Login" || kind == "tplink" && r.URL.Path == "/" && data["login"] != nil || kind == "xiaomi" && r.URL.Path == "/cgi-bin/luci/api/xqsystem/login"
		if login {
			f.logins.Add(1)
			valid := false
			switch kind {
			case "pve":
				_ = r.ParseForm()
				valid = r.Form.Get("username") == "root@pam" && (r.Form.Get("password") == "fixture-password" || r.Form.Get("password") == f.authToken())
			case "esxi":
				valid = root.value("userName") == "root" && root.value("password") == "fixture-password" && r.Header.Get("VMware-CSRF-Token") != ""
			case "tplink":
				var input map[string]string
				_ = json.Unmarshal(data["login"], &input)
				valid = input["username"] == "admin" && input["password"] == tplinkPassword("fixture-password", slpSalt, slpAlphabet)
			case "xiaomi":
				_ = r.ParseForm()
				valid = r.Form.Get("username") == "admin" && r.Form.Get("password") == xiaomiPassword("fixture-password", miFixtureKey, r.Form.Get("nonce"), true) && r.Form.Get("logtype") == "2"
			}
			if !valid {
				f.deny(w)
				return
			}
			if f.interactive.Load() {
				if kind == "pve" {
					jsonReply(w, 200, map[string]any{"data": map[string]string{"ticket": "PVE:!tfa!challenge", "username": "root@pam", "CSRFPreventionToken": "csrf"}})
				} else {
					jsonReply(w, 200, map[string]int{"error_code": -40402})
				}
				return
			}
			switch kind {
			case "pve":
				jsonReply(w, 200, map[string]any{"data": map[string]string{"ticket": f.authToken(), "username": "root@pam", "CSRFPreventionToken": "csrf"}})
			case "esxi":
				http.SetCookie(w, &http.Cookie{Name: "vmware_soap_session", Value: f.authToken(), Path: "/", HttpOnly: true})
				soapReply(w, `<LoginResponse><returnval><key>`+f.authToken()+`</key><userName>root</userName></returnval></LoginResponse>`)
			case "tplink":
				jsonReply(w, 200, map[string]any{"error_code": 0, "stok": f.authToken()})
			case "xiaomi":
				jsonReply(w, 200, map[string]any{"code": 0, "token": f.authToken(), "url": "/cgi-bin/luci/;stok=" + f.authToken() + "/web/home"})
			}
			return
		}
		read := r.Method == "GET" || kind == "esxi" && (operation == "RetrievePropertiesEx" || operation == "RetrieveProperties") || kind == "tplink" && method == "get"
		if !read {
			f.controls.Add(1)
		}
		valid := false
		switch kind {
		case "pve":
			c, e := r.Cookie("PVEAuthCookie")
			valid = e == nil && c.Value == f.authToken()
		case "esxi":
			c, e := r.Cookie("vmware_soap_session")
			valid = e == nil && c.Value == f.authToken() && r.Header.Get("VMware-CSRF-Token") != ""
		case "tplink":
			valid = strings.HasPrefix(r.URL.Path, "/stok="+f.authToken()+"/")
		case "xiaomi":
			valid = strings.HasPrefix(r.URL.Path, "/cgi-bin/luci/;stok="+f.authToken()+"/")
		}
		if !valid {
			f.deny(w)
			return
		}
		if kind == "esxi" {
			soapReply(w, `<RetrievePropertiesExResponse><returnval><objects><propSet><name>currentSession</name><val><key>`+f.authToken()+`</key><userName>root</userName></val></propSet></objects></returnval></RetrievePropertiesExResponse>`)
		} else if kind == "tplink" {
			jsonReply(w, 200, map[string]any{"error_code": 0, "firmware": map[string]any{"config": map[string]string{"model": "TL-R479G+"}}})
		} else {
			jsonReply(w, 200, map[string]any{"code": 0, "data": map[string]string{"value": "state"}})
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}
func addNative(t *testing.T, a *App, f *fakeNative, slug string) Service {
	t.Helper()
	s := Service{ID: token(), Slug: slug, Name: slug, Type: f.kind, UpstreamURL: f.server.URL}
	if err := validateService(&s, a.cfg); err != nil {
		t.Fatal(err)
	}
	user := "admin"
	if f.kind == "pve" {
		user = "root@pam"
	}
	if f.kind == "esxi" {
		user = "root"
	}
	if err := a.store.SaveWithCredentials(context.Background(), s, &Credentials{user, "fixture-password"}); err != nil {
		t.Fatal(err)
	}
	return s
}
func soapRequest(operation string) string {
	return `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><` + operation + ` xmlns="urn:vim25"><_this type="PropertyCollector">ha-property-collector</_this></` + operation + `></soapenv:Body></soapenv:Envelope>`
}
func nativeRead(a *App, s Service, g *gatewaySession, unsafe bool) *httptest.ResponseRecorder {
	method, path, body := "GET", "/api2/json/access/permissions", ""
	switch s.Type {
	case "esxi":
		method, path, body = "POST", "/sdk/", soapRequest("RetrievePropertiesEx")
		if unsafe {
			body = soapRequest("PowerOffVM_Task")
		}
	case "tplink":
		method, path, body = "POST", "/stok="+nativeBrowserMarker+"/ds", `{"method":"get","firmware":{"name":"config"}}`
		if unsafe {
			body = `{"method":"set","system":{"reboot":null}}`
		}
	case "xiaomi":
		path = "/cgi-bin/luci/;stok=" + nativeBrowserMarker + "/api/xqsystem/status"
		if unsafe {
			method, body = "POST", `{"setting":"changed"}`
		}
	case "pve":
		if unsafe {
			method, body = "POST", `{"setting":"changed"}`
		}
	}
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	return gatewayRequest(a, s, g, method, path, reader)
}
func TestNativeConcurrentRecoveryAndNoUnsafeReplay(t *testing.T) {
	for _, kind := range []string{"pve", "esxi", "tplink", "xiaomi"} {
		t.Run(kind, func(t *testing.T) {
			a := testApp(t)
			f := newNative(t, kind)
			s := addNative(t, a, f, kind)
			p, _ := owner(a)
			g := enter(t, a, p, s)
			f.generation.Add(1)
			before := f.logins.Load()
			var wg sync.WaitGroup
			for range 8 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if got := nativeRead(a, s, g, false); got.Code != 200 {
						t.Errorf("native recovery failed: %d", got.Code)
					}
				}()
			}
			wg.Wait()
			if f.logins.Load() != before+1 {
				t.Fatal("refresh not merged")
			}
			f.generation.Add(1)
			before = f.logins.Load()
			got := nativeRead(a, s, g, true)
			if got.Header().Get("X-WebConsole-Session-Expired") != "true" || f.logins.Load() != before || f.controls.Load() != 1 {
				t.Fatal("native mutation was replayed")
			}
			page := blikvmDocument(a, s, g, s.EntryPath)
			if page.Code != 200 || !strings.Contains(page.Body.String(), "/__webconsole/native/bootstrap.js") {
				t.Fatal("native page bootstrap missing", page.Code)
			}
			boot := gatewayRequest(a, s, g, "GET", "/__webconsole/native/bootstrap.js", nil)
			if boot.Code != 200 || strings.Contains(boot.Body.String(), f.authToken()) || boot.Header().Get("Cross-Origin-Resource-Policy") != "same-origin" {
				t.Fatal("browser bootstrap leaked auth")
			}
			other := s
			other.ID = token()
			other.Slug = "other"
			if err := a.store.SaveWithCredentials(context.Background(), other, nil); err != nil {
				t.Fatal(err)
			}
			if gatewayRequest(a, other, g, "GET", "/api", nil).Code != 401 {
				t.Fatal("device isolation broken")
			}
		})
	}
}

func TestNativeManualLoginAndTicketRenewal(t *testing.T) {
	for _, kind := range []string{"pve", "esxi", "tplink", "xiaomi"} {
		t.Run(kind, func(t *testing.T) {
			a := testApp(t)
			f := newNative(t, kind)
			s := addNative(t, a, f, kind)
			p, _ := owner(a)
			g := enter(t, a, p, s)
			path, body, contentType := "/api2/json/access/ticket", "username=root%40pam&password="+nativeBrowserMarker, "application/x-www-form-urlencoded"
			if kind == "esxi" {
				path = "/sdk/"
				body = soapRequest("RetrievePropertiesEx")
				contentType = "text/xml"
			}
			if kind == "tplink" {
				path = "/"
				payload, _ := json.Marshal(map[string]any{"method": "do", "login": map[string]string{"username": "admin", "password": tplinkPassword("fixture-password", slpSalt, slpAlphabet)}})
				body = string(payload)
				contentType = "application/json"
			}
			if kind == "xiaomi" {
				path = "/cgi-bin/luci/api/xqsystem/login"
				nonce := "0_00:e0:4c:68:00:4d_1700000000_1234"
				body = "username=admin&logtype=2&nonce=" + nonce + "&password=" + xiaomiPassword("fixture-password", miFixtureKey, nonce, true)
				contentType = "application/x-www-form-urlencoded"
			}
			got := blikvmSubmit(a, s, g, path, body, contentType)
			if got.Code != 200 || strings.Contains(got.Body.String(), f.authToken()) || strings.Contains(got.Header().Get("Set-Cookie"), f.authToken()) {
				t.Fatal("native auth response leaked session", got.Code)
			}
			if !strings.Contains(got.Body.String(), nativeBrowserMarker) {
				t.Fatal("native session placeholder missing")
			}
			before := f.logins.Load()
			g.authMu.Lock()
			g.Manual = true
			clearNativeSession(&http.Client{Jar: g.Jar}, s)
			g.authMu.Unlock()
			page := blikvmDocument(a, s, g, manualEntry(s))
			if page.Code != 200 || f.logins.Load() != before {
				t.Fatal("manual page resubmitted stored credentials")
			}
		})
	}
}

func TestNativeBrowserFixtures(t *testing.T) {
	path := os.Getenv("WEBCONSOLE_NATIVE_BROWSER_FIXTURE")
	if path == "" {
		t.Skip("optional browser fixture export")
	}
	fixtures := map[string]string{}
	for _, kind := range []string{"pve", "esxi", "tplink", "xiaomi"} {
		a := testApp(t)
		f := newNative(t, kind)
		s := addNative(t, a, f, kind)
		p, _ := owner(a)
		g := enter(t, a, p, s)
		boot := gatewayRequest(a, s, g, "GET", "/__webconsole/native/bootstrap.js", nil)
		if boot.Code != 200 {
			t.Fatal("native script generation failed")
		}
		fixtures[kind] = boot.Body.String()
	}
	b, _ := json.Marshal(fixtures)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestNativeBootstrapOnlyChangesDocuments(t *testing.T) {
	for _, tc := range []struct {
		name, destination, accept string
		document                  bool
	}{
		{"document", "document", "text/html", true},
		{"legacy navigation", "", "text/html", true},
		{"angular template", "empty", "application/json, text/plain, */*", false},
		{"HTML fragment", "empty", "text/html", false},
		{"legacy template", "", "application/json, text/plain, */*", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jar, _ := cookiejar.New(nil)
			g := &gatewaySession{Jar: jar}
			s := Service{Type: "esxi", UpstreamURL: "https://esxi.test"}
			r := httptest.NewRequest("GET", "https://esxi.test/ui/views/login.html", nil)
			r.Header.Set("Sec-Fetch-Dest", tc.destination)
			r.Header.Set("Accept", tc.accept)
			const fragment = `<div class="login"><input type="password"><span>{{status}}</span></div>`
			resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}}, Body: io.NopCloser(strings.NewReader(fragment)), Request: r}
			if err := bridgeNativeResponse(resp, s, g); err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			if tc.document {
				if strings.Count(string(b), "/__webconsole/native/bootstrap.js") != 1 {
					t.Fatal("document must initialize the native bridge once")
				}
			} else if string(b) != fragment {
				t.Fatal("template response was changed or initialized the native bridge again")
			}
		})
	}
}

func TestESXiSessionObjectReferencesRoundTrip(t *testing.T) {
	for _, path := range []string{"/sdk", "/sdk/"} {
		t.Run(path, func(t *testing.T) {
			a := testApp(t)
			f := newNative(t, "esxi")
			s := addNative(t, a, f, "esxi")
			p, _ := owner(a)
			g := enter(t, a, p, s)
			original := "session[" + f.authToken() + "]view-17"
			masked := "session[" + nativeBrowserMarker + "]view-17"
			base := f.server.Config.Handler
			f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				setRequestBody(r, b)
				root, _ := decodeSOAP(b)
				if root != nil {
					switch root.child("Body").Children[0].Name {
					case "CreateContainerView":
						soapReply(w, `<CreateContainerViewResponse xmlns="urn:vim25"><returnval type="ContainerView">`+original+`</returnval></CreateContainerViewResponse>`)
						return
					case "RetrievePropertiesEx":
						if obj := root.find("obj"); obj != nil && strings.Contains(obj.Text, "view-17") {
							if obj.Text != original || root.value("displayName") != nativeBrowserMarker {
								t.Error("managed object reference or ordinary field rewritten incorrectly")
								w.WriteHeader(500)
								return
							}
							soapReply(w, `<RetrievePropertiesExResponse><returnval><objects><obj type="ContainerView">`+original+`</obj></objects></returnval></RetrievePropertiesExResponse>`)
							return
						}
					}
				}
				base.ServeHTTP(w, r)
			})
			created := blikvmSubmit(a, s, g, path, soapRequest("CreateContainerView"), "text/xml")
			if created.Code != 200 || !strings.Contains(created.Body.String(), masked) || strings.Contains(created.Body.String(), f.authToken()) {
				t.Fatal("session reference was not safely masked")
			}
			request := strings.Replace(soapRequest("RetrievePropertiesEx"), "</RetrievePropertiesEx>", `<specSet><objectSet><obj type="ContainerView">`+masked+`</obj></objectSet></specSet><displayName>`+nativeBrowserMarker+`</displayName></RetrievePropertiesEx>`, 1)
			result := blikvmSubmit(a, s, g, path, request, "text/xml")
			if result.Code != 200 || !strings.Contains(result.Body.String(), masked) {
				t.Fatal("session reference round trip failed", result.Code)
			}
			f.generation.Add(1)
			before := f.logins.Load()
			read := blikvmSubmit(a, s, g, path, soapRequest("RetrievePropertiesEx"), "text/xml")
			if read.Code != 200 || f.logins.Load() != before+1 {
				t.Fatal("SDK read did not recover expired session")
			}
			logout := blikvmSubmit(a, s, g, path, soapRequest("Logout"), "text/xml")
			if logout.Code != 200 || !g.Manual || nativeSession(&http.Client{Jar: g.Jar}, s).Token != "" {
				t.Fatal("SDK logout did not stop auto-login")
			}
		})
	}
}
func TestNativeMFAStopsAndLogoutCSRF(t *testing.T) {
	for _, kind := range []string{"pve", "tplink"} {
		t.Run(kind, func(t *testing.T) {
			a := testApp(t)
			f := newNative(t, kind)
			f.interactive.Store(true)
			s := addNative(t, a, f, kind)
			p, _ := owner(a)
			g := a.sessions.redeem(a.sessions.ticket(p, s.ID), s.ID)
			err := a.ensureLogin(context.Background(), s, g, nil)
			if err != errNativeInteractive {
				t.Fatal("interactive auth not detected", err)
			}
			_ = a.ensureLogin(context.Background(), s, g, nil)
			if f.logins.Load() != 1 {
				t.Fatal("interactive password resubmitted")
			}
			bad := gatewayRequest(a, s, g, "POST", "/__webconsole/native/logout", strings.NewReader(`{"csrf":"wrong"}`))
			if bad.Code != 403 {
				t.Fatal("CSRF check missing")
			}
			logout := gatewayRequest(a, s, g, "POST", "/__webconsole/native/logout", strings.NewReader(`{"csrf":"`+g.CSRF+`"}`))
			if logout.Code != 204 || !g.Manual {
				t.Fatal("manual/logout state missing")
			}
		})
	}
}
func TestNativePublicProtocolFixtures(t *testing.T) {
	root := os.Getenv("WEBCONSOLE_QUICK_PUBLIC_FIXTURES")
	if root == "" {
		t.Skip("optional actual firmware protocol check")
	}
	tp, err := os.ReadFile(filepath.Join(root, "tplink", "web-static_js_su_su.js"))
	if err != nil {
		t.Fatal(err)
	}
	if len(tplinkPasswordProtocol.FindSubmatch(tp)) != 3 {
		t.Fatal("actual SLP password protocol not detected")
	}
	mi, err := os.ReadFile(filepath.Join(root, "xiaomi", "cgi-bin_luci_web"))
	if err != nil {
		t.Fatal(err)
	}
	if len(xiaomiModePattern.FindSubmatch(mi)) != 2 || len(xiaomiKeyPattern.FindSubmatch(mi)) != 2 || len(xiaomiDevicePattern.FindSubmatch(mi)) != 2 {
		t.Fatal("actual Xiaomi password protocol not detected")
	}
	soap, err := os.ReadFile(filepath.Join(root, "esxi", "service-content.xml"))
	if err != nil {
		t.Fatal(err)
	}
	content, err := decodeSOAP(soap)
	if err != nil || content.value("sessionManager") == "" || content.value("propertyCollector") == "" {
		t.Fatal("actual ESXi SOAP protocol not detected")
	}
}
