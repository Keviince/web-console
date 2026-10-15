package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type nativeRequestKey struct{}
type nativeRequestInfo struct {
	Operation           string
	Safe, Login, Logout bool
}

func nativeInfo(r *http.Request) nativeRequestInfo {
	value, _ := r.Context().Value(nativeRequestKey{}).(nativeRequestInfo)
	return value
}

func setRequestBody(r *http.Request, b []byte) {
	r.Body = io.NopCloser(bytes.NewReader(b))
	r.ContentLength = int64(len(b))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
}

func prepareNativeRequest(r *http.Request, s Service, g *gatewaySession) *http.Request {
	info := nativeRequestInfo{}
	if s.Type == "glinet" {
		info.Login = r.Method == "POST" && r.URL.Path == "/api/auth/login"
		info.Logout = r.Method == "POST" && r.URL.Path == "/api/auth/logout"
	}
	if s.Type == "xiaomi" {
		info.Login = r.Method == "POST" && r.URL.Path == "/cgi-bin/luci/api/xqsystem/login"
		info.Logout = strings.HasSuffix(r.URL.Path, "/web/logout") || strings.HasSuffix(r.URL.Path, "/api/xqsystem/logout")
	}
	inspect := r.Method == "POST" && r.Body != nil && (s.Type == "pve" && pveLoginPath(r.URL.Path) || s.Type == "esxi" && esxiSDKPath(r.URL.Path) || s.Type == "tplink" && (r.URL.Path == "/" || strings.HasSuffix(r.URL.Path, "/ds")))
	if inspect {
		original := r.Body
		b, err := io.ReadAll(io.LimitReader(original, (2<<20)+1))
		if err != nil || len(b) > 2<<20 {
			r.Body = &prefixReadCloser{Reader: io.MultiReader(bytes.NewReader(b), original), Closer: original}
			return r.WithContext(context.WithValue(r.Context(), nativeRequestKey{}, info))
		}
		_ = original.Close()
		if s.Type == "pve" {
			info.Login = true
			form, err := url.ParseQuery(string(b))
			if err == nil && form.Get("password") == nativeBrowserMarker {
				auth := nativeSession(&http.Client{Jar: g.Jar}, s)
				if auth.Token != "" {
					form.Set("password", auth.Token)
					b = []byte(form.Encode())
				}
			}
		} else if s.Type == "esxi" {
			root, err := decodeSOAP(b)
			if err == nil && len(root.child("Body").Children) == 1 {
				info.Operation = root.child("Body").Children[0].Name
				info.Login, info.Logout = info.Operation == "Login", info.Operation == "Logout"
				switch info.Operation {
				case "RetrieveServiceContent", "RetrieveProperties", "RetrievePropertiesEx", "ContinueRetrievePropertiesEx", "WaitForUpdates", "WaitForUpdatesEx", "SessionIsActive":
					info.Safe = true
				}
				if info.Operation == "SessionIsActive" || info.Operation == "TerminateSession" {
					auth := nativeSession(&http.Client{Jar: g.Jar}, s)
					if auth.SessionID != "" {
						b = bytes.ReplaceAll(b, []byte(">"+nativeBrowserMarker+"<"), []byte(">"+xmlValue(auth.SessionID)+"<"))
					}
				}
				if !info.Login {
					auth := nativeSession(&http.Client{Jar: g.Jar}, s)
					visitESXiReferences(root, func(reference string) {
						if original := auth.References[reference]; original != "" {
							b = replaceXMLLeaf(b, reference, original)
						}
					})
				}
			}
		} else if s.Type == "tplink" {
			var data map[string]json.RawMessage
			if json.Unmarshal(b, &data) == nil {
				var method string
				_ = json.Unmarshal(data["method"], &method)
				info.Login = r.URL.Path == "/" && method == "do" && data["login"] != nil
				var system map[string]json.RawMessage
				_ = json.Unmarshal(data["system"], &system)
				info.Logout = method == "do" && system["logout"] != nil
				info.Safe = strings.HasSuffix(r.URL.Path, "/ds") && method == "get" && safeSLPRead(data)
			}
		}
		setRequestBody(r, b)
	}
	return r.WithContext(context.WithValue(r.Context(), nativeRequestKey{}, info))
}

// Only the native read selectors qualify; arbitrary do/set payloads, mixed
// operations or unknown request fields are never replayed.
func safeSLPRead(data map[string]json.RawMessage) bool {
	if len(data) < 2 {
		return false
	}
	for key, value := range data {
		if key == "method" {
			continue
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(value, &fields) != nil || len(fields) == 0 {
			return false
		}
		for selector := range fields {
			if selector != "name" && selector != "table" {
				return false
			}
			var one string
			var list []string
			if json.Unmarshal(fields[selector], &one) != nil && json.Unmarshal(fields[selector], &list) != nil {
				return false
			}
		}
	}
	return true
}

func safeDeviceRequest(r *http.Request) bool {
	return safeRequest(r) || nativeInfo(r).Safe && r.GetBody != nil
}

func applyNativeAuth(r *http.Request, s Service, g *gatewaySession) {
	c := &http.Client{Jar: g.Jar}
	auth := nativeSession(c, s)
	switch s.Type {
	case "glinet":
		applyGlinetAuth(r, s, g)
	case "pve":
		r.Header.Del("CSRFPreventionToken")
		if auth.CSRF != "" {
			r.Header.Set("CSRFPreventionToken", auth.CSRF)
		}
	case "esxi":
		r.Header.Del("X-Vsphere-Proxy")
		r.Header.Del("VMware-CSRF-Token")
		if auth.CSRF != "" {
			r.Header.Set("VMware-CSRF-Token", auth.CSRF)
		}
	case "tplink", "xiaomi":
		if auth.Token != "" {
			r.URL.Path = stokPath.ReplaceAllString(r.URL.Path, "${1}"+auth.Token+"${3}")
			r.URL.RawPath = ""
		}
	}
}

func replaceResponseBody(resp *http.Response, b []byte) {
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(b))
	resp.ContentLength = int64(len(b))
	resp.Header.Set("Content-Length", strconv.Itoa(len(b)))
	resp.Header.Set("Cache-Control", "no-store")
	for _, key := range []string{"ETag", "Last-Modified", "Content-MD5", "Digest"} {
		resp.Header.Del(key)
	}
}

func captureRouterLogin(resp *http.Response, s Service, g *gatewaySession) error {
	if resp.StatusCode != 200 {
		return nil
	}
	b := responsePrefix(resp, (128<<10)+1)
	if len(b) > 128<<10 {
		return errNativeProtocol
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(b, &envelope) != nil {
		return errNativeProtocol
	}
	auth := nativeAuth{}
	if s.Type == "tplink" {
		var result tplinkResponse
		if json.Unmarshal(b, &result) != nil || result.Code == nil {
			return errNativeProtocol
		}
		if *result.Code != 0 {
			return nil
		}
		if !nativeTokenPattern.MatchString(result.Stok) {
			return errNativeProtocol
		}
		auth.Token = result.Stok
		envelope["stok"], _ = json.Marshal(nativeBrowserMarker)
	} else {
		var result xiaomiResponse
		if json.Unmarshal(b, &result) != nil || result.Code == nil {
			return errNativeProtocol
		}
		if *result.Code != 0 {
			return nil
		}
		if !nativeTokenPattern.MatchString(result.Token) {
			return errNativeProtocol
		}
		path, err := xiaomiReturnPath(result.URL, s)
		if err != nil {
			return err
		}
		auth.Token, auth.Username = result.Token, "admin"
		envelope["token"], _ = json.Marshal(nativeBrowserMarker)
		envelope["url"], _ = json.Marshal(path)
	}
	g.authMu.Lock()
	saveNativeSession(&http.Client{Jar: g.Jar}, s, auth)
	g.Version++
	g.authMu.Unlock()
	out, _ := json.Marshal(envelope)
	replaceResponseBody(resp, out)
	return nil
}

func captureESXiResponse(resp *http.Response, s Service, g *gatewaySession) error {
	if resp.StatusCode != 200 || !esxiSDKPath(resp.Request.URL.Path) || resp.Request.Method != "POST" {
		return nil
	}
	info := nativeInfo(resp.Request)
	b := responsePrefix(resp, (4<<20)+1)
	if len(b) > 4<<20 {
		return nil
	}
	root, err := decodeSOAP(b)
	if err != nil {
		return err
	}
	g.authMu.Lock()
	c := &http.Client{Jar: g.Jar}
	auth := nativeSession(c, s)
	if info.Operation == "RetrieveServiceContent" {
		if value := root.value("sessionManager"); value != "" {
			auth.SessionManager = value
		}
		if value := root.value("propertyCollector"); value != "" {
			auth.PropertyCollector = value
		}
		if value := root.value("apiVersion"); esxiVersionPattern.MatchString(value) {
			auth.Version = value
		}
	}
	if info.Login {
		session := root.find("LoginResponse").find("returnval")
		if session != nil {
			auth.References = nil
			auth.Username, auth.SessionID = session.value("userName"), session.value("key")
			u, _ := url.Parse(s.UpstreamURL + "/sdk")
			for _, cookie := range g.Jar.Cookies(u) {
				if cookie.Name == "vmware_soap_session" {
					auth.Token = cookie.Value
				}
			}
			g.Version++
		}
	}
	// ESXi embeds the current session key in managed-object IDs such as
	// session[uuid]...ContainerView. Remember complete IDs so subsequent SOAP
	// references can be restored without rewriting names or other user data.
	visitESXiReferences(root, func(reference string) {
		if auth.SessionID != "" && strings.Contains(reference, auth.SessionID) {
			masked := strings.ReplaceAll(reference, auth.SessionID, nativeBrowserMarker)
			if auth.References == nil {
				auth.References = map[string]string{}
			}
			auth.References[masked] = reference
			b = replaceXMLLeaf(b, reference, masked)
		}
	})
	saveNativeSession(c, s, auth)
	g.authMu.Unlock()
	for _, secret := range []string{auth.Token, auth.SessionID} {
		if secret != "" {
			b = replaceXMLLeaf(b, secret, nativeBrowserMarker)
		}
	}
	replaceResponseBody(resp, b)
	return nil
}

func replaceXMLLeaf(b []byte, from, to string) []byte {
	return bytes.ReplaceAll(b, []byte(">"+xmlValue(from)+"<"), []byte(">"+xmlValue(to)+"<"))
}

func visitESXiReferences(root *soapNode, visit func(string)) {
	if root == nil {
		return
	}
	for _, attr := range root.Attr {
		if attr.Name.Local == "type" && (attr.Name.Space == "" || attr.Value == "ManagedObjectReference" || strings.HasSuffix(attr.Value, ":ManagedObjectReference")) && len(root.Children) == 0 {
			visit(root.Text)
			break
		}
	}
	for _, child := range root.Children {
		visitESXiReferences(child, visit)
	}
}

func (t *deviceRoundTripper) captureNativeResponse(resp *http.Response) error {
	s, g := t.service, t.session
	info := nativeInfo(resp.Request)
	if s.Type == "glinet" && info.Login {
		if err := captureGlinetLogin(resp, s, g); err != nil {
			return err
		}
	}
	if s.Type == "pve" && info.Login {
		if err := capturePVELogin(resp, s, g); err != nil {
			return err
		}
	}
	if (s.Type == "tplink" || s.Type == "xiaomi") && info.Login {
		if err := captureRouterLogin(resp, s, g); err != nil {
			return err
		}
	}
	if s.Type == "esxi" {
		if err := captureESXiResponse(resp, s, g); err != nil {
			return err
		}
	}
	if info.Logout {
		g.authMu.Lock()
		g.Manual = true
		g.Version++
		clearNativeSession(&http.Client{Jar: g.Jar}, s)
		g.authMu.Unlock()
		g.disconnect()
	}
	if info.Login && nativeSession(&http.Client{Jar: g.Jar}, s).Token != "" {
		resp.Header.Add("Set-Cookie", (&http.Cookie{Name: "wc_native_manual", Path: "/", MaxAge: -1}).String())
	}
	return nil
}
