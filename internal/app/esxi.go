package app

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

type esxiAdapter struct{}

func esxiSDKPath(path string) bool { return path == "/sdk" || path == "/sdk/" }

type soapNode struct {
	Name     string
	Text     string
	Attr     []xml.Attr
	Children []*soapNode
}

func (n *soapNode) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	n.Name, n.Attr = start.Name.Local, start.Attr
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch value := t.(type) {
		case xml.StartElement:
			child := &soapNode{}
			if err := d.DecodeElement(child, &value); err != nil {
				return err
			}
			n.Children = append(n.Children, child)
		case xml.CharData:
			n.Text += string(value)
		case xml.EndElement:
			n.Text = strings.TrimSpace(n.Text)
			return nil
		}
	}
}
func (n *soapNode) find(name string) *soapNode {
	if n == nil {
		return nil
	}
	if n.Name == name {
		return n
	}
	for _, child := range n.Children {
		if found := child.find(name); found != nil {
			return found
		}
	}
	return nil
}
func (n *soapNode) child(name string) *soapNode {
	if n != nil {
		for _, child := range n.Children {
			if child.Name == name {
				return child
			}
		}
	}
	return nil
}
func (n *soapNode) value(name string) string {
	if child := n.find(name); child != nil {
		return child.Text
	}
	return ""
}

func decodeSOAP(b []byte) (*soapNode, error) {
	var root soapNode
	if xml.Unmarshal(b, &root) != nil {
		return nil, errNativeProtocol
	}
	if root.Name != "Envelope" || root.child("Body") == nil {
		return nil, errNativeProtocol
	}
	return &root, nil
}
func soapFault(root *soapNode, name string) bool {
	fault := root.find("Fault")
	if fault == nil {
		return false
	}
	var visit func(*soapNode) bool
	visit = func(n *soapNode) bool {
		if n.Name == name || n.Name == name+"Fault" {
			return true
		}
		for _, attr := range n.Attr {
			if attr.Name.Local == "type" && (attr.Value == name || strings.HasSuffix(attr.Value, ":"+name)) {
				return true
			}
		}
		for _, child := range n.Children {
			if visit(child) {
				return true
			}
		}
		return false
	}
	return visit(fault)
}
func xmlValue(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func esxiSOAP(ctx context.Context, c *http.Client, s Service, auth nativeAuth, operation, inner string) (*soapNode, error) {
	body := `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><` + operation + ` xmlns="urn:vim25">` + inner + `</` + operation + `></soapenv:Body></soapenv:Envelope>`
	r, _ := http.NewRequestWithContext(ctx, "POST", s.UpstreamURL+"/sdk", strings.NewReader(body))
	r.Header.Set("Content-Type", "text/xml; charset=utf-8")
	r.Header.Set("SOAPAction", `"urn:vim25/`+auth.Version+`"`)
	r.Header.Set("VMware-CSRF-Token", auth.CSRF)
	resp, err := c.Do(r)
	if err != nil {
		return nil, connectionError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		return nil, errNeedsLogin
	}
	if resp.StatusCode == 429 {
		return nil, errNativeRateLimit
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(b) > 1<<20 {
		return nil, errNativeProtocol
	}
	root, err := decodeSOAP(b)
	if err != nil {
		return nil, err
	}
	if soapFault(root, "NotAuthenticated") {
		return nil, errNeedsLogin
	}
	if soapFault(root, "InvalidLogin") {
		return nil, errLogin
	}
	if root.find("Fault") != nil || resp.StatusCode != 200 {
		return nil, errors.New("ESXi API 请求失败，请核对账号权限")
	}
	return root, nil
}

var esxiVersionPattern = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){1,4}$`)

func (esxiAdapter) Login(ctx context.Context, c *http.Client, s Service, cred Credentials) error {
	text, err := publicDeviceText(ctx, c, s, "/sdk/vimServiceVersions.xml")
	if err != nil {
		return err
	}
	var versions soapNode
	if xml.Unmarshal([]byte(text), &versions) != nil {
		return errNativeProtocol
	}
	version := ""
	for _, namespace := range versions.Children {
		if namespace.Name == "namespace" && namespace.value("name") == "urn:vim25" {
			version = namespace.value("version")
			break
		}
	}
	if !esxiVersionPattern.MatchString(version) {
		return errNativeProtocol
	}
	auth := nativeAuth{CSRF: token(), Version: version}
	content, err := esxiSOAP(ctx, c, s, auth, "RetrieveServiceContent", `<_this type="ServiceInstance">ServiceInstance</_this>`)
	if err != nil {
		return err
	}
	auth.SessionManager, auth.PropertyCollector = content.value("sessionManager"), content.value("propertyCollector")
	if auth.SessionManager == "" || auth.PropertyCollector == "" {
		return errNativeProtocol
	}
	root, err := esxiSOAP(ctx, c, s, auth, "Login", `<_this type="SessionManager">`+xmlValue(auth.SessionManager)+`</_this><userName>`+xmlValue(cred.Username)+`</userName><password>`+xmlValue(cred.Password)+`</password><locale>en_US</locale>`)
	if err != nil {
		return err
	}
	session := root.find("LoginResponse").find("returnval")
	if session == nil {
		return errNativeProtocol
	}
	auth.Username, auth.SessionID = session.value("userName"), session.value("key")
	u, _ := url.Parse(s.UpstreamURL + "/sdk")
	for _, cookie := range c.Jar.Cookies(u) {
		if cookie.Name == "vmware_soap_session" {
			auth.Token = cookie.Value
		}
	}
	if auth.Token == "" || auth.SessionID == "" || auth.Username == "" {
		return errNativeProtocol
	}
	saveNativeSession(c, s, auth)
	return nil
}

func esxiCurrentSession(root *soapNode) *soapNode {
	var visit func(*soapNode) *soapNode
	visit = func(n *soapNode) *soapNode {
		if n.Name == "propSet" && n.value("name") == "currentSession" {
			return n.child("val")
		}
		for _, child := range n.Children {
			if found := visit(child); found != nil {
				return found
			}
		}
		return nil
	}
	return visit(root)
}

func (esxiAdapter) Check(ctx context.Context, c *http.Client, s Service) error {
	auth := nativeSession(c, s)
	if auth.Token == "" || auth.PropertyCollector == "" || auth.SessionManager == "" {
		return errNeedsLogin
	}
	root, err := esxiSOAP(ctx, c, s, auth, "RetrievePropertiesEx", `<_this type="PropertyCollector">`+xmlValue(auth.PropertyCollector)+`</_this><specSet><propSet><type>SessionManager</type><pathSet>currentSession</pathSet></propSet><objectSet><obj type="SessionManager">`+xmlValue(auth.SessionManager)+`</obj></objectSet></specSet><options/>`)
	if err != nil {
		return err
	}
	session := esxiCurrentSession(root)
	if session == nil || session.value("key") == "" || session.value("userName") == "" {
		return errNeedsLogin
	}
	return nil
}
func (esxiAdapter) Logout(ctx context.Context, c *http.Client, s Service) error {
	auth := nativeSession(c, s)
	if auth.Token != "" && auth.SessionManager != "" {
		_, _ = esxiSOAP(ctx, c, s, auth, "Logout", `<_this type="SessionManager">`+xmlValue(auth.SessionManager)+`</_this>`)
	}
	clearNativeSession(c, s)
	return nil
}
func (esxiAdapter) Expired(resp *http.Response) bool {
	if resp.StatusCode == 401 {
		return true
	}
	if resp.StatusCode != 500 || resp.Request == nil || !esxiSDKPath(resp.Request.URL.Path) {
		return false
	}
	root, err := decodeSOAP(responsePrefix(resp, 64<<10))
	return err == nil && soapFault(root, "NotAuthenticated")
}
