package app

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

type tplinkAdapter struct{}
type xiaomiAdapter struct{}

type tplinkResponse struct {
	Code *int   `json:"error_code"`
	Stok string `json:"stok"`
}
type xiaomiResponse struct {
	Code  *int   `json:"code"`
	Token string `json:"token"`
	URL   string `json:"url"`
}

var tplinkPasswordProtocol = regexp.MustCompile(`(?s)orgAuthPwd\s*=\s*function\([^)]*\)\s*\{return\s+this\.securityEncode\([^,]+,\s*["']([A-Za-z0-9]{4,128})["'],\s*["']([A-Za-z0-9]{128,512})["']\)`)
var tplinkPasswordFunction = regexp.MustCompile(`(?s)orgAuthPwd\s*=\s*function\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\{([^{}]+)\}`)
var tplinkPasswordVariables = regexp.MustCompile(`(?s)^\s*var\s+([A-Za-z_$][\w$]*)\s*=\s*["']([A-Za-z0-9]{4,128})["']\s*;\s*var\s+([A-Za-z_$][\w$]*)\s*=\s*((?:["'][A-Za-z0-9]+["']\s*\+\s*)*["'][A-Za-z0-9]+["'])\s*;\s*return\s+this\.securityEncode\(\s*([A-Za-z_$][\w$]*)\s*,\s*([A-Za-z_$][\w$]*)\s*,\s*([A-Za-z_$][\w$]*)\s*\)\s*;?\s*$`)
var tplinkStringPart = regexp.MustCompile(`["']([A-Za-z0-9]+)["']`)

// Parse only the two observed SLP forms; never execute device JavaScript.
func tplinkProtocol(source string) (string, string, error) {
	if match := tplinkPasswordProtocol.FindStringSubmatch(source); len(match) == 3 {
		return match[1], match[2], nil
	}
	fn := tplinkPasswordFunction.FindStringSubmatch(source)
	if len(fn) != 3 || len(fn[2]) > 4096 {
		return "", "", errNativeProtocol
	}
	vars := tplinkPasswordVariables.FindStringSubmatch(fn[2])
	if len(vars) != 8 || vars[5] != fn[1] || vars[6] != vars[1] || vars[7] != vars[3] {
		return "", "", errNativeProtocol
	}
	var alphabet strings.Builder
	for _, part := range tplinkStringPart.FindAllStringSubmatch(vars[4], -1) {
		alphabet.WriteString(part[1])
	}
	if alphabet.Len() < 128 || alphabet.Len() > 512 {
		return "", "", errNativeProtocol
	}
	return vars[2], alphabet.String(), nil
}

var xiaomiModePattern = regexp.MustCompile(`newEncryptMode\s*=\s*parseInt\(['"]([01])['"]\)`)
var xiaomiKeyPattern = regexp.MustCompile(`\bkey:\s*['"]([a-fA-F0-9]{32,64})['"]`)
var xiaomiDevicePattern = regexp.MustCompile(`\bdeviceId\s*=\s*['"]([a-fA-F0-9:]{17})['"]`)
var stokPath = regexp.MustCompile(`^(/cgi-bin/luci/;stok=|/stok=)([^/]*)(/.*)?$`)

func publicDeviceText(ctx context.Context, c *http.Client, s Service, path string) (string, error) {
	resp, err := call(ctx, c, "GET", s.UpstreamURL+path, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", errNativeProtocol
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(b) > 1<<20 {
		return "", errNativeProtocol
	}
	return string(b), nil
}

// The SLP firmware encodes UTF-16 code units, matching JavaScript charCodeAt.
func tplinkPassword(password, salt, alphabet string) string {
	p, k := utf16.Encode([]rune(password)), utf16.Encode([]rune(salt))
	size := max(len(p), len(k))
	var output strings.Builder
	for i := 0; i < size; i++ {
		var a, b uint16 = 187, 187
		if i >= len(p) {
			b = k[i]
		} else if i >= len(k) {
			a = p[i]
		} else {
			a, b = p[i], k[i]
		}
		output.WriteByte(alphabet[int(a^b)%len(alphabet)])
	}
	return output.String()
}

func (tplinkAdapter) Login(ctx context.Context, c *http.Client, s Service, cred Credentials) error {
	page, err := publicDeviceText(ctx, c, s, "/login.htm")
	if err != nil {
		return err
	}
	if !strings.Contains(page, `data-interface-type="SLP"`) || !strings.Contains(page, "orgAuthPwd") {
		return errNativeProtocol
	}
	source, err := publicDeviceText(ctx, c, s, "/web-static/js/su/su.js")
	if err != nil {
		return err
	}
	salt, alphabet, err := tplinkProtocol(source)
	if err != nil {
		return err
	}
	user := strings.ReplaceAll(url.QueryEscape(cred.Username), "+", "%20")
	r, _ := http.NewRequestWithContext(ctx, "POST", s.UpstreamURL+"/", nil)
	resp, err := nativeJSONCall(r, c, map[string]any{"method": "do", "login": map[string]string{"username": user, "password": tplinkPassword(cred.Password, salt, alphabet)}})
	if err != nil {
		return err
	}
	if resp.StatusCode == 429 {
		finish(resp)
		return errNativeRateLimit
	}
	var result tplinkResponse
	if err := nativeJSON(resp, &result); err != nil {
		return err
	}
	if result.Code == nil {
		return errNativeProtocol
	}
	if *result.Code == -40402 {
		return errNativeInteractive
	}
	if *result.Code == -40404 || *result.Code == -40406 || *result.Code == -40407 || *result.Code == -40408 {
		return errNativeRateLimit
	}
	if *result.Code != 0 {
		return errLogin
	}
	if !nativeTokenPattern.MatchString(result.Stok) {
		return errNativeProtocol
	}
	saveNativeSession(c, s, nativeAuth{Token: result.Stok, Username: cred.Username})
	return nil
}

func (tplinkAdapter) Check(ctx context.Context, c *http.Client, s Service) error {
	auth := nativeSession(c, s)
	if auth.Token == "" {
		return errNeedsLogin
	}
	r, _ := http.NewRequestWithContext(ctx, "POST", s.UpstreamURL+"/stok="+auth.Token+"/ds", nil)
	resp, err := nativeJSONCall(r, c, map[string]any{"method": "get", "firmware": map[string]string{"name": "config"}})
	if err != nil {
		return err
	}
	var result tplinkResponse
	status := resp.StatusCode
	if err := nativeJSON(resp, &result); err != nil {
		return err
	}
	if result.Code == nil {
		return errNativeProtocol
	}
	if status == 401 || *result.Code == -40401 || *result.Code == -40403 {
		return errNeedsLogin
	}
	if *result.Code == -40404 || *result.Code == -40408 {
		return errNativeRateLimit
	}
	if status != 200 || *result.Code != 0 {
		return fmt.Errorf("TP-Link 会话检查失败")
	}
	return nil
}
func (tplinkAdapter) Logout(_ context.Context, c *http.Client, s Service) error {
	clearNativeSession(c, s)
	return nil
}
func (tplinkAdapter) Expired(resp *http.Response) bool {
	if resp.StatusCode == 401 {
		return true
	}
	if resp.StatusCode != 200 || resp.Request == nil || !strings.HasSuffix(resp.Request.URL.Path, "/ds") {
		return false
	}
	b := responsePrefix(resp, 2048)
	code := regexp.MustCompile(`"error_code"\s*:\s*(-?\d+)`).FindSubmatch(b)
	return len(code) == 2 && (string(code[1]) == "-40401" || string(code[1]) == "-40403")
}

func xiaomiPassword(password, key, nonce string, sha256Mode bool) string {
	if sha256Mode {
		inner := sha256.Sum256([]byte(password + key))
		outer := sha256.Sum256([]byte(nonce + hex.EncodeToString(inner[:])))
		return hex.EncodeToString(outer[:])
	}
	inner := sha1.Sum([]byte(password + key))
	outer := sha1.Sum([]byte(nonce + hex.EncodeToString(inner[:])))
	return hex.EncodeToString(outer[:])
}

func (xiaomiAdapter) Login(ctx context.Context, c *http.Client, s Service, cred Credentials) error {
	if cred.Username != "admin" {
		return fmt.Errorf("小米路由器的原生 Web 账号固定为 admin")
	}
	page, err := publicDeviceText(ctx, c, s, "/cgi-bin/luci/web")
	if err != nil {
		return err
	}
	mode, key, device := xiaomiModePattern.FindStringSubmatch(page), xiaomiKeyPattern.FindStringSubmatch(page), xiaomiDevicePattern.FindStringSubmatch(page)
	if len(mode) != 2 || len(key) != 2 || len(device) != 2 || !strings.Contains(page, "/cgi-bin/luci/api/xqsystem/login") {
		return errNativeProtocol
	}
	random, err := rand.Int(rand.Reader, big.NewInt(10000))
	if err != nil {
		return errNativeProtocol
	}
	nonce := "0_" + device[1] + "_" + strconv.FormatInt(time.Now().Unix(), 10) + "_" + random.String()
	resp, err := call(ctx, c, "POST", s.UpstreamURL+"/cgi-bin/luci/api/xqsystem/login", url.Values{"username": {"admin"}, "password": {xiaomiPassword(cred.Password, key[1], nonce, mode[1] == "1")}, "logtype": {"2"}, "nonce": {nonce}})
	if err != nil {
		return err
	}
	if resp.StatusCode == 429 {
		finish(resp)
		return errNativeRateLimit
	}
	if resp.StatusCode != 200 {
		finish(resp)
		return errLogin
	}
	var result xiaomiResponse
	if err := nativeJSON(resp, &result); err != nil {
		return err
	}
	if result.Code == nil {
		return errNativeProtocol
	}
	if *result.Code != 0 {
		return errLogin
	}
	if !nativeTokenPattern.MatchString(result.Token) {
		return errNativeProtocol
	}
	if _, err := xiaomiReturnPath(result.URL, s); err != nil {
		return err
	}
	saveNativeSession(c, s, nativeAuth{Token: result.Token, Username: "admin"})
	return nil
}

func (xiaomiAdapter) Check(ctx context.Context, c *http.Client, s Service) error {
	auth := nativeSession(c, s)
	if auth.Token == "" {
		return errNeedsLogin
	}
	resp, err := call(ctx, c, "GET", s.UpstreamURL+"/cgi-bin/luci/;stok="+auth.Token+"/api/xqsystem/status", nil)
	if err != nil {
		return err
	}
	if resp.StatusCode == 401 {
		finish(resp)
		return errNeedsLogin
	}
	if resp.StatusCode != 200 {
		finish(resp)
		return fmt.Errorf("小米路由器会话检查失败")
	}
	var result xiaomiResponse
	if err := nativeJSON(resp, &result); err != nil {
		return err
	}
	if result.Code == nil {
		return errNativeProtocol
	}
	if *result.Code == 401 || *result.Code == 403 {
		return errNeedsLogin
	}
	if *result.Code != 0 {
		return fmt.Errorf("小米路由器会话检查失败")
	}
	return nil
}
func (xiaomiAdapter) Logout(_ context.Context, c *http.Client, s Service) error {
	clearNativeSession(c, s)
	return nil
}
func (xiaomiAdapter) Expired(resp *http.Response) bool {
	if resp.StatusCode == 401 {
		return true
	}
	if resp.Request == nil || !strings.Contains(resp.Request.URL.Path, "/api/") || resp.StatusCode != 200 {
		return false
	}
	b := responsePrefix(resp, 2048)
	code := regexp.MustCompile(`"code"\s*:\s*(\d+)`).FindSubmatch(b)
	return len(code) == 2 && (string(code[1]) == "401" || string(code[1]) == "403")
}

func xiaomiReturnPath(value string, s Service) (string, error) {
	u, err := url.Parse(value)
	if err != nil || u.User != nil {
		return "", errNativeProtocol
	}
	origin, _ := url.Parse(s.UpstreamURL)
	if u.IsAbs() || u.Host != "" {
		if !sameDeviceOrigin(u, origin) {
			return "", errNativeProtocol
		}
	}
	if !strings.HasPrefix(u.Path, "/cgi-bin/luci/") || strings.ContainsAny(value, "\r\n\\") {
		return "", errNativeProtocol
	}
	u.Scheme, u.Host = "", ""
	u.Path = stokPath.ReplaceAllString(u.Path, "${1}"+nativeBrowserMarker+"${3}")
	u.RawPath = ""
	return u.String(), nil
}
