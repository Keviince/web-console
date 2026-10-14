package app

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Only URLs for the configured device are mapped. Other sites and relative
// paths retain their normal behavior; the gateway never accepts a new target.
func manualProxyURLRewriter(s Service, origin string) func(string) string {
	u, _ := url.Parse(s.UpstreamURL)
	host := regexp.QuoteMeta(u.Host)
	if u.Port() == "" {
		host += "(?::" + devicePort(u) + ")?"
	} else if u.Port() == "80" && u.Scheme == "http" || u.Port() == "443" && u.Scheme == "https" {
		host = regexp.QuoteMeta(strings.TrimSuffix(u.Host, ":"+u.Port())) + "(?::" + u.Port() + ")?"
	}
	pattern := regexp.MustCompile(`(?i)(https?:|wss?:)?//` + host + `([/?#\s"'<>),;]|$)`)
	return func(value string) string {
		for _, slash := range []string{"/", `\/`} {
			// JSON and JavaScript may escape every slash in an absolute URL.
			encodedPattern := pattern
			if slash != "/" {
				encodedPattern = regexp.MustCompile(strings.ReplaceAll(pattern.String(), "/", regexp.QuoteMeta(slash)))
			}
			value = encodedPattern.ReplaceAllStringFunc(value, func(match string) string {
				parts := encodedPattern.FindStringSubmatch(match)
				target := origin
				if strings.HasPrefix(strings.ToLower(parts[1]), "ws") {
					target = "ws" + strings.TrimPrefix(origin, "http")
				}
				return strings.ReplaceAll(target, "/", slash) + parts[2]
			})
		}
		return value
	}
}

func rewriteManualProxyResponse(resp *http.Response, s Service, origin string) error {
	rewrite := manualProxyURLRewriter(s, origin)
	for _, name := range []string{"Location", "Refresh", "Link", "Content-Security-Policy", "Content-Security-Policy-Report-Only", "Access-Control-Allow-Origin"} {
		values := resp.Header.Values(name)
		if len(values) > 0 {
			resp.Header.Del(name)
			for _, value := range values {
				resp.Header.Add(name, rewrite(value))
			}
		}
	}
	typeName, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	text := typeName == "text/html" || typeName == "text/css" || typeName == "text/javascript" || typeName == "application/javascript" || typeName == "application/x-javascript" || typeName == "application/json" || typeName == "application/xml" || typeName == "text/xml" || typeName == "image/svg+xml"
	if !text || resp.StatusCode == http.StatusNotModified || resp.Request != nil && resp.Request.Method == "HEAD" || resp.Header.Get("Content-Disposition") != "" {
		return nil
	}
	var reader io.Reader = resp.Body
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		if encoding != "gzip" {
			return errors.New("设备原页面使用了不支持的压缩格式")
		}
		decoded, err := gzip.NewReader(resp.Body)
		if err != nil {
			return err
		}
		defer decoded.Close()
		reader = decoded
	}
	// Bound memory use for rewriteable pages; streams and downloads bypass this.
	const limit = 32 << 20
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	_ = resp.Body.Close()
	if err != nil {
		return err
	}
	if len(body) > limit {
		return errors.New("设备原页面超过代理改写大小限制")
	}
	body = []byte(rewrite(string(body)))
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("ETag")
	resp.Header.Del("Content-MD5")
	resp.Header.Set("Cache-Control", "no-store")
	return nil
}
