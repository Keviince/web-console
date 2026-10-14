package app

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Listen, PortalURL, DeviceDomain, Issuer, ClientID, ClientSecret, AllowedSub string
	DataDir, WebRoot                                                            string
	Key                                                                         []byte
	DevHTTP                                                                     bool
	SessionTTL                                                                  time.Duration
}

func LoadConfig() (Config, error) {
	c := Config{
		Listen: env("LISTEN", ":8080"), PortalURL: strings.TrimRight(os.Getenv("PORTAL_URL"), "/"),
		DeviceDomain: strings.ToLower(os.Getenv("DEVICE_DOMAIN")), Issuer: os.Getenv("OIDC_ISSUER"),
		ClientID: os.Getenv("OIDC_CLIENT_ID"), AllowedSub: os.Getenv("OIDC_ALLOWED_SUB"),
		DataDir: env("DATA_DIR", "data"), WebRoot: env("WEB_ROOT", "web/dist"), SessionTTL: 8 * time.Hour,
	}
	c.DevHTTP, _ = strconv.ParseBool(os.Getenv("DEV_HTTP"))
	key, err := os.ReadFile(env("ENCRYPTION_KEY_FILE", "/run/secrets/encryption_key"))
	if err != nil {
		return c, errors.New("cannot read ENCRYPTION_KEY_FILE")
	}
	c.Key, err = hex.DecodeString(strings.TrimSpace(string(key)))
	if err != nil || len(c.Key) != 32 {
		return c, errors.New("encryption key must be 64 hexadecimal characters")
	}
	secret, err := os.ReadFile(env("OIDC_CLIENT_SECRET_FILE", "/run/secrets/oidc_client_secret"))
	if err != nil {
		return c, errors.New("cannot read OIDC_CLIENT_SECRET_FILE")
	}
	c.ClientSecret = strings.TrimSpace(string(secret))
	if err := c.Validate(); err != nil {
		return c, err
	}
	return c, nil
}

func (c Config) Validate() error {
	u, err := url.Parse(c.PortalURL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("PORTAL_URL must be an absolute origin without a path")
	}
	if u.Scheme != "https" && !(c.DevHTTP && u.Scheme == "http" && isLoopback(u.Hostname())) {
		return errors.New("PORTAL_URL requires HTTPS (DEV_HTTP permits localhost only)")
	}
	if !validDomain(c.DeviceDomain) {
		return errors.New("DEVICE_DOMAIN must be a valid domain suffix")
	}
	if strings.HasSuffix(strings.ToLower(u.Hostname()), "."+c.DeviceDomain) {
		return errors.New("PORTAL_URL cannot be a child of DEVICE_DOMAIN; use the portal hostname itself or a separate device domain")
	}
	if c.DevHTTP && !isLoopback(c.DeviceDomain) {
		return errors.New("DEV_HTTP requires a localhost device domain")
	}
	issuer, err := url.Parse(c.Issuer)
	if err != nil || issuer.Hostname() == "" || issuer.User != nil || (issuer.Scheme != "https" && !(c.DevHTTP && issuer.Scheme == "http" && isLoopback(issuer.Hostname()))) {
		return errors.New("OIDC_ISSUER requires an HTTPS URL")
	}
	if c.ClientID == "" || c.ClientSecret == "" || c.AllowedSub == "" {
		return errors.New("OIDC_CLIENT_ID, client secret and OIDC_ALLOWED_SUB are required")
	}
	if len(c.Key) != 32 {
		return errors.New("a 256-bit encryption key is required")
	}
	return nil
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
func isLoopback(host string) bool {
	return host == "localhost" || strings.HasSuffix(host, ".localhost") || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback())
}
func validDomain(domain string) bool {
	if len(domain) > 253 || strings.Contains(domain, ":") || net.ParseIP(domain) != nil {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if !validSlug(label) {
			return false
		}
	}
	return domain != ""
}
func validSlug(s string) bool {
	if len(s) < 1 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}
func (c Config) portalHost() string { u, _ := url.Parse(c.PortalURL); return strings.ToLower(u.Host) }
func (c Config) deviceOrigin(slug string) string {
	u, _ := url.Parse(c.PortalURL)
	host := slug + "." + c.DeviceDomain
	if u.Port() != "" {
		host += ":" + u.Port()
	}
	return fmt.Sprintf("%s://%s", u.Scheme, host)
}
