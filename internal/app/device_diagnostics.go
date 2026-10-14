package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

var (
	errDeviceHTTPSRedirect  = errors.New("device requires HTTPS")
	errDeviceRedirectOrigin = errors.New("device redirect changes origin")
	errDeviceRedirectLimit  = errors.New("device redirect limit exceeded")
)

type deviceConnectionError struct {
	reason, message string
	cause           error
}

func (e *deviceConnectionError) Error() string { return e.message }
func (e *deviceConnectionError) Unwrap() error { return e.cause }

func sameDeviceOrigin(a, b *url.URL) bool {
	return a.Scheme == b.Scheme && strings.EqualFold(a.Hostname(), b.Hostname()) && devicePort(a) == devicePort(b)
}

func devicePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func classifyDeviceConnection(err error) (string, string) {
	switch {
	case errors.Is(err, errDeviceHTTPSRedirect):
		return "https_required", "设备将 HTTP 请求跳转到 HTTPS，请把设备内网地址改为实际的 https:// 地址，并配置设备证书"
	case errors.Is(err, errDeviceRedirectOrigin):
		return "redirect_origin_changed", "设备跳转到了其他地址，请填写设备最终访问地址；登录凭据不会转发到其他地址"
	case errors.Is(err, errDeviceRedirectLimit):
		return "redirect_loop", "设备重定向次数过多，请检查设备地址和反向代理配置"
	case errors.Is(err, errCertificatePin):
		return "certificate_pin_mismatch", "设备证书指纹不匹配，请先核对设备证书"
	case errors.Is(err, errPinnedCertificateTime):
		return "certificate_outside_validity", "固定的设备证书已过期或尚未生效"
	case errors.Is(err, http.ErrSchemeMismatch):
		return "https_on_http_port", "该端口返回 HTTP 响应，请核对设备协议和 HTTPS 端口"
	}
	var cert *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	if errors.As(err, &cert) || errors.As(err, &unknown) || errors.As(err, &invalid) || errors.As(err, &hostname) {
		return "tls_certificate_invalid", "设备 TLS 证书校验失败，请配置可信证书并使用证书匹配的地址；没有正确 SAN 的自签名证书可使用已核对的固定指纹"
	}
	var network net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &network) && network.Timeout() {
		return "connection_timeout", "设备连接超时，请检查容器到设备的路由、防火墙和端口"
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "dns_failed", "容器无法解析设备主机名，请检查 DNS 或填写可达的内网 IP"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connection_refused", "设备拒绝连接，请检查端口及设备 Web 服务是否已启动"
	}
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		return "network_unreachable", "容器无法到达设备网络，请检查路由和防火墙"
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return "connection_reset", "设备关闭了连接，请检查协议、端口及设备 Web 服务状态"
	}
	if errors.Is(err, context.Canceled) {
		return "connection_canceled", "设备请求已取消，请重新打开设备"
	}
	return "connection_failed", "无法连接设备，请检查地址、端口与容器网络，或按参考编号查看服务日志"
}

func deviceFailureReason(err error) string {
	var connection *deviceConnectionError
	if errors.As(err, &connection) {
		return connection.reason
	}
	switch {
	case errors.Is(err, errNeedsLogin):
		return "session_expired"
	case errors.Is(err, errLogin):
		return "login_rejected"
	case errors.Is(err, errNanoInteractive), errors.Is(err, errBliInteractive), errors.Is(err, errNativeInteractive):
		return "interactive_auth_required"
	case errors.Is(err, errBliRateLimit), errors.Is(err, errNativeRateLimit):
		return "login_rate_limited"
	case errors.Is(err, errBliProtocol), errors.Is(err, errNativeProtocol):
		return "unsupported_login_protocol"
	case errors.Is(err, sql.ErrNoRows):
		return "credentials_missing"
	}
	var limited *nanoRateLimitError
	if errors.As(err, &limited) {
		return "login_rate_limited"
	}
	return "device_operation_failed"
}

func logDeviceFailure(log *slog.Logger, event string, service Service, stage string, err error) string {
	requestID := token()[:12]
	// Raw HTTP errors can contain authentication URLs, cookies or response bodies.
	u, _ := url.Parse(service.UpstreamURL)
	origin := ""
	if u != nil {
		origin = u.Scheme + "://" + u.Host
	}
	log.Warn(event, "service", service.ID, "type", service.Type, "upstream_origin", origin, "stage", stage, "reason", deviceFailureReason(err), "request_id", requestID)
	return requestID
}

func (a *App) deviceTestError(w http.ResponseWriter, s Service, stage string, err error) {
	requestID := logDeviceFailure(a.log, "device test failed", s, stage, err)
	w.Header().Set("X-WebConsole-Request-ID", requestID)
	jsonError(w, http.StatusBadGateway, fmt.Sprintf("%s（错误码：%s，参考编号：%s）", err.Error(), deviceFailureReason(err), requestID))
}

func checkDeviceConnection(ctx context.Context, service Service, credentials func() (Credentials, error)) (string, error) {
	ss := newSessions()
	p := ss.addPortal("test", "test", time.Minute)
	g := ss.redeem(ss.ticket(p, service.ID), service.ID)
	defer g.close()
	client, err := clientFor(service, g)
	if err != nil {
		return "transport", err
	}
	defer client.Transport.(*http.Transport).CloseIdleConnections()
	if service.Type == "proxy" {
		// Reachability only: do not submit credentials, follow redirects, or logout.
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		response, err := call(ctx, client, "GET", service.UpstreamURL+service.EntryPath, nil)
		if err != nil {
			return "connection", err
		}
		defer finish(response)
		if response.StatusCode >= 500 {
			return "connection", errors.New("设备原页面返回服务错误")
		}
		return "connection", nil
	}
	if service.Type == "pikvm" && strings.HasPrefix(service.UpstreamURL, "http://") {
		// Detect an HTTPS-only endpoint before submitting stored credentials.
		response, err := call(ctx, client, "GET", service.UpstreamURL+"/api/auth/check", nil)
		if err != nil {
			return "preflight", err
		}
		finish(response)
	}
	cred, err := credentials()
	if err != nil {
		return "credentials", err
	}
	adapter := adapterFor(service.Type)
	if err := adapter.Login(ctx, client, service, cred); err != nil {
		return "login", err
	}
	defer func() {
		logoutContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = adapter.Logout(logoutContext, client, service)
	}()
	if err := adapter.Check(ctx, client, service); err != nil {
		return "session_check", err
	}
	return "session_check", nil
}

// TestStoredDevice uses the same adapters as the portal without starting a web
// server. It never changes device configuration or replays control requests.
func TestStoredDevice(ctx context.Context, cfg Config, slug string, log *slog.Logger) error {
	store, err := OpenStore(cfg.DataDir, cfg.Key)
	if err != nil {
		return errors.New("无法打开设备配置数据库")
	}
	defer store.Close()
	service, err := store.BySlug(ctx, slug)
	if err != nil {
		return errors.New("未找到指定设备，请使用设备的访问子域名标识")
	}
	if service.Type == "link" {
		return errors.New("普通链接不进行自动登录测试")
	}
	stage, err := checkDeviceConnection(ctx, service, func() (Credentials, error) { return store.Credentials(ctx, service.ID) })
	if err != nil {
		logDeviceFailure(log, "device test failed", service, stage, err)
		return err
	}
	log.Info("device test successful", "service", service.ID, "type", service.Type)
	return nil
}
