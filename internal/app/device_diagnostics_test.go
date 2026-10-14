package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestDeviceConnectionErrorsAreSpecificAndSanitized(t *testing.T) {
	for _, tc := range []struct {
		err    error
		reason string
	}{
		{errDeviceHTTPSRedirect, "https_required"},
		{errDeviceRedirectOrigin, "redirect_origin_changed"},
		{errDeviceRedirectLimit, "redirect_loop"},
		{context.DeadlineExceeded, "connection_timeout"},
		{&net.DNSError{Err: "sensitive-dns-body", Name: "device.invalid", IsNotFound: true}, "dns_failed"},
		{syscall.ECONNREFUSED, "connection_refused"},
		{syscall.EHOSTUNREACH, "network_unreachable"},
		{syscall.ECONNRESET, "connection_reset"},
		{http.ErrSchemeMismatch, "https_on_http_port"},
		{errCertificatePin, "certificate_pin_mismatch"},
		{errPinnedCertificateTime, "certificate_outside_validity"},
		{errors.New("sensitive-server-body"), "connection_failed"},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			err := connectionError(&url.Error{Op: "Post", URL: "https://device.invalid/api/login?password=sensitive-password", Err: tc.err})
			if deviceFailureReason(err) != tc.reason || !errors.Is(err, tc.err) {
				t.Fatalf("incorrect classification: %s", err)
			}
			if strings.Contains(err.Error(), "sensitive-") || strings.Contains(err.Error(), "/api/login") {
				t.Fatal("connection error exposed request or response details")
			}
			wrapped := connectionError(fmt.Errorf("sensitive-wrapper: %w", err))
			if wrapped.Error() != err.Error() {
				t.Fatal("existing connection diagnosis exposed an outer wrapper")
			}
		})
	}
}

func TestDeviceRedirectsRemainOnOrigin(t *testing.T) {
	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetRequests.Add(1)
		w.WriteHeader(200)
	}))
	defer target.Close()
	for _, tc := range []struct{ name, location, reason string }{
		{"same host HTTPS", "https://127.0.0.1/", "https_required"},
		{"different endpoint", target.URL + "/?password=sensitive-password", "redirect_origin_changed"},
		{"redirect loop", "/loop", "redirect_loop"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, tc.location, 307) }))
			defer server.Close()
			service := Service{ID: "device", UpstreamURL: server.URL}
			sessions := newSessions()
			portal := sessions.addPortal("owner", "", time.Hour)
			gateway := sessions.redeem(sessions.ticket(portal, service.ID), service.ID)
			if gateway == nil {
				t.Fatal("missing gateway")
			}
			defer gateway.close()
			client, err := clientFor(service, gateway)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Transport.(*http.Transport).CloseIdleConnections()
			_, err = call(context.Background(), client, "GET", server.URL, nil)
			if err == nil || deviceFailureReason(err) != tc.reason {
				t.Fatalf("incorrect redirect error: %v", err)
			}
		})
	}
	if targetRequests.Load() != 0 {
		t.Fatal("request reached an unapproved redirect target")
	}
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{"https://DEVICE.example", "https://device.example:443", true},
		{"http://device.example", "http://device.example:80", true},
		{"http://device.example", "https://device.example", false},
		{"https://device.example", "https://device.example:8443", false},
	} {
		a, _ := url.Parse(tc.a)
		b, _ := url.Parse(tc.b)
		if sameDeviceOrigin(a, b) != tc.same {
			t.Fatal("incorrect origin comparison")
		}
	}
}

func TestStoredDeviceDiagnosticUsesSavedCredentials(t *testing.T) {
	a := testApp(t)
	device := newPiKVM(t)
	service := addPi(t, a, device, "diagnostic")
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	if err := TestStoredDevice(context.Background(), a.cfg, service.Slug, logger); err != nil {
		t.Fatal(err)
	}
	if device.loginCount.Load() != 1 || !strings.Contains(logs.String(), "device test successful") {
		t.Fatal("saved-device test did not authenticate exactly once")
	}
	if strings.Contains(logs.String(), "password") {
		t.Fatal("saved credentials were logged")
	}
	credentials, err := a.store.Credentials(context.Background(), service.ID)
	if err != nil || credentials.Password != "password" {
		t.Fatal("diagnostics changed stored credentials")
	}
	if TestStoredDevice(context.Background(), a.cfg, "does-not-exist", logger) == nil {
		t.Fatal("unknown device accepted")
	}
}

func TestPiKVMHTTPSPreflightNeverSubmitsStoredPassword(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			posts.Add(1)
		}
		http.Redirect(w, r, "https://"+r.Host+r.URL.Path, 301)
	}))
	defer server.Close()
	stage, err := checkDeviceConnection(context.Background(), Service{ID: "device", Type: "pikvm", UpstreamURL: server.URL}, func() (Credentials, error) { return Credentials{"admin", "sensitive-password"}, nil })
	if err == nil || stage != "preflight" || deviceFailureReason(err) != "https_required" || posts.Load() != 0 {
		t.Fatal("HTTPS redirect was detected after sending credentials")
	}
	var logs bytes.Buffer
	a := &App{log: slog.New(slog.NewJSONHandler(&logs, nil))}
	w := httptest.NewRecorder()
	a.deviceTestError(w, Service{ID: "device", Type: "pikvm", UpstreamURL: server.URL}, stage, err)
	var event map[string]any
	if err := json.Unmarshal(logs.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if event["reason"] != "https_required" || event["request_id"] != w.Header().Get("X-WebConsole-Request-ID") || !strings.Contains(w.Body.String(), w.Header().Get("X-WebConsole-Request-ID")) {
		t.Fatal("test failure cannot be matched to its log")
	}
	if strings.Contains(logs.String(), "sensitive-") {
		t.Fatal("device failure log exposed credentials")
	}
}
