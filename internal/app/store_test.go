package app

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyDatabaseRetainsDevicesAndCredentials(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{7}, 32)
	ctx := context.Background()
	store, err := OpenStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	service := Service{ID: "legacy", Slug: "legacy", Name: "Legacy device", Type: "pikvm", UpstreamURL: "https://192.168.1.100"}
	credentials := Credentials{Username: "admin", Password: "legacy-fixture-secret"}
	if err := store.SaveWithCredentials(ctx, service, &credentials); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "webconsole.db"), filepath.Join(dir, "webcontrol.db")); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	listed, err := store.List(ctx)
	if err != nil || len(listed) != 1 || listed[0].ID != service.ID || !listed[0].HasCredentials {
		t.Fatal("rename lost the existing device")
	}
	saved, err := store.Credentials(ctx, service.ID)
	if err != nil || saved != credentials {
		t.Fatal("rename lost the encrypted credentials")
	}
	if _, err := os.Stat(filepath.Join(dir, "webconsole.db")); !os.IsNotExist(err) {
		t.Fatal("legacy deployment unexpectedly created a fresh database")
	}
}

func TestEncryptedCredentialsAndPersistence(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{7}, 32)
	ctx := context.Background()
	s, err := OpenStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	item := Service{ID: "one", Slug: "one", Name: "设备", Type: "pikvm", UpstreamURL: "http://127.0.0.1"}
	cred := Credentials{Username: "admin", Password: "unique-secret-password"}
	if err = s.SaveWithCredentials(ctx, item, &cred); err != nil {
		t.Fatal(err)
	}
	var config, encrypted []byte
	if err = s.db.QueryRow("SELECT config,credentials FROM services WHERE id='one'").Scan(&config, &encrypted); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(config, []byte(cred.Password)) || bytes.Contains(encrypted, []byte(cred.Password)) {
		t.Fatal("plaintext secret persisted")
	}
	got, err := s.Credentials(ctx, item.ID)
	if err != nil || got != cred {
		t.Fatalf("roundtrip: %v", err)
	}
	item.Name = "renamed"
	if err = s.Save(ctx, item); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Credentials(ctx, item.ID)
	if got != cred {
		t.Fatal("metadata update lost credentials")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	listed, err := s.List(ctx)
	if err != nil || len(listed) != 1 || !listed[0].HasCredentials {
		t.Fatalf("persistence: %v", err)
	}
	// Authenticated encryption binds ciphertext to the device ID.
	other := item
	other.ID = "two"
	other.Slug = "two"
	if err = s.Save(ctx, other); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("UPDATE services SET credentials=? WHERE id='two'", encrypted); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Credentials(ctx, "two"); err == nil {
		t.Fatal("cross-device ciphertext accepted")
	}
	item.Type = "link"
	if err = s.Save(ctx, item); err != nil {
		t.Fatal(err)
	}
	gotItem, _ := s.Get(ctx, item.ID)
	if gotItem.HasCredentials {
		t.Fatal("link retained device password")
	}
	s.Close()
	s, err = OpenStore(dir, bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.Credentials(ctx, "two"); err == nil {
		t.Fatal("wrong key accepted")
	}
}
func TestServiceValidation(t *testing.T) {
	cfg := Config{PortalURL: "https://control.example.com", DeviceDomain: "devices.example.com"}
	for _, raw := range []string{"https://user:secret@192.168.1.1", "file:///etc/passwd", "http://control.example.com", "http://one.devices.example.com", "http://192.168.1.1/path", "http://192.168.1.1?password=secret"} {
		s := Service{Name: "test", Slug: "test", Type: "pikvm", UpstreamURL: raw}
		if validateService(&s, cfg) == nil {
			t.Errorf("accepted invalid upstream %q", raw)
		}
	}
	s := Service{Name: "test", Slug: "TEST", Type: "openwrt", UpstreamURL: "http://192.168.1.1"}
	if err := validateService(&s, cfg); err != nil || s.EntryPath != "/cgi-bin/luci/" || s.Slug != "test" {
		t.Fatalf("defaults: %v", err)
	}
	for _, entry := range []string{"//evil.example", "/\\evil.example", "/__webconsole/start", "https://evil.example", "/x\r\nheader"} {
		s.EntryPath = entry
		if validateService(&s, cfg) == nil {
			t.Errorf("accepted bad entry %q", entry)
		}
	}
}

func TestIgnoreCertificateTimeConfiguration(t *testing.T) {
	cfg := Config{PortalURL: "https://control.example.com", DeviceDomain: "devices.example.com"}
	for _, raw := range []string{"https://192.168.1.13", "http://192.168.1.13"} {
		s := Service{Name: "GLKVM", Slug: "glkvm", Type: "glinet", UpstreamURL: raw, IgnoreCertificateTime: true}
		if validateService(&s, cfg) == nil {
			t.Fatal("time override accepted without a certificate pin")
		}
		if _, err := newTransport(s); err == nil {
			t.Fatal("transport accepted a time override without a pin")
		}
	}
	s := Service{ID: "glkvm", Name: "GLKVM", Slug: "glkvm", Type: "glinet", UpstreamURL: "https://192.168.1.13", CertificatePin: string(bytes.Repeat([]byte("01"), 32)), IgnoreCertificateTime: true}
	if err := validateService(&s, cfg); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(t.TempDir(), bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.Save(ctx, s); err != nil {
		t.Fatal(err)
	}
	saved, err := store.Get(ctx, s.ID)
	if err != nil || !saved.IgnoreCertificateTime {
		t.Fatal("time override was not persisted", err)
	}
	s.IgnoreCertificateTime = false
	if err := store.Save(ctx, s); err != nil {
		t.Fatal(err)
	}
	saved, err = store.Get(ctx, s.ID)
	if err != nil || saved.IgnoreCertificateTime {
		t.Fatal("time override was not disabled", err)
	}
	s.Type = "link"
	s.IgnoreCertificateTime = true
	if err := validateService(&s, cfg); err != nil || s.IgnoreCertificateTime || s.CertificatePin != "" {
		t.Fatal("ordinary link retained the TLS override")
	}
}
func TestAtomicSaveDuplicateSlug(t *testing.T) {
	s, err := OpenStore(t.TempDir(), bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	one := Service{ID: "one", Slug: "dup", Type: "pikvm"}
	if err = s.Save(ctx, one); err != nil {
		t.Fatal(err)
	}
	other := one
	other.ID = "two"
	if err = s.SaveWithCredentials(ctx, other, &Credentials{"admin", "secret"}); err == nil {
		t.Fatal("duplicate accepted")
	}
	if _, err = s.Get(ctx, "two"); err != sql.ErrNoRows {
		t.Fatal("partial row persisted")
	}
}
