package app

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

type Service struct {
	ID                    string `json:"id"`
	Name                  string `json:"name"`
	Slug                  string `json:"slug"`
	Type                  string `json:"type"`
	UpstreamURL           string `json:"upstreamUrl"`
	EntryPath             string `json:"entryPath"`
	Group                 string `json:"group"`
	Notes                 string `json:"notes"`
	TrustedCA             string `json:"trustedCa,omitempty"`
	CertificatePin        string `json:"certificatePin,omitempty"`
	IgnoreCertificateTime bool   `json:"ignoreCertificateTime,omitempty"`
	HasCredentials        bool   `json:"hasCredentials"`
	TPLinkProtocol        string `json:"tplinkProtocol,omitempty"`
}
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type serviceInput struct {
	Service
	Credentials *Credentials `json:"credentials,omitempty"`
}

func validateCredentials(c *Credentials) error {
	if c != nil && (c.Username == "" || c.Password == "" || len(c.Username) > 256 || len(c.Password) > 4096) {
		return errors.New("账号和密码必填且长度须在限制内")
	}
	return nil
}

type Store struct {
	db   *sql.DB
	aead cipher.AEAD
}

func OpenStore(dir string, key []byte) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "webconsole.db")
	// Older deployments keep their filename until an offline migration. Opening
	// the existing database prevents a rename from creating an empty workspace.
	if _, err := os.Stat(path); os.IsNotExist(err) {
		legacyPath := filepath.Join(dir, "webcontrol.db")
		if _, err := os.Stat(legacyPath); err == nil {
			path = legacyPath
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;`)
	if err == nil {
		var version int
		err = db.QueryRow("PRAGMA user_version").Scan(&version)
		if err == nil && version > 1 {
			err = errors.New("数据库版本比本程序更新，请使用匹配的 web-console 版本")
		}
		if err == nil && version == 0 {
			_, err = db.Exec(`BEGIN; CREATE TABLE IF NOT EXISTS services (id TEXT PRIMARY KEY, slug TEXT NOT NULL UNIQUE, config BLOB NOT NULL, credentials BLOB); PRAGMA user_version=1; COMMIT;`)
		}
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	_ = os.Chmod(path, 0600)
	return &Store{db: db, aead: aead}, nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) List(ctx context.Context) ([]Service, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT config, credentials IS NOT NULL FROM services ORDER BY slug")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Service{}
	for rows.Next() {
		var b []byte
		var item Service
		var has bool
		if err := rows.Scan(&b, &has); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &item); err != nil {
			return nil, err
		}
		item.HasCredentials = has
		items = append(items, item)
	}
	return items, rows.Err()
}
func (s *Store) Get(ctx context.Context, id string) (Service, error) {
	var b []byte
	var item Service
	var has bool
	err := s.db.QueryRowContext(ctx, "SELECT config, credentials IS NOT NULL FROM services WHERE id=?", id).Scan(&b, &has)
	if err != nil {
		return item, err
	}
	err = json.Unmarshal(b, &item)
	item.HasCredentials = has
	return item, err
}
func (s *Store) BySlug(ctx context.Context, slug string) (Service, error) {
	var id string
	err := s.db.QueryRowContext(ctx, "SELECT id FROM services WHERE slug=?", slug).Scan(&id)
	if err != nil {
		return Service{}, err
	}
	return s.Get(ctx, id)
}
func (s *Store) Save(ctx context.Context, item Service) error {
	return s.SaveWithCredentials(ctx, item, nil)
}
func (s *Store) SaveWithCredentials(ctx context.Context, item Service, cred *Credentials) error {
	item.HasCredentials = false
	b, err := json.Marshal(item)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO services(id,slug,config) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET slug=excluded.slug, config=excluded.config`, item.ID, item.Slug, b)
	if err != nil {
		return err
	}
	if !storesCredentials(item.Type) {
		_, err = tx.ExecContext(ctx, "UPDATE services SET credentials=NULL WHERE id=?", item.ID)
	} else if cred != nil {
		var encrypted []byte
		encrypted, err = s.encryptCredentials(item.ID, *cred)
		if err == nil {
			_, err = tx.ExecContext(ctx, "UPDATE services SET credentials=? WHERE id=?", encrypted, item.ID)
		}
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) Delete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM services WHERE id=?", id)
	return err
}
func (s *Store) SetCredentials(ctx context.Context, id string, c Credentials) error {
	item, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if !storesCredentials(item.Type) {
		return errors.New("此类型不保存账号密码")
	}
	encrypted, err := s.encryptCredentials(id, c)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, "UPDATE services SET credentials=? WHERE id=?", encrypted, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
func (s *Store) encryptCredentials(id string, c Credentials) ([]byte, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	encrypted := s.aead.Seal(nonce, nonce, b, []byte(id))
	return encrypted, nil
}
func (s *Store) Credentials(ctx context.Context, id string) (Credentials, error) {
	var b []byte
	var c Credentials
	if err := s.db.QueryRowContext(ctx, "SELECT credentials FROM services WHERE id=?", id).Scan(&b); err != nil {
		return c, err
	}
	if len(b) < s.aead.NonceSize() {
		return c, errors.New("未配置设备账号密码")
	}
	plain, err := s.aead.Open(nil, b[:s.aead.NonceSize()], b[s.aead.NonceSize():], []byte(id))
	if err != nil {
		return c, errors.New("设备凭据无法解密，请检查加密密钥")
	}
	err = json.Unmarshal(plain, &c)
	return c, err
}
func storesCredentials(kind string) bool { return kind != "link" && kind != "proxy" }

func validateService(s *Service, cfg Config) error {
	s.Name = strings.TrimSpace(s.Name)
	s.Slug = strings.ToLower(strings.TrimSpace(s.Slug))
	if s.Name == "" || len(s.Name) > 120 || !validSlug(s.Slug) {
		return errors.New("名称必填，子域名仅支持小写字母、数字和连字符")
	}
	if s.Type != "pikvm" && s.Type != "nanokvm" && s.Type != "blikvm" && s.Type != "openwrt" && s.Type != "link" && s.Type != "proxy" && !quickLoginKind(s.Type) {
		return errors.New("不支持的设备类型")
	}
	u, err := url.Parse(s.UpstreamURL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("设备地址必须是 HTTP(S) 地址，不能包含账号密码、查询参数或片段")
	}
	if s.Type == "tplink" {
		if s.TPLinkProtocol == "" {
			s.TPLinkProtocol = "slp"
		}
		if s.TPLinkProtocol != "slp" {
			return errors.New("不支持的 TP-Link 快速登录协议")
		}
		if u.Path == "/login.htm" {
			u.Path = ""
			s.UpstreamURL = u.String()
		}
	} else {
		s.TPLinkProtocol = ""
	}
	if s.Type != "link" && u.Path != "" && u.Path != "/" {
		return errors.New("代理设备地址只能包含协议、主机和端口")
	}
	if u.Host == cfg.portalHost() || u.Hostname() == cfg.DeviceDomain || strings.HasSuffix(u.Hostname(), "."+cfg.DeviceDomain) {
		return errors.New("设备地址不能指向门户或设备代理域名")
	}
	if s.Type == "link" {
		s.TrustedCA = ""
		s.CertificatePin = ""
		s.IgnoreCertificateTime = false
		if s.EntryPath == "" {
			s.EntryPath = "/"
		}
	} else {
		s.UpstreamURL = strings.TrimRight(s.UpstreamURL, "/")
		if s.EntryPath == "" {
			if s.Type == "pikvm" {
				s.EntryPath = "/kvm/"
			} else if s.Type == "nanokvm" {
				s.EntryPath = "/#/"
			} else if s.Type == "blikvm" {
				s.EntryPath = "/matrix"
			} else if s.Type == "glinet" {
				s.EntryPath = "/#/"
			} else if s.Type == "pve" || s.Type == "tplink" || s.Type == "proxy" {
				s.EntryPath = "/"
			} else if s.Type == "esxi" {
				s.EntryPath = "/ui/"
			} else if s.Type == "xiaomi" {
				s.EntryPath = "/cgi-bin/luci/;stok=" + nativeBrowserMarker + "/web/home"
			} else {
				s.EntryPath = "/cgi-bin/luci/"
			}
		}
	}
	entry, err := url.Parse(s.EntryPath)
	if err != nil || !strings.HasPrefix(s.EntryPath, "/") || strings.HasPrefix(s.EntryPath, "//") || strings.ContainsAny(s.EntryPath, "\\\r\n") || entry.Host != "" || entry.Scheme != "" || strings.HasPrefix(entry.Path, "/__webconsole/") {
		return errors.New("入口路径必须是设备内的相对路径")
	}
	if len(s.Notes) > 2000 || len(s.Group) > 80 || len(s.TrustedCA) > 65536 {
		return fmt.Errorf("配置字段过长")
	}
	s.CertificatePin = normalizePin(s.CertificatePin)
	if s.CertificatePin != "" && u.Scheme != "https" {
		return errors.New("证书指纹只适用于 HTTPS 设备")
	}
	if s.TrustedCA != "" || s.CertificatePin != "" || s.IgnoreCertificateTime {
		if _, err := newTransport(*s); err != nil {
			return err
		}
	}
	return nil
}
