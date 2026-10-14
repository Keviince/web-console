package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/http/cookiejar"
	"sync"
	"time"
)

const portalCookie = "__Host-wc_portal"
const gatewayCookie = "__Host-wc_gateway"
const transactionCookie = "__Host-wc_oidc"

func token() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

type portalSession struct {
	ID, Subject, Name, CSRF string
	Expires                 time.Time
}
type authTransaction struct {
	State, Nonce, Verifier, Browser, ReturnTo string
	Expires                                   time.Time
}
type launchTicket struct {
	PortalID, ServiceID string
	Expires             time.Time
}
type gatewaySession struct {
	ID, PortalID, ServiceID, Subject, CSRF string
	Expires                                time.Time
	Jar                                    *cookiejar.Jar
	authMu                                 sync.Mutex
	Version                                uint64
	LastAttempt                            time.Time
	LastError                              error
	RetryAfter                             time.Time
	Manual                                 bool
	connMu                                 sync.Mutex
	conns                                  map[net.Conn]struct{}
	closed                                 bool
	ctx                                    context.Context
	cancel                                 context.CancelFunc
}

func (s *gatewaySession) track(c net.Conn) bool {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if s.closed {
		c.Close()
		return false
	}
	s.conns[c] = struct{}{}
	return true
}
func (s *gatewaySession) untrack(c net.Conn) { s.connMu.Lock(); delete(s.conns, c); s.connMu.Unlock() }
func (s *gatewaySession) disconnect() {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	for c := range s.conns {
		_ = c.Close()
	}
	s.conns = make(map[net.Conn]struct{})
}
func (s *gatewaySession) close() {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	for c := range s.conns {
		_ = c.Close()
	}
	s.conns = make(map[net.Conn]struct{})
}
func (s *gatewaySession) isClosed() bool { s.connMu.Lock(); defer s.connMu.Unlock(); return s.closed }

type sessionStore struct {
	mu           sync.Mutex
	portals      map[string]*portalSession
	gateways     map[string]*gatewaySession
	transactions map[string]authTransaction
	tickets      map[string]launchTicket
}

func newSessions() *sessionStore {
	return &sessionStore{portals: map[string]*portalSession{}, gateways: map[string]*gatewaySession{}, transactions: map[string]authTransaction{}, tickets: map[string]launchTicket{}}
}
func (s *sessionStore) portal(id string) *portalSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.portals[id]
	if p == nil || !time.Now().Before(p.Expires) {
		return nil
	}
	return p
}
func (s *sessionStore) addPortal(sub, name string, ttl time.Duration) *portalSession {
	p := &portalSession{ID: token(), Subject: sub, Name: name, CSRF: token(), Expires: time.Now().Add(ttl)}
	s.mu.Lock()
	s.portals[p.ID] = p
	s.mu.Unlock()
	return p
}
func (s *sessionStore) gateway(id, serviceID string) *gatewaySession {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.gateways[id]
	if g == nil || g.ServiceID != serviceID {
		return nil
	}
	p := s.portals[g.PortalID]
	if p == nil || !time.Now().Before(p.Expires) || !time.Now().Before(g.Expires) || g.isClosed() {
		return nil
	}
	return g
}
func (s *sessionStore) ticket(p *portalSession, serviceID string) string {
	id := token()
	s.mu.Lock()
	s.tickets[id] = launchTicket{PortalID: p.ID, ServiceID: serviceID, Expires: time.Now().Add(30 * time.Second)}
	s.mu.Unlock()
	return id
}
func (s *sessionStore) redeem(id, serviceID string) *gatewaySession {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tickets[id]
	if !ok || t.ServiceID != serviceID {
		return nil
	}
	delete(s.tickets, id)
	p := s.portals[t.PortalID]
	if p == nil || !time.Now().Before(t.Expires) || !time.Now().Before(p.Expires) {
		return nil
	}
	jar, _ := cookiejar.New(nil)
	g := &gatewaySession{ID: token(), PortalID: p.ID, ServiceID: serviceID, Subject: p.Subject, CSRF: token(), Expires: p.Expires, Jar: jar, conns: map[net.Conn]struct{}{}}
	g.ctx, g.cancel = context.WithDeadline(context.Background(), p.Expires)
	context.AfterFunc(g.ctx, g.close)
	s.gateways[g.ID] = g
	return g
}
func (s *sessionStore) revokePortal(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.portals, id)
	for key, g := range s.gateways {
		if g.PortalID == id {
			g.close()
			delete(s.gateways, key)
		}
	}
	for key, t := range s.tickets {
		if t.PortalID == id {
			delete(s.tickets, key)
		}
	}
}
func (s *sessionStore) revokeDevice(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, g := range s.gateways {
		if g.ServiceID == id {
			g.close()
			delete(s.gateways, key)
		}
	}
	for key, t := range s.tickets {
		if t.ServiceID == id {
			delete(s.tickets, key)
		}
	}
}
func (s *sessionStore) revokeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range s.gateways {
		g.close()
	}
	s.portals = map[string]*portalSession{}
	s.gateways = map[string]*gatewaySession{}
	s.tickets = map[string]launchTicket{}
	s.transactions = map[string]authTransaction{}
}
func (s *sessionStore) prune() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, p := range s.portals {
		if !now.Before(p.Expires) {
			delete(s.portals, k)
		}
	}
	for k, g := range s.gateways {
		if s.portals[g.PortalID] == nil || !now.Before(g.Expires) {
			g.close()
			delete(s.gateways, k)
		}
	}
	for k, t := range s.tickets {
		if !now.Before(t.Expires) {
			delete(s.tickets, k)
		}
	}
	for k, t := range s.transactions {
		if !now.Before(t.Expires) {
			delete(s.transactions, k)
		}
	}
}
