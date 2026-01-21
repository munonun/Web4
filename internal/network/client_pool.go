package network

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

const (
	clientMaxRetries  = 3
	clientBackoffBase = 100 * time.Millisecond
	clientBackoffMax  = 1 * time.Second
	clientConnIdle    = 30 * time.Second
	clientTimeout     = 8 * time.Second
)

type pooledConn struct {
	conn        *quic.Conn
	lastUsed    time.Time
	established time.Time
}

type addrFailure struct {
	count int
	last  time.Time
}

type clientPool struct {
	mu        sync.Mutex
	conns     map[string]*pooledConn
	failures  map[string]*addrFailure
	idleAfter time.Duration
}

func newClientPool(idleAfter time.Duration) *clientPool {
	if idleAfter <= 0 {
		idleAfter = clientConnIdle
	}
	return &clientPool{
		conns:     make(map[string]*pooledConn),
		failures:  make(map[string]*addrFailure),
		idleAfter: idleAfter,
	}
}

func (p *clientPool) get(ctx context.Context, addr string, tlsConf *tls.Config, quicConf *quic.Config) (*quic.Conn, error) {
	if addr == "" {
		return nil, errors.New("missing addr")
	}
	now := time.Now()
	p.mu.Lock()
	if ent, ok := p.conns[addr]; ok {
		if ent.conn.Context().Err() == nil && now.Sub(ent.lastUsed) <= p.idleAfter {
			ent.lastUsed = now
			conn := ent.conn
			p.mu.Unlock()
			return conn, nil
		}
		delete(p.conns, addr)
		conn := ent.conn
		p.mu.Unlock()
		_ = conn.CloseWithError(0, "stale")
	} else {
		p.mu.Unlock()
	}
	debugLog("quic dial to %s", addr)
	conn, err := quic.DialAddr(ctx, addr, tlsConf, quicConf)
	if err != nil {
		return nil, err
	}
	debugLog("quic conn established to %s", addr)
	p.mu.Lock()
	p.conns[addr] = &pooledConn{conn: conn, lastUsed: now, established: now}
	p.mu.Unlock()
	return conn, nil
}

func (p *clientPool) touch(addr string, conn *quic.Conn) {
	if p == nil || addr == "" || conn == nil {
		return
	}
	now := time.Now()
	p.mu.Lock()
	if ent, ok := p.conns[addr]; ok && ent.conn == conn {
		ent.lastUsed = now
	}
	p.mu.Unlock()
}

func (p *clientPool) drop(addr string, conn *quic.Conn, reason string) {
	if p == nil || addr == "" || conn == nil {
		return
	}
	p.mu.Lock()
	if ent, ok := p.conns[addr]; ok && ent.conn == conn {
		delete(p.conns, addr)
	}
	p.mu.Unlock()
	_ = conn.CloseWithError(0, reason)
}

func (p *clientPool) forget(addr string, conn *quic.Conn) {
	if p == nil || addr == "" || conn == nil {
		return
	}
	p.mu.Lock()
	if ent, ok := p.conns[addr]; ok && ent.conn == conn {
		delete(p.conns, addr)
	}
	p.mu.Unlock()
}

func (p *clientPool) establishedAt(addr string, conn *quic.Conn) (time.Time, bool) {
	if p == nil || addr == "" || conn == nil {
		return time.Time{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	ent, ok := p.conns[addr]
	if !ok || ent.conn != conn {
		return time.Time{}, false
	}
	return ent.established, !ent.established.IsZero()
}

func (p *clientPool) recordFailure(addr string) int {
	if p == nil || addr == "" {
		return 0
	}
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	ent := p.failures[addr]
	if ent == nil {
		ent = &addrFailure{}
		p.failures[addr] = ent
	}
	ent.count++
	ent.last = now
	return ent.count
}

func (p *clientPool) resetFailures(addr string) {
	if p == nil || addr == "" {
		return
	}
	p.mu.Lock()
	delete(p.failures, addr)
	p.mu.Unlock()
}

func withDefaultTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		return context.WithTimeout(context.Background(), clientTimeout)
	}
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, clientTimeout)
}
