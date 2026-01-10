package network

import "sync"

type ipLimiter struct {
	mu           sync.Mutex
	maxConns     int
	maxStreams   int
	connCounts   map[string]int
	streamCounts map[string]int
}

func newIPLimiter(maxConns, maxStreams int) *ipLimiter {
	return &ipLimiter{
		maxConns:     maxConns,
		maxStreams:   maxStreams,
		connCounts:   make(map[string]int),
		streamCounts: make(map[string]int),
	}
}

func (l *ipLimiter) acquireConn(ip string) bool {
	if l.maxConns <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.connCounts[ip] >= l.maxConns {
		return false
	}
	l.connCounts[ip]++
	return true
}

func (l *ipLimiter) releaseConn(ip string) {
	if l.maxConns <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.connCounts[ip] <= 1 {
		delete(l.connCounts, ip)
		return
	}
	l.connCounts[ip]--
}

func (l *ipLimiter) acquireStream(ip string) bool {
	if l.maxStreams <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.streamCounts[ip] >= l.maxStreams {
		return false
	}
	l.streamCounts[ip]++
	return true
}

func (l *ipLimiter) releaseStream(ip string) {
	if l.maxStreams <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.streamCounts[ip] <= 1 {
		delete(l.streamCounts, ip)
		return
	}
	l.streamCounts[ip]--
}
