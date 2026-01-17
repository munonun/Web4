package main

import (
	"sync"
	"time"
)

const (
	defaultHostRateLimit = 50
	defaultNodeRateLimit = 20
	defaultRateWindow    = time.Second
)

type rateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	buckets map[string]*rateBucket
}

type rateBucket struct {
	count int
	reset time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	if window <= 0 {
		window = defaultRateWindow
	}
	return &rateLimiter{
		limit:   limit,
		window: window,
		buckets: make(map[string]*rateBucket),
	}
}

func (r *rateLimiter) Allow(key string) bool {
	if r == nil || key == "" || r.limit <= 0 {
		return true
	}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.buckets[key]
	if !ok || now.After(b.reset) {
		r.buckets[key] = &rateBucket{count: 1, reset: now.Add(r.window)}
		return true
	}
	if b.count >= r.limit {
		return false
	}
	b.count++
	return true
}

var recvHostLimiter = newRateLimiter(defaultHostRateLimit, defaultRateWindow)
var recvNodeLimiter = newRateLimiter(defaultNodeRateLimit, defaultRateWindow)

func resetRecvLimiters(hostLimit, nodeLimit int, window time.Duration) {
	recvHostLimiter = newRateLimiter(hostLimit, window)
	recvNodeLimiter = newRateLimiter(nodeLimit, window)
}
