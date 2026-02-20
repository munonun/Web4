package node

import (
	"container/list"
	"os"
	"strconv"
	"sync"
	"time"
)

type helloSigCacheEntry struct {
	key [32]byte
	sig []byte
	ts  time.Time
}

type helloSigCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	maxSize int
	items   map[[32]byte]*list.Element
	order   *list.List
}

func newHelloSigCache() *helloSigCache {
	ttl := 10 * time.Second
	if raw := os.Getenv("WEB4_HELLO_SIG_CACHE_TTL_SEC"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			ttl = time.Duration(v) * time.Second
		}
	}
	maxSize := 256
	if raw := os.Getenv("WEB4_HELLO_SIG_CACHE_MAX"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			maxSize = v
		}
	}
	return &helloSigCache{
		ttl:     ttl,
		maxSize: maxSize,
		items:   make(map[[32]byte]*list.Element),
		order:   list.New(),
	}
}

func (c *helloSigCache) get(key [32]byte) ([]byte, bool) {
	if c == nil {
		return nil, false
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneExpiredLocked(now)
	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	ent := el.Value.(*helloSigCacheEntry)
	out := make([]byte, len(ent.sig))
	copy(out, ent.sig)
	return out, true
}

func (c *helloSigCache) put(key [32]byte, sig []byte) {
	if c == nil || len(sig) == 0 {
		return
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneExpiredLocked(now)
	if el, ok := c.items[key]; ok {
		ent := el.Value.(*helloSigCacheEntry)
		ent.sig = append(ent.sig[:0], sig...)
		ent.ts = now
		c.order.MoveToFront(el)
		return
	}
	ent := &helloSigCacheEntry{
		key: key,
		sig: append([]byte(nil), sig...),
		ts:  now,
	}
	el := c.order.PushFront(ent)
	c.items[key] = el
	for c.maxSize > 0 && c.order.Len() > c.maxSize {
		back := c.order.Back()
		if back == nil {
			break
		}
		old := back.Value.(*helloSigCacheEntry)
		delete(c.items, old.key)
		c.order.Remove(back)
	}
}

func (c *helloSigCache) pruneExpiredLocked(now time.Time) {
	if c.ttl <= 0 {
		return
	}
	cutoff := now.Add(-c.ttl)
	for {
		back := c.order.Back()
		if back == nil {
			return
		}
		ent := back.Value.(*helloSigCacheEntry)
		if ent.ts.After(cutoff) {
			return
		}
		delete(c.items, ent.key)
		c.order.Remove(back)
	}
}
