package peer

import (
	"container/list"
	"sync"
	"time"
)

const (
	DefaultCandidateCap = 512
	DefaultCandidateTTL = 30 * time.Minute
)

type CandidatePool struct {
	mu    sync.Mutex
	cap   int
	ttl   time.Duration
	hot   map[string]*list.Element
	order *list.List
}

type candidateEntry struct {
	addr      string
	expiresAt time.Time
}

func NewCandidatePool(capacity int, ttl time.Duration) *CandidatePool {
	if capacity <= 0 {
		capacity = DefaultCandidateCap
	}
	if ttl <= 0 {
		ttl = DefaultCandidateTTL
	}
	return &CandidatePool{
		cap:   capacity,
		ttl:   ttl,
		hot:   make(map[string]*list.Element),
		order: list.New(),
	}
}

func (c *CandidatePool) Add(addr string) {
	if addr == "" {
		return
	}
	c.mu.Lock()
	c.pruneLocked()
	if el, ok := c.hot[addr]; ok {
		ent := el.Value.(*candidateEntry)
		ent.expiresAt = time.Now().Add(c.ttl)
		c.order.MoveToFront(el)
		c.mu.Unlock()
		return
	}
	if c.cap > 0 && len(c.hot) >= c.cap {
		c.evictLocked(len(c.hot) - c.cap + 1)
	}
	ent := &candidateEntry{addr: addr, expiresAt: time.Now().Add(c.ttl)}
	el := c.order.PushFront(ent)
	c.hot[addr] = el
	c.mu.Unlock()
}

func (c *CandidatePool) Has(addr string) bool {
	c.mu.Lock()
	c.pruneLocked()
	_, ok := c.hot[addr]
	c.mu.Unlock()
	return ok
}

func (c *CandidatePool) List() []string {
	c.mu.Lock()
	c.pruneLocked()
	out := make([]string, 0, len(c.hot))
	for el := c.order.Front(); el != nil; el = el.Next() {
		ent := el.Value.(*candidateEntry)
		out = append(out, ent.addr)
	}
	c.mu.Unlock()
	return out
}

func (c *CandidatePool) pruneLocked() {
	now := time.Now()
	for el := c.order.Back(); el != nil; {
		prev := el.Prev()
		ent := el.Value.(*candidateEntry)
		if ent.expiresAt.After(now) {
			el = prev
			continue
		}
		delete(c.hot, ent.addr)
		c.order.Remove(el)
		el = prev
	}
}

func (c *CandidatePool) evictLocked(n int) {
	for n > 0 {
		el := c.order.Back()
		if el == nil {
			return
		}
		ent := el.Value.(*candidateEntry)
		delete(c.hot, ent.addr)
		c.order.Remove(el)
		n--
	}
}
