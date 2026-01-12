package peer

import (
	"bufio"
	"container/list"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"web4mvp/internal/proto"
	"web4mvp/internal/store"
)

const (
	DefaultMemberCap       = 512
	DefaultMemberTTL       = 30 * time.Minute
	DefaultMemberLoadLimit = 512
	maxMemberScanSize      = 2 * proto.MaxFrameSize
)

type MemberOptions struct {
	Cap       int
	TTL       time.Duration
	LoadLimit int
}

type MemberStore struct {
	mu    sync.Mutex
	path  string
	cap   int
	ttl   time.Duration
	hot   map[string]*list.Element
	order *list.List
}

type memberEntry struct {
	key       string
	id        [32]byte
	expiresAt time.Time
}

type diskMember struct {
	NodeID string `json:"node_id"`
}

func NewMemberStore(path string, opts MemberOptions) (*MemberStore, error) {
	capacity := opts.Cap
	if capacity <= 0 {
		capacity = DefaultMemberCap
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultMemberTTL
	}
	loadLimit := opts.LoadLimit
	if loadLimit <= 0 {
		loadLimit = capacity
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	s := &MemberStore{
		path:  path,
		cap:   capacity,
		ttl:   ttl,
		hot:   make(map[string]*list.Element),
		order: list.New(),
	}
	if loadLimit > 0 {
		if err := s.loadLast(loadLimit); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *MemberStore) Add(id [32]byte, persist bool) error {
	if isZeroNodeID(id) {
		return fmt.Errorf("missing node_id")
	}
	key := hex.EncodeToString(id[:])

	s.mu.Lock()
	s.pruneLocked()
	if el, ok := s.hot[key]; ok {
		ent := el.Value.(*memberEntry)
		ent.id = id
		ent.expiresAt = time.Now().Add(s.ttl)
		s.order.MoveToFront(el)
		s.mu.Unlock()
		if !persist {
			return nil
		}
		rec := diskMember{NodeID: key}
		return store.AppendJSONL(s.path, rec)
	}
	if s.cap > 0 && len(s.hot) >= s.cap {
		s.evictLocked(len(s.hot) - s.cap + 1)
	}
	ent := &memberEntry{key: key, id: id, expiresAt: time.Now().Add(s.ttl)}
	el := s.order.PushFront(ent)
	s.hot[key] = el
	s.mu.Unlock()

	if !persist {
		return nil
	}
	rec := diskMember{NodeID: key}
	return store.AppendJSONL(s.path, rec)
}

func (s *MemberStore) Has(id [32]byte) bool {
	if isZeroNodeID(id) {
		return false
	}
	key := hex.EncodeToString(id[:])
	s.mu.Lock()
	s.pruneLocked()
	_, ok := s.hot[key]
	s.mu.Unlock()
	return ok
}

func (s *MemberStore) Refresh() error {
	if s == nil {
		return nil
	}
	limit := s.cap
	if limit <= 0 {
		limit = DefaultMemberCap
	}
	return s.loadLast(limit)
}

func (s *MemberStore) List() [][32]byte {
	s.mu.Lock()
	s.pruneLocked()
	out := make([][32]byte, 0, len(s.hot))
	for el := s.order.Front(); el != nil; el = el.Next() {
		ent := el.Value.(*memberEntry)
		out = append(out, ent.id)
	}
	s.mu.Unlock()
	return out
}

func (s *MemberStore) Len() int {
	s.mu.Lock()
	s.pruneLocked()
	n := len(s.hot)
	s.mu.Unlock()
	return n
}

func (s *MemberStore) pruneLocked() {
	if s.ttl <= 0 {
		return
	}
	now := time.Now()
	for el := s.order.Back(); el != nil; {
		prev := el.Prev()
		ent := el.Value.(*memberEntry)
		if ent.expiresAt.After(now) {
			el = prev
			continue
		}
		delete(s.hot, ent.key)
		s.order.Remove(el)
		el = prev
	}
}

func (s *MemberStore) evictLocked(n int) {
	for n > 0 {
		el := s.order.Back()
		if el == nil {
			return
		}
		ent := el.Value.(*memberEntry)
		delete(s.hot, ent.key)
		s.order.Remove(el)
		n--
	}
}

func (s *MemberStore) loadLast(limit int) error {
	records, err := readLastMembers(s.path, limit)
	if err != nil {
		return err
	}
	for _, rec := range records {
		idBytes, err := hex.DecodeString(rec.NodeID)
		if err != nil || len(idBytes) != 32 {
			continue
		}
		var id [32]byte
		copy(id[:], idBytes)
		_ = s.Add(id, false)
	}
	return nil
}

func readLastMembers(path string, n int) ([]diskMember, error) {
	if n <= 0 {
		return nil, nil
	}
	paths := memberScanPaths(path)
	out := make([]diskMember, 0, n)
	for i := len(paths) - 1; i >= 0; i-- {
		f, err := os.Open(paths[i])
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), maxMemberScanSize)
		for sc.Scan() {
			var rec diskMember
			if err := json.Unmarshal(sc.Bytes(), &rec); err == nil {
				if len(out) < n {
					out = append(out, rec)
				} else {
					copy(out, out[1:])
					out[n-1] = rec
				}
			}
		}
		if err := sc.Err(); err != nil {
			_ = f.Close()
			return nil, err
		}
		_ = f.Close()
	}
	return out, nil
}

func memberScanPaths(path string) []string {
	out := make([]string, 0, store.MaxRotations+1)
	out = append(out, path)
	for i := 1; i <= store.MaxRotations; i++ {
		out = append(out, fmt.Sprintf("%s.%d", path, i))
	}
	return out
}
