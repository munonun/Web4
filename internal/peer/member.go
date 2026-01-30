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
	DefaultMemberScope     = proto.InviteScopeAll
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
	key        string
	id         [32]byte
	expiresAt  time.Time
	scope      uint32
	inviterID  [32]byte
	inviterSet bool
}

type diskMember struct {
	NodeID        string  `json:"node_id"`
	Scope         *uint32 `json:"scope,omitempty"`
	InviterNodeID string  `json:"inviter_node_id,omitempty"`
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
	return s.AddWithScope(id, DefaultMemberScope, persist)
}

func (s *MemberStore) AddWithScope(id [32]byte, scope uint32, persist bool) error {
	if isZeroNodeID(id) {
		return fmt.Errorf("missing node_id")
	}
	if scope == 0 {
		scope = DefaultMemberScope
	}
	return s.addWithScope(id, scope, [32]byte{}, false, persist, true)
}

func (s *MemberStore) AddInvitedWithScope(id [32]byte, scope uint32, inviterID [32]byte, persist bool) error {
	if isZeroNodeID(inviterID) {
		return fmt.Errorf("missing inviter node_id")
	}
	if scope == 0 {
		scope = DefaultMemberScope
	}
	return s.addWithScope(id, scope, inviterID, true, persist, true)
}

func (s *MemberStore) SetScope(id [32]byte, scope uint32, persist bool) error {
	if isZeroNodeID(id) {
		return fmt.Errorf("missing node_id")
	}
	return s.addWithScope(id, scope, [32]byte{}, false, persist, false)
}

func (s *MemberStore) InviterFor(id [32]byte) ([32]byte, bool) {
	if isZeroNodeID(id) {
		return [32]byte{}, false
	}
	key := hex.EncodeToString(id[:])
	s.mu.Lock()
	s.pruneLocked()
	el, ok := s.hot[key]
	if !ok {
		s.mu.Unlock()
		return [32]byte{}, false
	}
	ent := el.Value.(*memberEntry)
	inviterID := ent.inviterID
	inviterSet := ent.inviterSet
	s.mu.Unlock()
	if !inviterSet {
		return [32]byte{}, false
	}
	return inviterID, true
}

func (s *MemberStore) addWithScope(id [32]byte, scope uint32, inviterID [32]byte, inviterSet bool, persist bool, orScope bool) error {
	key := hex.EncodeToString(id[:])

	s.mu.Lock()
	s.pruneLocked()
	if el, ok := s.hot[key]; ok {
		ent := el.Value.(*memberEntry)
		ent.id = id
		ent.expiresAt = time.Now().Add(s.ttl)
		if orScope {
			ent.scope |= scope
		} else {
			ent.scope = scope
		}
		if inviterSet && !ent.inviterSet {
			ent.inviterID = inviterID
			ent.inviterSet = true
		}
		s.order.MoveToFront(el)
		entScope := ent.scope
		entInviterID := ent.inviterID
		entInviterSet := ent.inviterSet
		s.mu.Unlock()
		if !persist {
			return nil
		}
		rec := diskMember{NodeID: key, Scope: uint32ptr(entScope)}
		if entInviterSet {
			rec.InviterNodeID = hex.EncodeToString(entInviterID[:])
		}
		return store.AppendJSONL(s.path, rec)
	}
	if s.cap > 0 && len(s.hot) >= s.cap {
		s.evictLocked(len(s.hot) - s.cap + 1)
	}
	ent := &memberEntry{
		key:        key,
		id:         id,
		expiresAt:  time.Now().Add(s.ttl),
		scope:      scope,
		inviterID:  inviterID,
		inviterSet: inviterSet,
	}
	el := s.order.PushFront(ent)
	s.hot[key] = el
	s.mu.Unlock()

	if !persist {
		return nil
	}
	rec := diskMember{NodeID: key, Scope: uint32ptr(scope)}
	if inviterSet {
		rec.InviterNodeID = hex.EncodeToString(inviterID[:])
	}
	return store.AppendJSONL(s.path, rec)
}

func (s *MemberStore) Has(id [32]byte) bool {
	return s.HasScope(id, 0)
}

func (s *MemberStore) HasScope(id [32]byte, scope uint32) bool {
	if isZeroNodeID(id) {
		return false
	}
	key := hex.EncodeToString(id[:])
	s.mu.Lock()
	s.pruneLocked()
	el, ok := s.hot[key]
	if !ok {
		s.mu.Unlock()
		return false
	}
	ent := el.Value.(*memberEntry)
	s.mu.Unlock()
	if scope == 0 {
		return ent.scope != 0
	}
	return ent.scope&scope == scope
}

func (s *MemberStore) Scope(id [32]byte) (uint32, bool) {
	if isZeroNodeID(id) {
		return 0, false
	}
	key := hex.EncodeToString(id[:])
	s.mu.Lock()
	s.pruneLocked()
	el, ok := s.hot[key]
	if !ok {
		s.mu.Unlock()
		return 0, false
	}
	ent := el.Value.(*memberEntry)
	scope := ent.scope
	s.mu.Unlock()
	return scope, true
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
		if ent.scope != 0 {
			out = append(out, ent.id)
		}
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
		scope := DefaultMemberScope
		if rec.Scope != nil {
			scope = *rec.Scope
		}
		var inviterID [32]byte
		inviterSet := false
		if rec.InviterNodeID != "" {
			invBytes, err := hex.DecodeString(rec.InviterNodeID)
			if err == nil && len(invBytes) == 32 {
				copy(inviterID[:], invBytes)
				inviterSet = true
			}
		}
		_ = s.addWithScope(id, scope, inviterID, inviterSet, false, false)
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

func uint32ptr(v uint32) *uint32 {
	return &v
}
