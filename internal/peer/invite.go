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
	DefaultInviteCap       = 1024
	DefaultInviteTTL       = 24 * time.Hour
	DefaultInviteLoadLimit = 1024
	maxInviteScanSize      = 2 * proto.MaxFrameSize
)

type InviteOptions struct {
	Cap       int
	TTL       time.Duration
	LoadLimit int
}

type InviteStore struct {
	mu    sync.Mutex
	path  string
	cap   int
	ttl   time.Duration
	hot   map[string]*list.Element
	order *list.List
}

type inviteEntry struct {
	key       string
	inviterID [32]byte
	inviteID  []byte
	expiresAt time.Time
	seenAt    time.Time
}

type diskInvite struct {
	InviterNodeID string `json:"inviter_node_id"`
	InviteID      string `json:"invite_id"`
	ExpiresAt     uint64 `json:"expires_at,omitempty"`
	SeenAt        uint64 `json:"seen_at,omitempty"`
}

func NewInviteStore(path string, opts InviteOptions) (*InviteStore, error) {
	capacity := opts.Cap
	if capacity <= 0 {
		capacity = DefaultInviteCap
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultInviteTTL
	}
	loadLimit := opts.LoadLimit
	if loadLimit <= 0 {
		loadLimit = capacity
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	s := &InviteStore{
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

func (s *InviteStore) Seen(inviterID [32]byte, inviteID []byte) bool {
	if s == nil {
		return false
	}
	if isZeroNodeID(inviterID) || len(inviteID) == 0 {
		return false
	}
	key := inviteKey(inviterID, inviteID)
	s.mu.Lock()
	s.pruneLocked()
	_, ok := s.hot[key]
	s.mu.Unlock()
	return ok
}

func (s *InviteStore) Mark(inviterID [32]byte, inviteID []byte, expiresAt uint64, persist bool) error {
	if s == nil {
		return fmt.Errorf("invite store unavailable")
	}
	if isZeroNodeID(inviterID) {
		return fmt.Errorf("missing inviter node_id")
	}
	if len(inviteID) == 0 {
		return fmt.Errorf("missing invite_id")
	}
	key := inviteKey(inviterID, inviteID)
	seenAt := time.Now()
	var expires time.Time
	if expiresAt > 0 {
		expires = time.Unix(int64(expiresAt), 0)
	}

	s.mu.Lock()
	s.pruneLocked()
	if el, ok := s.hot[key]; ok {
		ent := el.Value.(*inviteEntry)
		ent.expiresAt = expires
		ent.seenAt = seenAt
		s.order.MoveToFront(el)
		s.mu.Unlock()
		if !persist {
			return nil
		}
		rec := diskInvite{
			InviterNodeID: hex.EncodeToString(inviterID[:]),
			InviteID:      hex.EncodeToString(inviteID),
			ExpiresAt:     expiresAt,
			SeenAt:        uint64(seenAt.Unix()),
		}
		return store.AppendJSONL(s.path, rec)
	}
	if s.cap > 0 && len(s.hot) >= s.cap {
		s.evictLocked(len(s.hot) - s.cap + 1)
	}
	idCopy := make([]byte, len(inviteID))
	copy(idCopy, inviteID)
	ent := &inviteEntry{
		key:       key,
		inviterID: inviterID,
		inviteID:  idCopy,
		expiresAt: expires,
		seenAt:    seenAt,
	}
	el := s.order.PushFront(ent)
	s.hot[key] = el
	s.mu.Unlock()

	if !persist {
		return nil
	}
	rec := diskInvite{
		InviterNodeID: hex.EncodeToString(inviterID[:]),
		InviteID:      hex.EncodeToString(inviteID),
		ExpiresAt:     expiresAt,
		SeenAt:        uint64(seenAt.Unix()),
	}
	return store.AppendJSONL(s.path, rec)
}

func (s *InviteStore) pruneLocked() {
	if s.ttl <= 0 {
		return
	}
	now := time.Now()
	for el := s.order.Back(); el != nil; {
		prev := el.Prev()
		ent := el.Value.(*inviteEntry)
		if !ent.expiresAt.IsZero() && ent.expiresAt.Before(now) {
			delete(s.hot, ent.key)
			s.order.Remove(el)
			el = prev
			continue
		}
		if ent.seenAt.Add(s.ttl).Before(now) {
			delete(s.hot, ent.key)
			s.order.Remove(el)
			el = prev
			continue
		}
		el = prev
	}
}

func (s *InviteStore) evictLocked(n int) {
	for n > 0 {
		el := s.order.Back()
		if el == nil {
			return
		}
		ent := el.Value.(*inviteEntry)
		delete(s.hot, ent.key)
		s.order.Remove(el)
		n--
	}
}

func (s *InviteStore) loadLast(limit int) error {
	records, err := readLastInvites(s.path, limit)
	if err != nil {
		return err
	}
	for _, rec := range records {
		inviterBytes, err := hex.DecodeString(rec.InviterNodeID)
		if err != nil || len(inviterBytes) != 32 {
			continue
		}
		inviteBytes, err := hex.DecodeString(rec.InviteID)
		if err != nil || len(inviteBytes) == 0 {
			continue
		}
		var inviterID [32]byte
		copy(inviterID[:], inviterBytes)
		_ = s.Mark(inviterID, inviteBytes, rec.ExpiresAt, false)
	}
	return nil
}

func readLastInvites(path string, n int) ([]diskInvite, error) {
	if n <= 0 {
		return nil, nil
	}
	paths := inviteScanPaths(path)
	out := make([]diskInvite, 0, n)
	for i := len(paths) - 1; i >= 0; i-- {
		f, err := os.Open(paths[i])
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), maxInviteScanSize)
		for sc.Scan() {
			var rec diskInvite
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

func inviteScanPaths(path string) []string {
	out := make([]string, 0, store.MaxRotations+1)
	out = append(out, path)
	for i := 1; i <= store.MaxRotations; i++ {
		out = append(out, fmt.Sprintf("%s.%d", path, i))
	}
	return out
}

func inviteKey(inviterID [32]byte, inviteID []byte) string {
	return hex.EncodeToString(inviterID[:]) + ":" + hex.EncodeToString(inviteID)
}
