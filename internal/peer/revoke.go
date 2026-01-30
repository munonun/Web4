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
	DefaultRevokeCap       = 1024
	DefaultRevokeTTL       = 24 * time.Hour
	DefaultRevokeLoadLimit = 1024
	maxRevokeScanSize      = 2 * proto.MaxFrameSize
)

type RevokeOptions struct {
	Cap       int
	TTL       time.Duration
	LoadLimit int
}

type RevokeStore struct {
	mu    sync.Mutex
	path  string
	cap   int
	ttl   time.Duration
	hot   map[string]*list.Element
	order *list.List
}

type revokeEntry struct {
	key       string
	revokerID [32]byte
	revokeID  []byte
	expiresAt time.Time
}

type diskRevoke struct {
	RevokerNodeID string `json:"revoker_node_id"`
	TargetNodeID  string `json:"target_node_id,omitempty"`
	RevokeID      string `json:"revoke_id"`
	IssuedAt      uint64 `json:"issued_at"`
}

func NewRevokeStore(path string, opts RevokeOptions) (*RevokeStore, error) {
	capacity := opts.Cap
	if capacity <= 0 {
		capacity = DefaultRevokeCap
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultRevokeTTL
	}
	loadLimit := opts.LoadLimit
	if loadLimit <= 0 {
		loadLimit = capacity
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	s := &RevokeStore{
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

func (s *RevokeStore) Seen(revokerID [32]byte, revokeID []byte) bool {
	if isZeroNodeID(revokerID) || len(revokeID) == 0 {
		return false
	}
	key := revokeKey(revokerID, revokeID)
	s.mu.Lock()
	s.pruneLocked()
	_, ok := s.hot[key]
	s.mu.Unlock()
	return ok
}

func (s *RevokeStore) Mark(revokerID [32]byte, revokeID []byte, targetID [32]byte, issuedAt uint64, persist bool) error {
	if s == nil {
		return fmt.Errorf("revoke store unavailable")
	}
	if isZeroNodeID(revokerID) {
		return fmt.Errorf("missing revoker node_id")
	}
	if len(revokeID) == 0 {
		return fmt.Errorf("missing revoke_id")
	}
	key := revokeKey(revokerID, revokeID)
	s.mu.Lock()
	s.pruneLocked()
	if el, ok := s.hot[key]; ok {
		ent := el.Value.(*revokeEntry)
		ent.expiresAt = time.Now().Add(s.ttl)
		s.order.MoveToFront(el)
		s.mu.Unlock()
		return nil
	}
	if s.cap > 0 && len(s.hot) >= s.cap {
		s.evictLocked(len(s.hot) - s.cap + 1)
	}
	idCopy := make([]byte, len(revokeID))
	copy(idCopy, revokeID)
	ent := &revokeEntry{
		key:       key,
		revokerID: revokerID,
		revokeID:  idCopy,
		expiresAt: time.Now().Add(s.ttl),
	}
	el := s.order.PushFront(ent)
	s.hot[key] = el
	s.mu.Unlock()

	if !persist {
		return nil
	}
	rec := diskRevoke{
		RevokerNodeID: hex.EncodeToString(revokerID[:]),
		RevokeID:      hex.EncodeToString(revokeID),
		IssuedAt:      issuedAt,
	}
	if !isZeroNodeID(targetID) {
		rec.TargetNodeID = hex.EncodeToString(targetID[:])
	}
	return store.AppendJSONL(s.path, rec)
}

func (s *RevokeStore) pruneLocked() {
	if s.ttl <= 0 {
		return
	}
	now := time.Now()
	for el := s.order.Back(); el != nil; {
		prev := el.Prev()
		ent := el.Value.(*revokeEntry)
		if ent.expiresAt.After(now) {
			el = prev
			continue
		}
		delete(s.hot, ent.key)
		s.order.Remove(el)
		el = prev
	}
}

func (s *RevokeStore) evictLocked(n int) {
	for n > 0 {
		el := s.order.Back()
		if el == nil {
			return
		}
		ent := el.Value.(*revokeEntry)
		delete(s.hot, ent.key)
		s.order.Remove(el)
		n--
	}
}

func (s *RevokeStore) loadLast(limit int) error {
	records, err := readLastRevokes(s.path, limit)
	if err != nil {
		return err
	}
	for _, rec := range records {
		revokerBytes, err := hex.DecodeString(rec.RevokerNodeID)
		if err != nil || len(revokerBytes) != 32 {
			continue
		}
		revokeBytes, err := hex.DecodeString(rec.RevokeID)
		if err != nil || len(revokeBytes) == 0 {
			continue
		}
		var revokerID [32]byte
		copy(revokerID[:], revokerBytes)
		_ = s.Mark(revokerID, revokeBytes, [32]byte{}, rec.IssuedAt, false)
	}
	return nil
}

func readLastRevokes(path string, n int) ([]diskRevoke, error) {
	if n <= 0 {
		return nil, nil
	}
	paths := revokeScanPaths(path)
	out := make([]diskRevoke, 0, n)
	for i := len(paths) - 1; i >= 0; i-- {
		f, err := os.Open(paths[i])
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), maxRevokeScanSize)
		for sc.Scan() {
			var rec diskRevoke
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

func revokeScanPaths(path string) []string {
	out := make([]string, 0, store.MaxRotations+1)
	out = append(out, path)
	for i := 1; i <= store.MaxRotations; i++ {
		out = append(out, fmt.Sprintf("%s.%d", path, i))
	}
	return out
}

func revokeKey(revokerID [32]byte, revokeID []byte) string {
	return hex.EncodeToString(revokerID[:]) + ":" + hex.EncodeToString(revokeID)
}
