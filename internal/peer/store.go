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

	"web4mvp/internal/crypto"
	"web4mvp/internal/proto"
	"web4mvp/internal/store"
)

const (
	DefaultCap       = 512
	DefaultTTL       = 30 * time.Minute
	DefaultLoadLimit = 512
	maxPeerScanSize  = 2 * proto.MaxFrameSize
)

type Peer struct {
	NodeID [32]byte
	PubKey []byte
	Addr   string
}

type Options struct {
	Cap       int
	TTL       time.Duration
	LoadLimit int
}

type Store struct {
	mu    sync.Mutex
	path  string
	cap   int
	ttl   time.Duration
	hot   map[string]*list.Element
	order *list.List
}

type entry struct {
	key       string
	peer      Peer
	expiresAt time.Time
}

type diskPeer struct {
	NodeID string `json:"node_id"`
	PubKey string `json:"pubkey"`
	Addr   string `json:"addr,omitempty"`
}

func NewStore(path string, opts Options) (*Store, error) {
	capacity := opts.Cap
	if capacity <= 0 {
		capacity = DefaultCap
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	loadLimit := opts.LoadLimit
	if loadLimit <= 0 {
		loadLimit = capacity
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	s := &Store{
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

func (s *Store) Upsert(p Peer, persist bool) error {
	if len(p.PubKey) == 0 && p.Addr == "" && isZeroNodeID(p.NodeID) {
		return fmt.Errorf("empty peer")
	}
	key := keyForPeer(p)
	if key == "" {
		return fmt.Errorf("invalid peer key")
	}
	pub := make([]byte, len(p.PubKey))
	copy(pub, p.PubKey)
	p.PubKey = pub

	s.mu.Lock()
	s.pruneLocked()
	if el, ok := s.hot[key]; ok {
		ent := el.Value.(*entry)
		ent.peer = p
		ent.expiresAt = time.Now().Add(s.ttl)
		s.order.MoveToFront(el)
		s.mu.Unlock()
		if !persist || len(p.PubKey) == 0 {
			return nil
		}
		rec := diskPeer{
			NodeID: hex.EncodeToString(p.NodeID[:]),
			PubKey: hex.EncodeToString(p.PubKey),
			Addr:   p.Addr,
		}
		return store.AppendJSONL(s.path, rec)
	}
	if s.cap > 0 && len(s.hot) >= s.cap {
		s.evictLocked(len(s.hot) - s.cap + 1)
	}
	ent := &entry{key: key, peer: p, expiresAt: time.Now().Add(s.ttl)}
	el := s.order.PushFront(ent)
	s.hot[key] = el
	s.mu.Unlock()

	if !persist || len(p.PubKey) == 0 {
		return nil
	}
	rec := diskPeer{
		NodeID: hex.EncodeToString(p.NodeID[:]),
		PubKey: hex.EncodeToString(p.PubKey),
		Addr:   p.Addr,
	}
	return store.AppendJSONL(s.path, rec)
}

func (s *Store) List() []Peer {
	s.mu.Lock()
	s.pruneLocked()
	out := make([]Peer, 0, len(s.hot))
	for el := s.order.Front(); el != nil; el = el.Next() {
		ent := el.Value.(*entry)
		p := ent.peer
		pub := make([]byte, len(p.PubKey))
		copy(pub, p.PubKey)
		out = append(out, Peer{NodeID: p.NodeID, PubKey: pub})
	}
	s.mu.Unlock()
	return out
}

func (s *Store) Len() int {
	s.mu.Lock()
	s.pruneLocked()
	n := len(s.hot)
	s.mu.Unlock()
	return n
}

func (s *Store) pruneLocked() {
	if s.ttl <= 0 {
		return
	}
	now := time.Now()
	for el := s.order.Back(); el != nil; {
		prev := el.Prev()
		ent := el.Value.(*entry)
		if ent.expiresAt.After(now) {
			el = prev
			continue
		}
		delete(s.hot, ent.key)
		s.order.Remove(el)
		el = prev
	}
}

func (s *Store) evictLocked(n int) {
	for n > 0 {
		el := s.order.Back()
		if el == nil {
			return
		}
		ent := el.Value.(*entry)
		delete(s.hot, ent.key)
		s.order.Remove(el)
		n--
	}
}

func (s *Store) loadLast(limit int) error {
	records, err := readLastN(s.path, limit)
	if err != nil {
		return err
	}
	for _, rec := range records {
		pub, err := hex.DecodeString(rec.PubKey)
		if err != nil || len(pub) != crypto.PubLen {
			continue
		}
		idBytes, err := hex.DecodeString(rec.NodeID)
		if err != nil || len(idBytes) != 32 {
			continue
		}
		var id [32]byte
		copy(id[:], idBytes)
		_ = s.Upsert(Peer{NodeID: id, PubKey: pub, Addr: rec.Addr}, false)
	}
	return nil
}

func readLastN(path string, n int) ([]diskPeer, error) {
	if n <= 0 {
		return nil, nil
	}
	paths := peerScanPaths(path)
	out := make([]diskPeer, 0, n)
	for i := len(paths) - 1; i >= 0; i-- {
		f, err := os.Open(paths[i])
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), maxPeerScanSize)
		for sc.Scan() {
			var rec diskPeer
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

func peerScanPaths(path string) []string {
	out := make([]string, 0, store.MaxRotations+1)
	out = append(out, path)
	for i := 1; i <= store.MaxRotations; i++ {
		out = append(out, fmt.Sprintf("%s.%d", path, i))
	}
	return out
}

func keyForPeer(p Peer) string {
	if !isZeroNodeID(p.NodeID) {
		return hex.EncodeToString(p.NodeID[:])
	}
	if p.Addr != "" {
		return "addr:" + p.Addr
	}
	return ""
}

func isZeroNodeID(id [32]byte) bool {
	var zero [32]byte
	return id == zero
}
