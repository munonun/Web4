package peer

import (
	"bufio"
	"container/list"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"web4mvp/internal/crypto"
	"web4mvp/internal/proto"
	"web4mvp/internal/store"
)

const (
	DefaultCap              = 512
	DefaultTTL              = 30 * time.Minute
	DefaultLoadLimit        = 512
	maxPeerScanSize         = 2 * proto.MaxFrameSize
	DefaultAddrCooldown     = 2 * time.Minute
	DefaultAddrObservation  = 2
	DefaultAddrMuteDuration = 2 * time.Minute
)

type Peer struct {
	NodeID [32]byte
	PubKey []byte
	Addr   string
}

type Options struct {
	Cap                 int
	TTL                 time.Duration
	LoadLimit           int
	AddrCooldown        time.Duration
	AddrObservation     int
	AllowAddrFromUpsert bool
	DeriveNodeID        func(pub []byte) [32]byte
}

type Store struct {
	mu                  sync.Mutex
	path                string
	cap                 int
	ttl                 time.Duration
	deriveNodeID        func(pub []byte) [32]byte
	addrCooldown        time.Duration
	addrObservation     int
	allowAddrFromUpsert bool
	hot                 map[string]*list.Element
	order               *list.List
	addrIndex           map[string][32]byte
	addrObs             map[[32]byte]map[string]*addrObservation
	addrChange          map[[32]byte]time.Time
	mutedAddrs          map[string]time.Time
	addrHints           map[[32]byte]string
	hintIndex           map[string][32]byte
	addrVerified        map[[32]byte]bool
}

type entry struct {
	key       string
	peer      Peer
	expiresAt time.Time
}

type addrObservation struct {
	count    int
	lastSeen time.Time
}

type diskPeer struct {
	NodeID string `json:"node_id"`
	PubKey string `json:"pubkey"`
	Addr   string `json:"addr,omitempty"`
}

var (
	ErrAddrConflict = errors.New("addr conflict")
	ErrAddrMuted    = errors.New("addr muted")
	ErrAddrCooldown = errors.New("addr cooldown")
)

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
	if opts.DeriveNodeID == nil {
		return nil, fmt.Errorf("missing derive_node_id")
	}
	addrCooldown := opts.AddrCooldown
	if addrCooldown <= 0 {
		addrCooldown = DefaultAddrCooldown
	}
	addrObs := opts.AddrObservation
	if addrObs <= 0 {
		addrObs = DefaultAddrObservation
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	s := &Store{
		path:                path,
		cap:                 capacity,
		ttl:                 ttl,
		deriveNodeID:        opts.DeriveNodeID,
		addrCooldown:        addrCooldown,
		addrObservation:     addrObs,
		allowAddrFromUpsert: opts.AllowAddrFromUpsert,
		hot:                 make(map[string]*list.Element),
		order:               list.New(),
		addrIndex:           make(map[string][32]byte),
		addrObs:             make(map[[32]byte]map[string]*addrObservation),
		addrChange:          make(map[[32]byte]time.Time),
		mutedAddrs:          make(map[string]time.Time),
		addrHints:           make(map[[32]byte]string),
		hintIndex:           make(map[string][32]byte),
		addrVerified:        make(map[[32]byte]bool),
	}
	if loadLimit > 0 {
		if err := s.loadLast(loadLimit); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) Upsert(p Peer, persist bool) error {
	if isZeroNodeID(p.NodeID) {
		return fmt.Errorf("missing node_id")
	}
	logDebug := func(peer Peer) {
		if os.Getenv("WEB4_DEBUG") != "1" {
			return
		}
		pubNodeID := s.deriveNodeID(peer.PubKey)
		pubHash := crypto.SHA3_256(peer.PubKey)
		fmt.Fprintf(os.Stderr, "peer upsert: node_id=%x addr=%s pub_node_id=%x pub_hash=%x\n", peer.NodeID[:], peer.Addr, pubNodeID[:], pubHash[:])
	}
	key := keyForPeer(p)

	s.mu.Lock()
	s.pruneLocked()
	now := time.Now()
	if p.Addr != "" && !s.allowAddrFromUpsert {
		p.Addr = ""
	}
	var existing *entry
	var existingEl *list.Element
	if el, ok := s.hot[key]; ok {
		existingEl = el
		existing = el.Value.(*entry)
		if p.Addr == "" {
			p.Addr = existing.peer.Addr
		}
		if len(p.PubKey) == 0 {
			p.PubKey = existing.peer.PubKey
		}
	}
	if len(p.PubKey) == 0 {
		s.mu.Unlock()
		return fmt.Errorf("missing pubkey")
	}
	derived := s.deriveNodeID(p.PubKey)
	if derived != p.NodeID {
		s.mu.Unlock()
		fmt.Fprintf(os.Stderr, "peer upsert rejected: node_id/pubkey mismatch node_id=%x pub_node_id=%x addr=%s\n", p.NodeID[:], derived[:], p.Addr)
		return fmt.Errorf("node_id/pubkey mismatch")
	}
	pub := make([]byte, len(p.PubKey))
	copy(pub, p.PubKey)
	p.PubKey = pub
	if existing != nil {
		if p.Addr == "" {
			p.Addr = existing.peer.Addr
		} else if p.Addr != existing.peer.Addr {
			if err := s.setAddrLocked(existing, p.Addr, now, false, false); err != nil {
				s.mu.Unlock()
				return err
			}
			p.Addr = existing.peer.Addr
		}
		existing.peer = p
		existing.expiresAt = now.Add(s.ttl)
		s.order.MoveToFront(existingEl)
		s.mu.Unlock()
		logDebug(p)
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
	addr := p.Addr
	p.Addr = ""
	ent := &entry{key: key, peer: p, expiresAt: now.Add(s.ttl)}
	if addr != "" {
		if err := s.setAddrLocked(ent, addr, now, false, false); err != nil {
			s.mu.Unlock()
			return err
		}
	}
	el := s.order.PushFront(ent)
	s.hot[key] = el
	s.mu.Unlock()

	logDebug(p)
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

func (s *Store) ObserveAddr(p Peer, observedAddr string, candidateAddr string, verified bool, persist bool) (bool, error) {
	if observedAddr == "" {
		return false, nil
	}
	if isZeroNodeID(p.NodeID) {
		return false, fmt.Errorf("missing node_id")
	}
	s.mu.Lock()
	s.pruneLocked()
	now := time.Now()
	key := keyForPeer(p)
	var ent *entry
	var entEl *list.Element
	if el, ok := s.hot[key]; ok {
		entEl = el
		ent = el.Value.(*entry)
		if len(p.PubKey) == 0 {
			p.PubKey = ent.peer.PubKey
		}
	}
	if len(p.PubKey) == 0 {
		s.mu.Unlock()
		return false, fmt.Errorf("missing pubkey")
	}
	derived := s.deriveNodeID(p.PubKey)
	if derived != p.NodeID {
		s.mu.Unlock()
		return false, fmt.Errorf("node_id/pubkey mismatch")
	}
	pub := make([]byte, len(p.PubKey))
	copy(pub, p.PubKey)
	p.PubKey = pub
	if ent == nil {
		if s.cap > 0 && len(s.hot) >= s.cap {
			s.evictLocked(len(s.hot) - s.cap + 1)
		}
		ent = &entry{key: key, peer: Peer{NodeID: p.NodeID, PubKey: pub}, expiresAt: now.Add(s.ttl)}
		entEl = s.order.PushFront(ent)
		s.hot[key] = entEl
	} else {
		ent.peer.NodeID = p.NodeID
		ent.peer.PubKey = pub
		ent.expiresAt = now.Add(s.ttl)
		s.order.MoveToFront(entEl)
	}
	host := hostForAddr(observedAddr)
	obsByHost := s.addrObs[p.NodeID]
	if obsByHost == nil {
		obsByHost = make(map[string]*addrObservation)
		s.addrObs[p.NodeID] = obsByHost
	}
	obs := obsByHost[host]
	if obs == nil {
		obs = &addrObservation{}
		obsByHost[host] = obs
	}
	obs.count++
	obs.lastSeen = now
	if candidateAddr == "" {
		s.mu.Unlock()
		return false, nil
	}
	allowUpdate := verified || obs.count >= s.addrObservation
	if !allowUpdate {
		s.mu.Unlock()
		return false, nil
	}
	prevAddr := ent.peer.Addr
	if err := s.setAddrLocked(ent, candidateAddr, now, false, true); err != nil {
		s.mu.Unlock()
		return false, err
	}
	changed := ent.peer.Addr != prevAddr
	s.mu.Unlock()
	if !persist || len(ent.peer.PubKey) == 0 {
		return changed, nil
	}
	rec := diskPeer{
		NodeID: hex.EncodeToString(ent.peer.NodeID[:]),
		PubKey: hex.EncodeToString(ent.peer.PubKey),
		Addr:   ent.peer.Addr,
	}
	return changed, store.AppendJSONL(s.path, rec)
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
		out = append(out, Peer{NodeID: p.NodeID, PubKey: pub, Addr: p.Addr})
	}
	s.mu.Unlock()
	return out
}

func (s *Store) SetAddrUnverified(p Peer, addr string, persist bool) (bool, error) {
	if addr == "" || isZeroNodeID(p.NodeID) || len(p.PubKey) == 0 {
		return false, nil
	}
	derived := s.deriveNodeID(p.PubKey)
	if derived != p.NodeID {
		return false, fmt.Errorf("node_id/pubkey mismatch")
	}
	now := time.Now()
	s.mu.Lock()
	s.pruneLocked()
	if owner, ok := s.addrIndex[addr]; ok && owner != p.NodeID {
		s.mutedAddrs[addr] = now.Add(DefaultAddrMuteDuration)
		s.mu.Unlock()
		return false, ErrAddrConflict
	}
	if owner, ok := s.hintIndex[addr]; ok && owner != p.NodeID {
		s.mutedAddrs[addr] = now.Add(DefaultAddrMuteDuration)
		s.mu.Unlock()
		return false, ErrAddrConflict
	}
	key := keyForPeer(p)
	var ent *entry
	var entEl *list.Element
	if el, ok := s.hot[key]; ok {
		entEl = el
		ent = el.Value.(*entry)
	}
	if ent == nil {
		if s.cap > 0 && len(s.hot) >= s.cap {
			s.evictLocked(len(s.hot) - s.cap + 1)
		}
		ent = &entry{key: key, peer: Peer{NodeID: p.NodeID, PubKey: p.PubKey}, expiresAt: now.Add(s.ttl)}
		entEl = s.order.PushFront(ent)
		s.hot[key] = entEl
	} else {
		ent.peer.NodeID = p.NodeID
		ent.peer.PubKey = p.PubKey
		ent.expiresAt = now.Add(s.ttl)
		s.order.MoveToFront(entEl)
	}
	if s.addrVerified[p.NodeID] {
		s.mu.Unlock()
		return false, nil
	}
	if ent.peer.Addr != "" && ent.peer.Addr != addr {
		currentHost := hostForAddr(ent.peer.Addr)
		newHost := hostForAddr(addr)
		if currentHost == "" || newHost == "" || currentHost != newHost {
			if last, ok := s.addrChange[ent.peer.NodeID]; ok && now.Sub(last) < s.addrCooldown {
				s.mu.Unlock()
				return false, ErrAddrCooldown
			}
		}
	}
	changed := ent.peer.Addr != addr
	ent.peer.Addr = addr
	s.addrVerified[p.NodeID] = false
	s.addrHints[p.NodeID] = addr
	s.hintIndex[addr] = p.NodeID
	if changed {
		s.addrChange[ent.peer.NodeID] = now
	}
	s.mu.Unlock()
	if !persist || len(ent.peer.PubKey) == 0 || !changed {
		return changed, nil
	}
	rec := diskPeer{
		NodeID: hex.EncodeToString(ent.peer.NodeID[:]),
		PubKey: hex.EncodeToString(ent.peer.PubKey),
		Addr:   ent.peer.Addr,
	}
	return changed, store.AppendJSONL(s.path, rec)
}

func (s *Store) AddrHint(id [32]byte) (string, bool) {
	if isZeroNodeID(id) {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	addr, ok := s.addrHints[id]
	return addr, ok
}

func (s *Store) IsAddrVerified(id [32]byte) bool {
	if isZeroNodeID(id) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addrVerified[id]
}

func (s *Store) Len() int {
	s.mu.Lock()
	s.pruneLocked()
	n := len(s.hot)
	s.mu.Unlock()
	return n
}

func (s *Store) Refresh() error {
	if s == nil {
		return nil
	}
	limit := s.cap
	if limit <= 0 {
		limit = DefaultCap
	}
	return s.loadLast(limit)
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
		if ent.peer.Addr != "" {
			if owner, ok := s.addrIndex[ent.peer.Addr]; ok && owner == ent.peer.NodeID {
				delete(s.addrIndex, ent.peer.Addr)
			}
		}
		delete(s.addrVerified, ent.peer.NodeID)
		if hint, ok := s.addrHints[ent.peer.NodeID]; ok {
			delete(s.addrHints, ent.peer.NodeID)
			if owner, ok := s.hintIndex[hint]; ok && owner == ent.peer.NodeID {
				delete(s.hintIndex, hint)
			}
		}
		delete(s.addrObs, ent.peer.NodeID)
		delete(s.addrChange, ent.peer.NodeID)
		delete(s.hot, ent.key)
		s.order.Remove(el)
		el = prev
	}
	for addr, until := range s.mutedAddrs {
		if until.Before(now) {
			delete(s.mutedAddrs, addr)
		}
	}
}

func (s *Store) evictLocked(n int) {
	for n > 0 {
		el := s.order.Back()
		if el == nil {
			return
		}
		ent := el.Value.(*entry)
		if ent.peer.Addr != "" {
			if owner, ok := s.addrIndex[ent.peer.Addr]; ok && owner == ent.peer.NodeID {
				delete(s.addrIndex, ent.peer.Addr)
			}
		}
		delete(s.addrVerified, ent.peer.NodeID)
		if hint, ok := s.addrHints[ent.peer.NodeID]; ok {
			delete(s.addrHints, ent.peer.NodeID)
			if owner, ok := s.hintIndex[hint]; ok && owner == ent.peer.NodeID {
				delete(s.hintIndex, hint)
			}
		}
		delete(s.addrObs, ent.peer.NodeID)
		delete(s.addrChange, ent.peer.NodeID)
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
		if err != nil || !crypto.IsRSAPublicKey(pub) {
			continue
		}
		idBytes, err := hex.DecodeString(rec.NodeID)
		if err != nil || len(idBytes) != 32 {
			continue
		}
		var id [32]byte
		copy(id[:], idBytes)
		_ = s.loadRecord(Peer{NodeID: id, PubKey: pub, Addr: rec.Addr})
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
	return hex.EncodeToString(p.NodeID[:])
}

func (s *Store) loadRecord(p Peer) error {
	if isZeroNodeID(p.NodeID) || len(p.PubKey) == 0 {
		return fmt.Errorf("invalid peer")
	}
	derived := s.deriveNodeID(p.PubKey)
	if derived != p.NodeID {
		return fmt.Errorf("node_id/pubkey mismatch")
	}
	s.mu.Lock()
	s.pruneLocked()
	now := time.Now()
	key := keyForPeer(p)
	var ent *entry
	var entEl *list.Element
	if el, ok := s.hot[key]; ok {
		entEl = el
		ent = el.Value.(*entry)
	}
	pub := make([]byte, len(p.PubKey))
	copy(pub, p.PubKey)
	p.PubKey = pub
	if ent == nil {
		if s.cap > 0 && len(s.hot) >= s.cap {
			s.evictLocked(len(s.hot) - s.cap + 1)
		}
		ent = &entry{key: key, peer: Peer{NodeID: p.NodeID, PubKey: p.PubKey}, expiresAt: now.Add(s.ttl)}
		entEl = s.order.PushFront(ent)
		s.hot[key] = entEl
	} else {
		ent.peer.NodeID = p.NodeID
		ent.peer.PubKey = p.PubKey
		ent.expiresAt = now.Add(s.ttl)
		s.order.MoveToFront(entEl)
	}
	if p.Addr != "" {
		_ = s.setAddrLocked(ent, p.Addr, now, true, true)
	}
	s.mu.Unlock()
	return nil
}

func (s *Store) setAddrLocked(ent *entry, addr string, now time.Time, ignoreCooldown bool, verified bool) error {
	if addr == "" {
		return nil
	}
	if until, ok := s.mutedAddrs[addr]; ok && until.After(now) {
		return ErrAddrMuted
	}
	if owner, ok := s.addrIndex[addr]; ok && owner != ent.peer.NodeID {
		s.mutedAddrs[addr] = now.Add(DefaultAddrMuteDuration)
		return ErrAddrConflict
	}
	if ent.peer.Addr == addr {
		if verified && !s.addrVerified[ent.peer.NodeID] {
			s.addrIndex[addr] = ent.peer.NodeID
			s.addrVerified[ent.peer.NodeID] = true
			s.addrChange[ent.peer.NodeID] = now
			if hint, ok := s.addrHints[ent.peer.NodeID]; ok {
				delete(s.addrHints, ent.peer.NodeID)
				if owner, ok := s.hintIndex[hint]; ok && owner == ent.peer.NodeID {
					delete(s.hintIndex, hint)
				}
			}
		}
		return nil
	}
	if ent.peer.Addr != "" && !ignoreCooldown {
		currentHost := hostForAddr(ent.peer.Addr)
		newHost := hostForAddr(addr)
		if currentHost == "" || newHost == "" || currentHost != newHost {
			if last, ok := s.addrChange[ent.peer.NodeID]; ok && now.Sub(last) < s.addrCooldown {
				return ErrAddrCooldown
			}
		}
	}
	if ent.peer.Addr != "" && verified {
		if owner, ok := s.addrIndex[ent.peer.Addr]; ok && owner == ent.peer.NodeID {
			delete(s.addrIndex, ent.peer.Addr)
		}
	}
	ent.peer.Addr = addr
	if verified {
		s.addrIndex[addr] = ent.peer.NodeID
	}
	s.addrChange[ent.peer.NodeID] = now
	s.addrVerified[ent.peer.NodeID] = verified
	if hint, ok := s.addrHints[ent.peer.NodeID]; ok {
		delete(s.addrHints, ent.peer.NodeID)
		if owner, ok := s.hintIndex[hint]; ok && owner == ent.peer.NodeID {
			delete(s.hintIndex, hint)
		}
	}
	return nil
}

func hostForAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func isZeroNodeID(id [32]byte) bool {
	var zero [32]byte
	return id == zero
}
