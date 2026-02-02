package metrics

import (
	"encoding/json"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type DeltaHeader struct {
	ScopeHash string `json:"scope_hash"`
	ViewID    string `json:"view_id"`
	Entries   int    `json:"entries"`
	Conserved bool   `json:"conserved"`
	ZK        string `json:"zk"`
}

type Snapshot struct {
	GeneratedAt time.Time     `json:"generated_at"`
	Delta       DeltaMetrics  `json:"delta"`
	Gossip      GossipMetrics `json:"gossip"`
	Recent      []DeltaHeader `json:"recent"`
}

type DeltaMetrics struct {
	Verified      uint64 `json:"verified"`
	Relayed       uint64 `json:"relayed"`
	DropDuplicate uint64 `json:"drop_duplicate"`
	DropRate      uint64 `json:"drop_rate"`
	DropNonMember uint64 `json:"drop_non_member"`
	DropZKFail    uint64 `json:"drop_zk_fail"`
}

type GossipMetrics struct {
	Relayed uint64 `json:"relayed"`
}

type Metrics struct {
	deltaVerified      atomic.Uint64
	deltaRelayed       atomic.Uint64
	deltaDropDuplicate atomic.Uint64
	deltaDropRate      atomic.Uint64
	deltaDropNonMember atomic.Uint64
	deltaDropZKFail    atomic.Uint64
	gossipRelayed      atomic.Uint64
	recent             *DeltaRecent
}

func New() *Metrics {
	return &Metrics{recent: NewDeltaRecent(64)}
}

func (m *Metrics) Recent() *DeltaRecent {
	return m.recent
}

func (m *Metrics) IncDeltaVerified() {
	m.deltaVerified.Add(1)
}

func (m *Metrics) IncDeltaRelayed() {
	m.deltaRelayed.Add(1)
}

func (m *Metrics) IncDeltaDropDuplicate() {
	m.deltaDropDuplicate.Add(1)
}

func (m *Metrics) IncDeltaDropRate() {
	m.deltaDropRate.Add(1)
}

func (m *Metrics) IncDeltaDropNonMember() {
	m.deltaDropNonMember.Add(1)
}

func (m *Metrics) IncDeltaDropZKFail() {
	m.deltaDropZKFail.Add(1)
}

func (m *Metrics) IncGossipRelayed() {
	m.gossipRelayed.Add(1)
}

func (m *Metrics) Snapshot() Snapshot {
	recent := []DeltaHeader{}
	if m.recent != nil {
		recent = m.recent.List()
	}
	return Snapshot{
		GeneratedAt: time.Now().UTC(),
		Delta: DeltaMetrics{
			Verified:      m.deltaVerified.Load(),
			Relayed:       m.deltaRelayed.Load(),
			DropDuplicate: m.deltaDropDuplicate.Load(),
			DropRate:      m.deltaDropRate.Load(),
			DropNonMember: m.deltaDropNonMember.Load(),
			DropZKFail:    m.deltaDropZKFail.Load(),
		},
		Gossip: GossipMetrics{
			Relayed: m.gossipRelayed.Load(),
		},
		Recent: recent,
	}
}

func (m *Metrics) WriteSnapshot(path string) error {
	if path == "" {
		return nil
	}
	snap := m.Snapshot()
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

type DeltaRecent struct {
	mu   sync.Mutex
	cap  int
	list []DeltaHeader
}

func NewDeltaRecent(capacity int) *DeltaRecent {
	if capacity <= 0 {
		capacity = 64
	}
	return &DeltaRecent{cap: capacity}
}

func (r *DeltaRecent) Add(h DeltaHeader) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.list) >= r.cap {
		copy(r.list, r.list[1:])
		r.list[len(r.list)-1] = h
		return
	}
	r.list = append(r.list, h)
}

func (r *DeltaRecent) List() []DeltaHeader {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]DeltaHeader, len(r.list))
	copy(out, r.list)
	return out
}
