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
	GeneratedAt        time.Time         `json:"generated_at"`
	Delta              DeltaMetrics      `json:"delta"`
	Gossip             GossipMetrics     `json:"gossip"`
	Recent             []DeltaHeader     `json:"recent"`
	RecvByType         map[string]uint64 `json:"recv_by_type,omitempty"`
	DropByReason       map[string]uint64 `json:"drop_by_reason,omitempty"`
	CurrentConns       uint64            `json:"current_conns"`
	CurrentStreams     uint64            `json:"current_streams"`
	PeerTableSize      uint64            `json:"peertable_size"`
	OutboundConnected  uint64            `json:"outbound_connected"`
	InboundConnected   uint64            `json:"inbound_connected"`
	PexRequestsTotal   uint64            `json:"pex_requests_total"`
	PexResponsesTotal  uint64            `json:"pex_responses_total"`
	EvictionCountTotal uint64            `json:"eviction_count_total"`
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
	pexRequestsTotal   atomic.Uint64
	pexResponsesTotal  atomic.Uint64
	evictionCountTotal atomic.Uint64
	recent             *DeltaRecent
	mu                 sync.Mutex
	recvByType         map[string]uint64
	dropByReason       map[string]uint64
	currentConns       atomic.Uint64
	currentStreams     atomic.Uint64
	peertableSize      atomic.Uint64
	outboundConnected  atomic.Uint64
	inboundConnected   atomic.Uint64
}

func New() *Metrics {
	return &Metrics{
		recent:       NewDeltaRecent(64),
		recvByType:   make(map[string]uint64),
		dropByReason: make(map[string]uint64),
	}
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

func (m *Metrics) IncPexRequestsTotal() {
	m.pexRequestsTotal.Add(1)
}

func (m *Metrics) IncPexResponsesTotal() {
	m.pexResponsesTotal.Add(1)
}

func (m *Metrics) IncEvictionCountTotal() {
	m.evictionCountTotal.Add(1)
}

func (m *Metrics) IncRecvByType(msgType string) {
	if m == nil || msgType == "" {
		return
	}
	m.mu.Lock()
	m.recvByType[msgType]++
	m.mu.Unlock()
}

func (m *Metrics) IncDropByReason(reason string) {
	if m == nil || reason == "" {
		return
	}
	m.mu.Lock()
	m.dropByReason[reason]++
	m.mu.Unlock()
}

func (m *Metrics) SetCurrentConns(n uint64) {
	if m == nil {
		return
	}
	m.currentConns.Store(n)
}

func (m *Metrics) SetCurrentStreams(n uint64) {
	if m == nil {
		return
	}
	m.currentStreams.Store(n)
}

func (m *Metrics) SetPeerTableSize(n uint64) {
	if m == nil {
		return
	}
	m.peertableSize.Store(n)
}

func (m *Metrics) SetOutboundConnected(n uint64) {
	if m == nil {
		return
	}
	m.outboundConnected.Store(n)
}

func (m *Metrics) SetInboundConnected(n uint64) {
	if m == nil {
		return
	}
	m.inboundConnected.Store(n)
}

func (m *Metrics) Snapshot() Snapshot {
	recent := []DeltaHeader{}
	if m.recent != nil {
		recent = m.recent.List()
	}
	recvByType := map[string]uint64{}
	dropByReason := map[string]uint64{}
	if m != nil {
		m.mu.Lock()
		for k, v := range m.recvByType {
			recvByType[k] = v
		}
		for k, v := range m.dropByReason {
			dropByReason[k] = v
		}
		m.mu.Unlock()
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
		Recent:             recent,
		RecvByType:         recvByType,
		DropByReason:       dropByReason,
		CurrentConns:       m.currentConns.Load(),
		CurrentStreams:     m.currentStreams.Load(),
		PeerTableSize:      m.peertableSize.Load(),
		OutboundConnected:  m.outboundConnected.Load(),
		InboundConnected:   m.inboundConnected.Load(),
		PexRequestsTotal:   m.pexRequestsTotal.Load(),
		PexResponsesTotal:  m.pexResponsesTotal.Load(),
		EvictionCountTotal: m.evictionCountTotal.Load(),
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
