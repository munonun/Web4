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
	GeneratedAt                time.Time         `json:"generated_at"`
	Delta                      DeltaMetrics      `json:"delta"`
	Gossip                     GossipMetrics     `json:"gossip"`
	Recent                     []DeltaHeader     `json:"recent"`
	RecvByType                 map[string]uint64 `json:"recv_by_type,omitempty"`
	DropByReason               map[string]uint64 `json:"drop_by_reason,omitempty"`
	CurrentConns               uint64            `json:"current_conns"`
	CurrentStreams             uint64            `json:"current_streams"`
	PeerTableSize              uint64            `json:"peertable_size"`
	OutboundConnected          uint64            `json:"outbound_connected"`
	InboundConnected           uint64            `json:"inbound_connected"`
	PexRequestsTotal           uint64            `json:"pex_requests_total"`
	PexResponsesTotal          uint64            `json:"pex_responses_total"`
	DialAttemptsTotal          uint64            `json:"dial_attempts_total"`
	DialSuccessTotal           uint64            `json:"dial_success_total"`
	PexReqSentTotal            uint64            `json:"pex_req_sent_total"`
	PexRespRecvTotal           uint64            `json:"pex_resp_recv_total"`
	EvictionCountTotal         uint64            `json:"eviction_count_total"`
	DialAttemptByReason        map[string]uint64 `json:"dial_attempt_total_by_reason,omitempty"`
	DialSuccessByReason        map[string]uint64 `json:"dial_success_total_by_reason,omitempty"`
	DialFailByReason           map[string]uint64 `json:"dial_fail_total_by_reason,omitempty"`
	QuicConnectSuccessTotal    uint64            `json:"quic_connect_success_total"`
	HelloHandshakeSuccessTotal uint64            `json:"hello_handshake_success_total"`
	HelloHandshakeFailTotal    uint64            `json:"hello_handshake_fail_total"`
	HelloHandshakeFailByReason map[string]uint64 `json:"hello_handshake_fail_total_by_reason,omitempty"`
	HelloSuccessTotal          uint64            `json:"hello_success_total"`
	HelloRejectByReason        map[string]uint64 `json:"hello_reject_total_by_reason,omitempty"`
	CandidateAvailable         uint64            `json:"candidate_available"`
	BackoffBlocked             uint64            `json:"backoff_blocked"`
	SeedDialSkippedTotal       uint64            `json:"seed_dial_skipped_total"`
	RecoveryPanicDials         uint64            `json:"recovery_panic_dials_total"`
	RecoveryModeActive         bool              `json:"recovery_mode_active"`
	RecoveryEnterTotal         uint64            `json:"recovery_enter_total"`
	RecoveryExitTotal          uint64            `json:"recovery_exit_total"`
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
	deltaVerified       atomic.Uint64
	deltaRelayed        atomic.Uint64
	deltaDropDuplicate  atomic.Uint64
	deltaDropRate       atomic.Uint64
	deltaDropNonMember  atomic.Uint64
	deltaDropZKFail     atomic.Uint64
	gossipRelayed       atomic.Uint64
	pexRequestsTotal    atomic.Uint64
	pexResponsesTotal   atomic.Uint64
	dialAttemptsTotal   atomic.Uint64
	dialSuccessTotal    atomic.Uint64
	pexReqSentTotal     atomic.Uint64
	pexRespRecvTotal    atomic.Uint64
	evictionCountTotal  atomic.Uint64
	helloSuccessTotal   atomic.Uint64
	quicConnectSuccess  atomic.Uint64
	helloHSOkTotal      atomic.Uint64
	helloHSFailTotal    atomic.Uint64
	candidateAvailable  atomic.Uint64
	backoffBlocked      atomic.Uint64
	seedDialSkipped     atomic.Uint64
	recoveryPanicDials  atomic.Uint64
	recoveryModeActive  atomic.Bool
	recoveryEnterTotal  atomic.Uint64
	recoveryExitTotal   atomic.Uint64
	recent              *DeltaRecent
	mu                  sync.Mutex
	recvByType          map[string]uint64
	dropByReason        map[string]uint64
	dialAttemptByReason map[string]uint64
	dialSuccessByReason map[string]uint64
	dialFailByReason    map[string]uint64
	helloRejectByReason map[string]uint64
	helloHSFailByReason map[string]uint64
	currentConns        atomic.Uint64
	currentStreams      atomic.Uint64
	peertableSize       atomic.Uint64
	outboundConnected   atomic.Uint64
	inboundConnected    atomic.Uint64
}

func New() *Metrics {
	return &Metrics{
		recent:              NewDeltaRecent(64),
		recvByType:          make(map[string]uint64),
		dropByReason:        make(map[string]uint64),
		dialAttemptByReason: make(map[string]uint64),
		dialSuccessByReason: make(map[string]uint64),
		dialFailByReason:    make(map[string]uint64),
		helloRejectByReason: make(map[string]uint64),
		helloHSFailByReason: make(map[string]uint64),
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

func (m *Metrics) IncDialAttemptsTotal() {
	m.dialAttemptsTotal.Add(1)
}

func (m *Metrics) IncDialSuccessTotal() {
	m.dialSuccessTotal.Add(1)
}

func (m *Metrics) IncPexReqSentTotal() {
	m.pexReqSentTotal.Add(1)
}

func (m *Metrics) IncPexRespRecvTotal() {
	m.pexRespRecvTotal.Add(1)
}

func (m *Metrics) IncEvictionCountTotal() {
	m.evictionCountTotal.Add(1)
}

func (m *Metrics) IncRecoveryPanicDialsTotal() {
	if m == nil {
		return
	}
	m.recoveryPanicDials.Add(1)
}

func (m *Metrics) IncDialAttemptByReason(reason string) {
	if m == nil || reason == "" {
		return
	}
	m.mu.Lock()
	m.dialAttemptByReason[reason]++
	m.mu.Unlock()
}

func (m *Metrics) IncDialSuccessByReason(reason string) {
	if m == nil || reason == "" {
		return
	}
	m.mu.Lock()
	m.dialSuccessByReason[reason]++
	m.mu.Unlock()
}

func (m *Metrics) IncDialFailByReason(reason string) {
	if m == nil || reason == "" {
		return
	}
	m.mu.Lock()
	m.dialFailByReason[reason]++
	m.mu.Unlock()
}

func (m *Metrics) IncHelloSuccessTotal() {
	if m == nil {
		return
	}
	m.helloSuccessTotal.Add(1)
}

func (m *Metrics) IncQuicConnectSuccessTotal() {
	if m == nil {
		return
	}
	m.quicConnectSuccess.Add(1)
}

func (m *Metrics) IncHelloHandshakeSuccessTotal() {
	if m == nil {
		return
	}
	m.helloHSOkTotal.Add(1)
}

func (m *Metrics) IncHelloHandshakeFailByReason(reason string) {
	if m == nil || reason == "" {
		return
	}
	m.helloHSFailTotal.Add(1)
	m.mu.Lock()
	m.helloHSFailByReason[reason]++
	m.mu.Unlock()
}

func (m *Metrics) IncHelloRejectByReason(reason string) {
	if m == nil || reason == "" {
		return
	}
	m.mu.Lock()
	m.helloRejectByReason[reason]++
	m.mu.Unlock()
}

func (m *Metrics) IncCandidateAvailable() {
	if m == nil {
		return
	}
	m.candidateAvailable.Add(1)
}

func (m *Metrics) IncBackoffBlocked() {
	if m == nil {
		return
	}
	m.backoffBlocked.Add(1)
}

func (m *Metrics) IncSeedDialSkippedTotal() {
	if m == nil {
		return
	}
	m.seedDialSkipped.Add(1)
}

func (m *Metrics) SetRecoveryModeActive(active bool) {
	if m == nil {
		return
	}
	m.recoveryModeActive.Store(active)
}

func (m *Metrics) IncRecoveryEnterTotal() {
	if m == nil {
		return
	}
	m.recoveryEnterTotal.Add(1)
}

func (m *Metrics) IncRecoveryExitTotal() {
	if m == nil {
		return
	}
	m.recoveryExitTotal.Add(1)
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
	dialAttemptByReason := map[string]uint64{}
	dialSuccessByReason := map[string]uint64{}
	dialFailByReason := map[string]uint64{}
	helloRejectByReason := map[string]uint64{}
	helloHSFailByReason := map[string]uint64{}
	if m != nil {
		m.mu.Lock()
		for k, v := range m.recvByType {
			recvByType[k] = v
		}
		for k, v := range m.dropByReason {
			dropByReason[k] = v
		}
		for k, v := range m.dialAttemptByReason {
			dialAttemptByReason[k] = v
		}
		for k, v := range m.dialSuccessByReason {
			dialSuccessByReason[k] = v
		}
		for k, v := range m.dialFailByReason {
			dialFailByReason[k] = v
		}
		for k, v := range m.helloRejectByReason {
			helloRejectByReason[k] = v
		}
		for k, v := range m.helloHSFailByReason {
			helloHSFailByReason[k] = v
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
		Recent:                     recent,
		RecvByType:                 recvByType,
		DropByReason:               dropByReason,
		CurrentConns:               m.currentConns.Load(),
		CurrentStreams:             m.currentStreams.Load(),
		PeerTableSize:              m.peertableSize.Load(),
		OutboundConnected:          m.outboundConnected.Load(),
		InboundConnected:           m.inboundConnected.Load(),
		PexRequestsTotal:           m.pexRequestsTotal.Load(),
		PexResponsesTotal:          m.pexResponsesTotal.Load(),
		DialAttemptsTotal:          m.dialAttemptsTotal.Load(),
		DialSuccessTotal:           m.dialSuccessTotal.Load(),
		PexReqSentTotal:            m.pexReqSentTotal.Load(),
		PexRespRecvTotal:           m.pexRespRecvTotal.Load(),
		EvictionCountTotal:         m.evictionCountTotal.Load(),
		DialAttemptByReason:        dialAttemptByReason,
		DialSuccessByReason:        dialSuccessByReason,
		DialFailByReason:           dialFailByReason,
		QuicConnectSuccessTotal:    m.quicConnectSuccess.Load(),
		HelloHandshakeSuccessTotal: m.helloHSOkTotal.Load(),
		HelloHandshakeFailTotal:    m.helloHSFailTotal.Load(),
		HelloHandshakeFailByReason: helloHSFailByReason,
		HelloSuccessTotal:          m.helloSuccessTotal.Load(),
		HelloRejectByReason:        helloRejectByReason,
		CandidateAvailable:         m.candidateAvailable.Load(),
		BackoffBlocked:             m.backoffBlocked.Load(),
		SeedDialSkippedTotal:       m.seedDialSkipped.Load(),
		RecoveryPanicDials:         m.recoveryPanicDials.Load(),
		RecoveryModeActive:         m.recoveryModeActive.Load(),
		RecoveryEnterTotal:         m.recoveryEnterTotal.Load(),
		RecoveryExitTotal:          m.recoveryExitTotal.Load(),
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
