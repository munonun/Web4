package node

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"sync"

	"web4mvp/internal/crypto"
	"web4mvp/internal/peer"
	"web4mvp/internal/proto"
)

type SessionState struct {
	mu            sync.Mutex
	SendKey       []byte
	RecvKey       []byte
	NonceBaseSend []byte
	NonceBaseRecv []byte
	SendCounter   uint64
	RecvCounter   uint64
	HaveRecv      bool
}

type PendingHandshake struct {
	ToID        [32]byte
	EA          []byte
	Na          []byte
	Ephemeral   *crypto.Ephemeral
	Hello1Bytes []byte
}

type SessionStore struct {
	mu         sync.Mutex
	sessions   map[[32]byte]*SessionState
	pending    map[[32]byte]*PendingHandshake
	lastHello1 map[[32]byte][32]byte
}

func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions:   make(map[[32]byte]*SessionState),
		pending:    make(map[[32]byte]*PendingHandshake),
		lastHello1: make(map[[32]byte][32]byte),
	}
}

func (s *SessionStore) Get(id [32]byte) (*SessionState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.sessions[id]
	return st, ok
}

func (s *SessionStore) Set(id [32]byte, st *SessionState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = st
}

func (s *SessionStore) SetPending(id [32]byte, p *PendingHandshake) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[id] = p
}

func (s *SessionStore) PopPending(id [32]byte) (*PendingHandshake, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[id]
	if ok {
		delete(s.pending, id)
	}
	return p, ok
}

func (s *SessionStore) Has(id [32]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.sessions[id]
	return ok
}

func (s *SessionStore) IsHello1Replay(id [32]byte, hash [32]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if last, ok := s.lastHello1[id]; ok && last == hash {
		return true
	}
	return false
}

func (s *SessionStore) RecordHello1(id [32]byte, hash [32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastHello1[id] = hash
}

func (s *SessionState) NextSendSeq() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.SendCounter == ^uint64(0) {
		return 0, errors.New("send counter exhausted")
	}
	seq := s.SendCounter
	s.SendCounter++
	return seq, nil
}

func (s *SessionState) AcceptRecvSeq(seq uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.HaveRecv && seq <= s.RecvCounter {
		return errors.New("replayed or out-of-order seq")
	}
	s.RecvCounter = seq
	s.HaveRecv = true
	return nil
}

func (n *Node) BuildHello1(toID [32]byte) (proto.Hello1Msg, error) {
	if n == nil || n.Sessions == nil {
		return proto.Hello1Msg{}, errors.New("session store unavailable")
	}
	eph, err := crypto.GenerateEphemeral()
	if err != nil {
		return proto.Hello1Msg{}, err
	}
	ea, err := eph.Public()
	if err != nil {
		eph.Destroy()
		return proto.Hello1Msg{}, err
	}
	na := make([]byte, 32)
	if _, err := rand.Read(na); err != nil {
		eph.Destroy()
		return proto.Hello1Msg{}, err
	}
	fromID := n.ID
	sigInput := hello1SigInput(fromID, toID, ea, na)
	sig, err := crypto.SignDigest(n.PrivKey, crypto.SHA3_256(sigInput))
	if err != nil {
		eph.Destroy()
		return proto.Hello1Msg{}, err
	}
	msg := proto.Hello1Msg{
		Type:       proto.MsgTypeHello1,
		FromNodeID: hex.EncodeToString(fromID[:]),
		FromPub:    hex.EncodeToString(n.PubKey),
		ToNodeID:   hex.EncodeToString(toID[:]),
		EA:         hex.EncodeToString(ea),
		Na:         hex.EncodeToString(na),
		Sig:        hex.EncodeToString(sig),
	}
	n.Sessions.SetPending(toID, &PendingHandshake{
		ToID:        toID,
		EA:          ea,
		Na:          na,
		Ephemeral:   eph,
		Hello1Bytes: proto.Hello1Bytes(fromID, toID, ea, na),
	})
	return msg, nil
}

func (n *Node) HandleHello1(m proto.Hello1Msg) (proto.Hello2Msg, error) {
	return n.HandleHello1From(m, "")
}

func (n *Node) HandleHello1From(m proto.Hello1Msg, senderAddr string) (proto.Hello2Msg, error) {
	if n == nil || n.Sessions == nil || n.Peers == nil {
		return proto.Hello2Msg{}, errors.New("node unavailable")
	}
	fromID, toID, fromPub, ea, na, sig, err := proto.DecodeHello1Fields(m)
	if err != nil {
		return proto.Hello2Msg{}, err
	}
	derived := DeriveNodeID(fromPub)
	if derived != fromID {
		return proto.Hello2Msg{}, errors.New("hello1 from_id mismatch")
	}
	if fromID == n.ID {
		return proto.Hello2Msg{}, errors.New("hello1 from_id self")
	}
	if toID != n.ID {
		return proto.Hello2Msg{}, errors.New("hello1 to_id mismatch")
	}
	sigInput := hello1SigInput(fromID, toID, ea, na)
	if !crypto.VerifyDigest(fromPub, crypto.SHA3_256(sigInput), sig) {
		return proto.Hello2Msg{}, errors.New("bad hello1 signature")
	}
	h1BytesForReplay := proto.Hello1Bytes(fromID, toID, ea, na)
	h1HashBytes := crypto.SHA3_256(h1BytesForReplay)
	var h1Hash [32]byte
	copy(h1Hash[:], h1HashBytes)
	if n.Sessions.IsHello1Replay(fromID, h1Hash) {
		return proto.Hello2Msg{}, errors.New("hello1 replay")
	}
	n.Sessions.RecordHello1(fromID, h1Hash)
	peerInfo := peer.Peer{NodeID: fromID, PubKey: fromPub}
	if err := n.Peers.Upsert(peerInfo, true); err != nil {
		return proto.Hello2Msg{}, err
	}
	observedAddr := senderAddr
	if observedAddr == "" && m.FromAddr != "" && isAddrParseable(m.FromAddr) {
		observedAddr = m.FromAddr
	}
	if observedAddr != "" {
		candidateAddr := ""
		verified := false
		if m.FromAddr != "" && isAddrParseable(m.FromAddr) && (senderAddr == "" || sameHost(senderAddr, m.FromAddr)) {
			candidateAddr = m.FromAddr
			verified = senderAddr != "" && m.FromAddr == senderAddr
		} else if senderAddr != "" {
			candidateAddr = senderAddr
			verified = true
		}
		if _, err := n.Peers.ObserveAddr(peerInfo, observedAddr, candidateAddr, verified, true); err != nil {
			return proto.Hello2Msg{}, err
		}
		if candidateAddr != "" && !verified {
			if _, err := n.Peers.SetAddrUnverified(peerInfo, candidateAddr, true); err != nil {
				return proto.Hello2Msg{}, err
			}
		}
	}
	eph, err := crypto.GenerateEphemeral()
	if err != nil {
		return proto.Hello2Msg{}, err
	}
	eb, err := eph.Public()
	if err != nil {
		eph.Destroy()
		return proto.Hello2Msg{}, err
	}
	nb := make([]byte, 32)
	if _, err := rand.Read(nb); err != nil {
		eph.Destroy()
		return proto.Hello2Msg{}, err
	}
	sigInput2 := hello2SigInput(fromID, toID, ea, eb, na, nb)
	sig2, err := crypto.SignDigest(n.PrivKey, crypto.SHA3_256(sigInput2))
	if err != nil {
		eph.Destroy()
		return proto.Hello2Msg{}, err
	}
	h1Bytes := proto.Hello1Bytes(fromID, toID, ea, na)
	h2Bytes := proto.Hello2Bytes(n.ID, fromID, eb, nb)
	transcript := crypto.SHA3_256(append(h1Bytes, h2Bytes...))
	ss, err := eph.Shared(ea)
	if err != nil {
		eph.Destroy()
		return proto.Hello2Msg{}, err
	}
	keys, err := crypto.DeriveSessionKeys(ss, transcript)
	if err != nil {
		eph.Destroy()
		return proto.Hello2Msg{}, err
	}
	zeroBytes(ss)
	zeroBytes(keys.Master)
	eph.Destroy()
	n.Sessions.Set(fromID, &SessionState{
		SendKey:       keys.RecvKey,
		RecvKey:       keys.SendKey,
		NonceBaseSend: keys.NonceBaseRecv,
		NonceBaseRecv: keys.NonceBaseSend,
	})
	return proto.Hello2Msg{
		Type:       proto.MsgTypeHello2,
		FromNodeID: hex.EncodeToString(n.ID[:]),
		FromPub:    hex.EncodeToString(n.PubKey),
		ToNodeID:   hex.EncodeToString(fromID[:]),
		EB:         hex.EncodeToString(eb),
		Nb:         hex.EncodeToString(nb),
		Sig:        hex.EncodeToString(sig2),
	}, nil
}

func (n *Node) HandleHello2(m proto.Hello2Msg) error {
	return n.HandleHello2From(m, "")
}

func (n *Node) HandleHello2From(m proto.Hello2Msg, senderAddr string) error {
	if n == nil || n.Sessions == nil || n.Peers == nil {
		return errors.New("node unavailable")
	}
	fromID, toID, fromPub, eb, nb, sig, err := proto.DecodeHello2Fields(m)
	if err != nil {
		return err
	}
	derived := DeriveNodeID(fromPub)
	if derived != fromID {
		return errors.New("hello2 from_id mismatch")
	}
	if toID != n.ID {
		return errors.New("hello2 to_id mismatch")
	}
	pending, ok := n.Sessions.PopPending(fromID)
	if !ok || pending == nil || pending.Ephemeral == nil {
		return errors.New("missing pending handshake")
	}
	sigInput := hello2SigInput(n.ID, fromID, pending.EA, eb, pending.Na, nb)
	if !crypto.VerifyDigest(fromPub, crypto.SHA3_256(sigInput), sig) {
		pending.Ephemeral.Destroy()
		return errors.New("bad hello2 signature")
	}
	if err := n.Peers.Upsert(peer.Peer{NodeID: fromID, PubKey: fromPub}, true); err != nil {
		pending.Ephemeral.Destroy()
		return err
	}
	if senderAddr != "" {
		candidateAddr := ""
		verified := false
		if m.FromAddr != "" && sameHost(senderAddr, m.FromAddr) {
			candidateAddr = m.FromAddr
			verified = m.FromAddr == senderAddr
		}
		if _, err := n.Peers.ObserveAddr(peer.Peer{NodeID: fromID, PubKey: fromPub}, senderAddr, candidateAddr, verified, true); err != nil {
			pending.Ephemeral.Destroy()
			return err
		}
		if candidateAddr != "" && !verified {
			if _, err := n.Peers.SetAddrUnverified(peer.Peer{NodeID: fromID, PubKey: fromPub}, candidateAddr, true); err != nil {
				pending.Ephemeral.Destroy()
				return err
			}
		}
	}
	h1Bytes := pending.Hello1Bytes
	h2Bytes := proto.Hello2Bytes(fromID, toID, eb, nb)
	transcript := crypto.SHA3_256(append(h1Bytes, h2Bytes...))
	ss, err := pending.Ephemeral.Shared(eb)
	if err != nil {
		pending.Ephemeral.Destroy()
		return err
	}
	keys, err := crypto.DeriveSessionKeys(ss, transcript)
	if err != nil {
		pending.Ephemeral.Destroy()
		return err
	}
	zeroBytes(ss)
	zeroBytes(keys.Master)
	pending.Ephemeral.Destroy()
	n.Sessions.Set(fromID, &SessionState{
		SendKey:       keys.SendKey,
		RecvKey:       keys.RecvKey,
		NonceBaseSend: keys.NonceBaseSend,
		NonceBaseRecv: keys.NonceBaseRecv,
	})
	return nil
}

func hello1SigInput(fromID, toID [32]byte, ea, na []byte) []byte {
	buf := make([]byte, 0, len("web4:h1:v1")+32+32+len(ea)+len(na))
	buf = append(buf, []byte("web4:h1:v1")...)
	buf = append(buf, fromID[:]...)
	buf = append(buf, toID[:]...)
	buf = append(buf, ea...)
	buf = append(buf, na...)
	return buf
}

func hello2SigInput(fromID, toID [32]byte, ea, eb, na, nb []byte) []byte {
	buf := make([]byte, 0, len("web4:h2:v1")+32+32+len(ea)+len(eb)+len(na)+len(nb))
	buf = append(buf, []byte("web4:h2:v1")...)
	buf = append(buf, fromID[:]...)
	buf = append(buf, toID[:]...)
	buf = append(buf, ea...)
	buf = append(buf, eb...)
	buf = append(buf, na...)
	buf = append(buf, nb...)
	return buf
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func sameHost(a, b string) bool {
	ha, _, err := net.SplitHostPort(a)
	if err != nil {
		ha = a
	}
	hb, _, err := net.SplitHostPort(b)
	if err != nil {
		hb = b
	}
	if ha == "" || hb == "" {
		return false
	}
	if ha == hb {
		return true
	}
	ipA := net.ParseIP(ha)
	ipB := net.ParseIP(hb)
	if ipA != nil && ipB != nil && ipA.IsLoopback() && ipB.IsLoopback() {
		return true
	}
	return false
}

func isAddrParseable(addr string) bool {
	_, _, err := net.SplitHostPort(addr)
	return err == nil
}
