package node

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
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
	ToID                 [32]byte
	SuiteID              byte
	Supports             []byte
	EA                   []byte
	Na                   []byte
	MLKEMPriv            []byte
	PQPub                []byte
	PQPriv               []byte
	Ephemeral            *crypto.Ephemeral
	Hello1Bytes          []byte
	Hello1TranscriptHash []byte
	Hello1SessionID      []byte
}

const (
	SuiteHybridMLKEMMLDSA byte = 0
	SuiteLegacyX25519RSA  byte = 1
	// Deprecated alias retained for backward compatibility.
	SuiteHybridMLKEMSPHINCS = SuiteHybridMLKEMMLDSA
)

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
	supports := supportedSuites()
	suiteID := selectInitiatorSuite(supports)
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
	var mlkemPub, mlkemPriv []byte
	var pqPub, pqPriv []byte
	var pqBindSig []byte
	if suiteID == SuiteHybridMLKEMSPHINCS {
		mlkemPub, mlkemPriv, err = crypto.GenMLKEM768Keypair()
		if err != nil {
			eph.Destroy()
			return proto.Hello1Msg{}, err
		}
		pqPub, pqPriv, err = n.loadOrCreateMLDSAKeypair()
		if err != nil {
			eph.Destroy()
			return proto.Hello1Msg{}, err
		}
		bind := pqBindInput(n.ID, pqPub)
		pqBindSig, err = crypto.SignDigest(n.PrivKey, crypto.SHA3_256(bind))
		if err != nil {
			eph.Destroy()
			return proto.Hello1Msg{}, err
		}
	}
	fromID := n.ID
	listenAddr := normalizeListenAddr(n.ListenAddr())
	h1Bytes := hello1TranscriptBytes(suiteID, fromID, toID, listenAddr, ea, na, mlkemPub)
	h1TranscriptHash := crypto.SHA3_256(h1Bytes)
	hello1SessionID := sessionIDForHandshake(suiteID, fromID, toID, ea, zero32(), h1TranscriptHash)
	sigInput := hello1SigInput(suiteID, fromID, toID, listenAddr, ea, na, hello1SessionID)
	sig, err := n.signHelloBySuiteCached(suiteID, n.PrivKey, pqPriv, sigInput)
	if err != nil {
		eph.Destroy()
		return proto.Hello1Msg{}, err
	}
	msg := proto.Hello1Msg{
		Type:            proto.MsgTypeHello1,
		FromNodeID:      hex.EncodeToString(fromID[:]),
		FromPub:         hex.EncodeToString(n.PubKey),
		ListenAddr:      listenAddr,
		FromAddr:        listenAddr,
		ToNodeID:        hex.EncodeToString(toID[:]),
		SuiteID:         int(suiteID),
		SupportedSuites: encodeSupportedSuites(supports),
		EA:              hex.EncodeToString(ea),
		Na:              hex.EncodeToString(na),
		MLKEMPub:        hex.EncodeToString(mlkemPub),
		PQPub:           hex.EncodeToString(pqPub),
		PQBindSig:       hex.EncodeToString(pqBindSig),
		SessionID:       hex.EncodeToString(hello1SessionID),
		Sig:             hex.EncodeToString(sig),
	}
	n.Sessions.SetPending(toID, &PendingHandshake{
		ToID:                 toID,
		SuiteID:              suiteID,
		Supports:             supports,
		EA:                   ea,
		Na:                   na,
		MLKEMPriv:            mlkemPriv,
		PQPub:                pqPub,
		PQPriv:               pqPriv,
		Ephemeral:            eph,
		Hello1Bytes:          h1Bytes,
		Hello1TranscriptHash: h1TranscriptHash,
		Hello1SessionID:      hello1SessionID,
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
	listenAddr := advertisedListenAddr(m.ListenAddr, m.FromAddr)
	peerSupports := parseSupportedSuites(m.SupportedSuites)
	selfSupports := supportedSuites()
	suiteID, err := validateSuiteSelection(byte(m.SuiteID), selfSupports, peerSupports)
	if err != nil {
		return proto.Hello2Msg{}, err
	}
	mlkemPub, err := decodeHexOptional(m.MLKEMPub)
	if err != nil {
		return proto.Hello2Msg{}, errors.New("bad mlkem_pub")
	}
	if suiteID == SuiteHybridMLKEMSPHINCS && len(mlkemPub) != crypto.MLKEM768PublicKeySize {
		return proto.Hello2Msg{}, errors.New("bad mlkem_pub")
	}
	pqPub, err := decodeHexOptional(m.PQPub)
	if err != nil {
		return proto.Hello2Msg{}, errors.New("bad pq_pub")
	}
	pqBindSig, err := decodeHexOptional(m.PQBindSig)
	if err != nil {
		return proto.Hello2Msg{}, errors.New("bad pq_bind_sig")
	}
	if suiteID == SuiteHybridMLKEMSPHINCS {
		if len(pqPub) == 0 || len(pqBindSig) == 0 {
			return proto.Hello2Msg{}, errors.New("missing pq binding")
		}
		bindInput := pqBindInput(fromID, pqPub)
		if !crypto.VerifyDigest(fromPub, crypto.SHA3_256(bindInput), pqBindSig) {
			return proto.Hello2Msg{}, errors.New("bad pq binding")
		}
	}

	h1BytesForReplay := hello1TranscriptBytes(suiteID, fromID, toID, listenAddr, ea, na, mlkemPub)
	h1TranscriptHash := crypto.SHA3_256(h1BytesForReplay)
	hello1SessionID, err := decodeSessionIDHex(m.SessionID)
	if err != nil {
		if !allowLegacyHelloSig() {
			return proto.Hello2Msg{}, err
		}
	}
	expectedHello1SID := sessionIDForHandshake(suiteID, fromID, toID, ea, zero32(), h1TranscriptHash)
	if len(hello1SessionID) > 0 && !bytesEqual(hello1SessionID, expectedHello1SID) {
		return proto.Hello2Msg{}, errors.New("hello1 session_id mismatch")
	}
	sigInput := hello1SigInput(suiteID, fromID, toID, listenAddr, ea, na, hello1SessionID)
	if len(hello1SessionID) == 0 {
		sigInput = hello1SigInputLegacy(suiteID, fromID, toID, listenAddr, ea, na)
	}
	if !verifyHelloBySuite(suiteID, fromPub, pqPub, sigInput, sig) {
		return proto.Hello2Msg{}, errors.New("bad hello1 signature")
	}
	var h1Hash [32]byte
	copy(h1Hash[:], h1TranscriptHash)
	if n.Sessions.IsHello1Replay(fromID, h1Hash) {
		return proto.Hello2Msg{}, errors.New("hello1 replay")
	}
	n.Sessions.RecordHello1(fromID, h1Hash)
	peerInfo := peer.Peer{NodeID: fromID, PubKey: fromPub}
	if err := n.Peers.Upsert(peerInfo, true); err != nil {
		return proto.Hello2Msg{}, err
	}
	if senderAddr != "" {
		if _, err := n.Peers.ObserveAddr(peerInfo, senderAddr, "", false, true); err != nil {
			return proto.Hello2Msg{}, err
		}
	}
	if listenAddr != "" && (senderAddr == "" || sameHost(senderAddr, listenAddr)) {
		if _, err := n.Peers.SetAddrUnverified(peerInfo, listenAddr, true); err != nil {
			return proto.Hello2Msg{}, err
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
	var mlkemCT []byte
	var ssMLKEM []byte
	if suiteID == SuiteHybridMLKEMSPHINCS {
		mlkemCT, ssMLKEM, err = crypto.MLKEM768Encapsulate(mlkemPub)
		if err != nil {
			eph.Destroy()
			return proto.Hello2Msg{}, err
		}
	}
	pqPubResp, pqPrivResp, err := n.maybeGenPQForSuite(suiteID)
	if err != nil {
		eph.Destroy()
		return proto.Hello2Msg{}, err
	}
	pqBindSigResp := []byte(nil)
	if suiteID == SuiteHybridMLKEMSPHINCS {
		bind := pqBindInput(n.ID, pqPubResp)
		pqBindSigResp, err = crypto.SignDigest(n.PrivKey, crypto.SHA3_256(bind))
		if err != nil {
			eph.Destroy()
			return proto.Hello2Msg{}, err
		}
	}
	respListenAddr := normalizeListenAddr(n.ListenAddr())
	h2Bytes := hello2TranscriptBytes(suiteID, n.ID, fromID, respListenAddr, eb, nb, mlkemCT)
	transcript := crypto.SHA3_256(append(h1BytesForReplay, h2Bytes...))
	sessionID := sessionIDForHandshake(suiteID, fromID, toID, ea, eb, transcript)
	sigInput2 := hello2SigInput(suiteID, fromID, toID, respListenAddr, ea, eb, na, nb, sessionID)
	sig2, err := n.signHelloBySuiteCached(suiteID, n.PrivKey, pqPrivResp, sigInput2)
	if err != nil {
		eph.Destroy()
		return proto.Hello2Msg{}, err
	}
	ssX, err := eph.Shared(ea)
	if err != nil {
		eph.Destroy()
		return proto.Hello2Msg{}, err
	}
	keys, err := crypto.DeriveSessionKeysBySuite(ssX, ssMLKEM, transcript, suiteID)
	if err != nil {
		eph.Destroy()
		return proto.Hello2Msg{}, err
	}
	zeroBytes(ssX)
	zeroBytes(ssMLKEM)
	zeroBytes(keys.Master)
	eph.Destroy()
	n.Sessions.Set(fromID, &SessionState{
		SendKey:       keys.RecvKey,
		RecvKey:       keys.SendKey,
		NonceBaseSend: keys.NonceBaseRecv,
		NonceBaseRecv: keys.NonceBaseSend,
	})
	return proto.Hello2Msg{
		Type:            proto.MsgTypeHello2,
		FromNodeID:      hex.EncodeToString(n.ID[:]),
		FromPub:         hex.EncodeToString(n.PubKey),
		ListenAddr:      respListenAddr,
		FromAddr:        respListenAddr,
		ToNodeID:        hex.EncodeToString(fromID[:]),
		SuiteID:         int(suiteID),
		SupportedSuites: encodeSupportedSuites(selfSupports),
		EB:              hex.EncodeToString(eb),
		Nb:              hex.EncodeToString(nb),
		MLKEMCT:         hex.EncodeToString(mlkemCT),
		PQPub:           hex.EncodeToString(pqPubResp),
		PQBindSig:       hex.EncodeToString(pqBindSigResp),
		SessionID:       hex.EncodeToString(sessionID),
		Sig:             hex.EncodeToString(sig2),
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
	peerSupports := parseSupportedSuites(m.SupportedSuites)
	suiteID, err := validateSuiteSelection(byte(m.SuiteID), pending.Supports, peerSupports)
	if err != nil {
		pending.Ephemeral.Destroy()
		return err
	}
	if suiteID != pending.SuiteID {
		pending.Ephemeral.Destroy()
		return errors.New("suite mismatch")
	}
	mlkemCT, err := decodeHexOptional(m.MLKEMCT)
	if err != nil {
		pending.Ephemeral.Destroy()
		return errors.New("bad mlkem_ct")
	}
	pqPub, err := decodeHexOptional(m.PQPub)
	if err != nil {
		pending.Ephemeral.Destroy()
		return errors.New("bad pq_pub")
	}
	pqBindSig, err := decodeHexOptional(m.PQBindSig)
	if err != nil {
		pending.Ephemeral.Destroy()
		return errors.New("bad pq_bind_sig")
	}
	if suiteID == SuiteHybridMLKEMSPHINCS {
		if len(mlkemCT) != crypto.MLKEM768CiphertextSize || len(pqPub) == 0 || len(pqBindSig) == 0 {
			pending.Ephemeral.Destroy()
			return errors.New("missing pq hybrid fields")
		}
		bindInput := pqBindInput(fromID, pqPub)
		if !crypto.VerifyDigest(fromPub, crypto.SHA3_256(bindInput), pqBindSig) {
			pending.Ephemeral.Destroy()
			return errors.New("bad pq binding")
		}
	}
	listenAddr := advertisedListenAddr(m.ListenAddr, m.FromAddr)
	sessionID, err := decodeSessionIDHex(m.SessionID)
	if err != nil {
		if !allowLegacyHelloSig() {
			return err
		}
	}
	h1Bytes := pending.Hello1Bytes
	h2Bytes := hello2TranscriptBytes(suiteID, fromID, toID, listenAddr, eb, nb, mlkemCT)
	transcript := crypto.SHA3_256(append(h1Bytes, h2Bytes...))
	expectedSID := sessionIDForHandshake(suiteID, n.ID, fromID, pending.EA, eb, transcript)
	if len(sessionID) > 0 && !bytesEqual(sessionID, expectedSID) {
		pending.Ephemeral.Destroy()
		return errors.New("hello2 session_id mismatch")
	}
	sigInput := hello2SigInput(suiteID, n.ID, fromID, listenAddr, pending.EA, eb, pending.Na, nb, sessionID)
	if len(sessionID) == 0 {
		sigInput = hello2SigInputLegacy(suiteID, n.ID, fromID, listenAddr, pending.EA, eb, pending.Na, nb)
	}
	if !verifyHelloBySuite(suiteID, fromPub, pqPub, sigInput, sig) {
		pending.Ephemeral.Destroy()
		return errors.New("bad hello2 signature")
	}
	if err := n.Peers.Upsert(peer.Peer{NodeID: fromID, PubKey: fromPub}, true); err != nil {
		pending.Ephemeral.Destroy()
		return err
	}
	if senderAddr != "" {
		if _, err := n.Peers.ObserveAddr(peer.Peer{NodeID: fromID, PubKey: fromPub}, senderAddr, "", false, true); err != nil {
			pending.Ephemeral.Destroy()
			return err
		}
	}
	if listenAddr != "" && (senderAddr == "" || sameHost(senderAddr, listenAddr)) {
		if _, err := n.Peers.SetAddrUnverified(peer.Peer{NodeID: fromID, PubKey: fromPub}, listenAddr, true); err != nil {
			pending.Ephemeral.Destroy()
			return err
		}
	}
	ssX, err := pending.Ephemeral.Shared(eb)
	if err != nil {
		pending.Ephemeral.Destroy()
		return err
	}
	var ssMLKEM []byte
	if suiteID == SuiteHybridMLKEMSPHINCS {
		ssMLKEM, err = crypto.MLKEM768Decapsulate(pending.MLKEMPriv, mlkemCT)
		if err != nil {
			pending.Ephemeral.Destroy()
			return err
		}
	}
	keys, err := crypto.DeriveSessionKeysBySuite(ssX, ssMLKEM, transcript, suiteID)
	if err != nil {
		pending.Ephemeral.Destroy()
		return err
	}
	zeroBytes(ssX)
	zeroBytes(ssMLKEM)
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

func hello1SigInput(suiteID byte, fromID, toID [32]byte, listenAddr string, ea, na, sessionID []byte) []byte {
	buf := make([]byte, 0, len("web4:h1:v4")+1+32+32+len(listenAddr)+len(ea)+len(na)+len(sessionID))
	buf = append(buf, []byte("web4:h1:v4")...)
	buf = append(buf, suiteID)
	buf = append(buf, fromID[:]...)
	buf = append(buf, toID[:]...)
	buf = append(buf, []byte(listenAddr)...)
	buf = append(buf, ea...)
	buf = append(buf, na...)
	buf = append(buf, sessionID...)
	return buf
}

func hello1SigInputLegacy(suiteID byte, fromID, toID [32]byte, listenAddr string, ea, na []byte) []byte {
	buf := make([]byte, 0, len("web4:h1:v3")+1+32+32+len(listenAddr)+len(ea)+len(na))
	buf = append(buf, []byte("web4:h1:v3")...)
	buf = append(buf, suiteID)
	buf = append(buf, fromID[:]...)
	buf = append(buf, toID[:]...)
	buf = append(buf, []byte(listenAddr)...)
	buf = append(buf, ea...)
	buf = append(buf, na...)
	return buf
}

func hello2SigInput(suiteID byte, fromID, toID [32]byte, listenAddr string, ea, eb, na, nb, sessionID []byte) []byte {
	buf := make([]byte, 0, len("web4:h2:v4")+1+32+32+len(listenAddr)+len(ea)+len(eb)+len(na)+len(nb)+len(sessionID))
	buf = append(buf, []byte("web4:h2:v4")...)
	buf = append(buf, suiteID)
	buf = append(buf, fromID[:]...)
	buf = append(buf, toID[:]...)
	buf = append(buf, []byte(listenAddr)...)
	buf = append(buf, ea...)
	buf = append(buf, eb...)
	buf = append(buf, na...)
	buf = append(buf, nb...)
	buf = append(buf, sessionID...)
	return buf
}

func hello2SigInputLegacy(suiteID byte, fromID, toID [32]byte, listenAddr string, ea, eb, na, nb []byte) []byte {
	buf := make([]byte, 0, len("web4:h2:v3")+1+32+32+len(listenAddr)+len(ea)+len(eb)+len(na)+len(nb))
	buf = append(buf, []byte("web4:h2:v3")...)
	buf = append(buf, suiteID)
	buf = append(buf, fromID[:]...)
	buf = append(buf, toID[:]...)
	buf = append(buf, []byte(listenAddr)...)
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

func sessionIDForHandshake(suiteID byte, fromID, toID [32]byte, ea, eb, transcriptHash []byte) []byte {
	buf := make([]byte, 0, len("WEB4/session")+len(proto.ProtoVersion)+1+32+32+len(ea)+len(eb)+len(transcriptHash))
	buf = append(buf, []byte("WEB4/session")...)
	buf = append(buf, []byte(proto.ProtoVersion)...)
	buf = append(buf, suiteID)
	buf = append(buf, fromID[:]...)
	buf = append(buf, toID[:]...)
	buf = append(buf, ea...)
	buf = append(buf, eb...)
	buf = append(buf, transcriptHash...)
	sum := crypto.SHA3_256(buf)
	out := make([]byte, len(sum))
	copy(out, sum)
	return out
}

func zero32() []byte {
	return make([]byte, 32)
}

func hello1TranscriptBytes(suiteID byte, fromID, toID [32]byte, listenAddr string, ea, na, mlkemPub []byte) []byte {
	base := proto.Hello1Bytes(fromID, toID, ea, na)
	out := make([]byte, 0, len(base)+1+len(listenAddr)+len(mlkemPub))
	out = append(out, base...)
	out = append(out, suiteID)
	out = append(out, []byte(listenAddr)...)
	out = append(out, mlkemPub...)
	return out
}

func hello2TranscriptBytes(suiteID byte, fromID, toID [32]byte, listenAddr string, eb, nb, mlkemCT []byte) []byte {
	base := proto.Hello2Bytes(fromID, toID, eb, nb)
	out := make([]byte, 0, len(base)+1+len(listenAddr)+len(mlkemCT))
	out = append(out, base...)
	out = append(out, suiteID)
	out = append(out, []byte(listenAddr)...)
	out = append(out, mlkemCT...)
	return out
}

func decodeSessionIDHex(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("missing session_id")
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, errors.New("bad session_id")
	}
	return b, nil
}

func allowLegacyHelloSig() bool {
	return os.Getenv("WEB4_HELLO_ALLOW_LEGACY_SIG") == "1"
}

func allowSuite0() bool {
	return os.Getenv("WEB4_HANDSHAKE_DISABLE_SUITE0") != "1"
}

func allowDowngrade() bool {
	return os.Getenv("WEB4_HANDSHAKE_ALLOW_DOWNGRADE") == "1"
}

func supportedSuites() []byte {
	out := make([]byte, 0, 2)
	if allowSuite0() {
		out = append(out, SuiteHybridMLKEMSPHINCS)
	}
	out = append(out, SuiteLegacyX25519RSA)
	return out
}

func encodeSupportedSuites(suites []byte) string {
	if len(suites) == 0 {
		return ""
	}
	parts := make([]string, 0, len(suites))
	for _, s := range suites {
		parts = append(parts, strconv.Itoa(int(s)))
	}
	return strings.Join(parts, ",")
}

func parseSupportedSuites(v string) []byte {
	if strings.TrimSpace(v) == "" {
		return []byte{SuiteLegacyX25519RSA}
	}
	parts := strings.Split(v, ",")
	out := make([]byte, 0, len(parts))
	seen := make(map[byte]struct{}, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 0 || n > 255 {
			continue
		}
		b := byte(n)
		if _, ok := seen[b]; ok {
			continue
		}
		seen[b] = struct{}{}
		out = append(out, b)
	}
	if len(out) == 0 {
		return []byte{SuiteLegacyX25519RSA}
	}
	return out
}

func supportsSuite(suites []byte, suite byte) bool {
	for _, s := range suites {
		if s == suite {
			return true
		}
	}
	return false
}

func preferredInitiatorSuite() (byte, bool) {
	raw := strings.TrimSpace(os.Getenv("WEB4_HANDSHAKE_SUITE"))
	if raw == "" {
		return 0, false
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 || n > 255 {
		return 0, false
	}
	return byte(n), true
}

func selectInitiatorSuite(supports []byte) byte {
	if preferred, ok := preferredInitiatorSuite(); ok && supportsSuite(supports, preferred) {
		return preferred
	}
	if supportsSuite(supports, SuiteHybridMLKEMSPHINCS) {
		return SuiteHybridMLKEMSPHINCS
	}
	return SuiteLegacyX25519RSA
}

func validateSuiteSelection(selected byte, selfSupports, peerSupports []byte) (byte, error) {
	if !supportsSuite(selfSupports, selected) {
		return 0, errors.New("unsupported suite")
	}
	if !supportsSuite(peerSupports, selected) {
		return 0, errors.New("peer unsupported suite")
	}
	if selected == SuiteLegacyX25519RSA &&
		supportsSuite(selfSupports, SuiteHybridMLKEMSPHINCS) &&
		supportsSuite(peerSupports, SuiteHybridMLKEMSPHINCS) &&
		!allowDowngrade() {
		return 0, errors.New("downgrade detected")
	}
	return selected, nil
}

func pqBindInput(nodeID [32]byte, pqPub []byte) []byte {
	buf := make([]byte, 0, len("WEB4/pqbind")+32+len(pqPub))
	buf = append(buf, []byte("WEB4/pqbind")...)
	buf = append(buf, nodeID[:]...)
	buf = append(buf, pqPub...)
	return buf
}

func signHelloBySuite(suiteID byte, rsaPriv, pqPriv, input []byte) ([]byte, error) {
	digest := crypto.SHA3_256(input)
	if suiteID == SuiteHybridMLKEMSPHINCS {
		if len(pqPriv) == 0 {
			return nil, errors.New("missing pq private key")
		}
		return crypto.MLDSASign(pqPriv, digest)
	}
	return crypto.SignDigest(rsaPriv, digest)
}

func (n *Node) signHelloBySuiteCached(suiteID byte, rsaPriv, pqPriv, input []byte) ([]byte, error) {
	keyBytes := crypto.SHA3_256(input)
	var key [32]byte
	copy(key[:], keyBytes)
	if n != nil && n.sigCache != nil {
		if cached, ok := n.sigCache.get(key); ok {
			return cached, nil
		}
	}
	sig, err := signHelloBySuite(suiteID, rsaPriv, pqPriv, input)
	if err != nil {
		return nil, err
	}
	if n != nil && n.sigCache != nil {
		n.sigCache.put(key, sig)
	}
	return sig, nil
}

func verifyHelloBySuite(suiteID byte, rsaPub, pqPub, input, sig []byte) bool {
	digest := crypto.SHA3_256(input)
	if suiteID == SuiteHybridMLKEMSPHINCS {
		if len(pqPub) == 0 || len(sig) < 64 {
			return false
		}
		return crypto.MLDSAVerify(pqPub, digest, sig)
	}
	return crypto.VerifyDigest(rsaPub, digest, sig)
}

func (n *Node) maybeGenPQForSuite(suiteID byte) ([]byte, []byte, error) {
	if suiteID != SuiteHybridMLKEMSPHINCS {
		return nil, nil, nil
	}
	return n.loadOrCreateMLDSAKeypair()
}

func decodeHexOptional(v string) ([]byte, error) {
	if strings.TrimSpace(v) == "" {
		return nil, nil
	}
	return hex.DecodeString(v)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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

func normalizeListenAddr(addr string) string {
	if !isAddrParseable(addr) {
		return ""
	}
	return addr
}

func advertisedListenAddr(listenAddr, legacyFromAddr string) string {
	_ = legacyFromAddr
	return normalizeListenAddr(listenAddr)
}
