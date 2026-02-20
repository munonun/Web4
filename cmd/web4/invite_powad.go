package main

import (
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"

	"web4mvp/internal/crypto"
	"web4mvp/internal/node"
	"web4mvp/internal/proto"
)

type pendingPoWaDChallenge struct {
	FromID         [32]byte
	ToID           [32]byte
	FromPub        []byte
	Scope          uint32
	ChallengeNonce uint64
	ExpiresAt      uint64
	PowBits        uint8
	InviteID       []byte
}

type invitePoWaDBackoff struct {
	Fails int
	Until time.Time
}

type invitePoWaDState struct {
	mu         sync.Mutex
	challenges map[string]pendingPoWaDChallenge
	backoff    map[string]invitePoWaDBackoff
}

var invitePoWaD = &invitePoWaDState{
	challenges: make(map[string]pendingPoWaDChallenge),
	backoff:    make(map[string]invitePoWaDBackoff),
}

func resetInvitePoWaDState() {
	invitePoWaD = &invitePoWaDState{
		challenges: make(map[string]pendingPoWaDChallenge),
		backoff:    make(map[string]invitePoWaDBackoff),
	}
}

func inviteChallengeTTL() time.Duration {
	if v, ok := envInt("WEB4_POWAD_TTL_SEC"); ok && v > 0 {
		return time.Duration(v) * time.Second
	}
	if v, ok := envInt("WEB4_POWAD_CHALLENGE_TTL_SEC"); ok && v > 0 {
		return time.Duration(v) * time.Second
	}
	return 60 * time.Second
}

func inviteCertTTL() time.Duration {
	if v, ok := envInt("WEB4_INVITE_CERT_TTL_SEC"); ok && v > 0 {
		return time.Duration(v) * time.Second
	}
	return time.Hour
}

func (s *invitePoWaDState) allowBackoff(key string, now time.Time) bool {
	if key == "" {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.backoff[key]
	if !ok {
		return true
	}
	if now.After(b.Until) {
		delete(s.backoff, key)
		return true
	}
	return false
}

func (s *invitePoWaDState) failBackoff(key string, now time.Time) {
	if key == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.backoff[key]
	b.Fails++
	d := 250 * time.Millisecond
	if b.Fails > 1 {
		shift := b.Fails - 1
		if shift > 5 {
			shift = 5
		}
		d <<= shift
	}
	if d > 8*time.Second {
		d = 8 * time.Second
	}
	b.Until = now.Add(d)
	s.backoff[key] = b
}

func (s *invitePoWaDState) clearBackoff(key string) {
	if key == "" {
		return
	}
	s.mu.Lock()
	delete(s.backoff, key)
	s.mu.Unlock()
}

func (s *invitePoWaDState) putChallenge(c pendingPoWaDChallenge) {
	s.mu.Lock()
	key := hex.EncodeToString(c.InviteID)
	s.challenges[key] = c
	s.mu.Unlock()
	if os.Getenv("WEB4_DEBUG") == "1" {
		fmt.Fprintf(os.Stderr, "powad challenge stored key=%s now=%d expiry=%d\n", key, time.Now().Unix(), c.ExpiresAt)
	}
}

type inviteChallengeLookup int

const (
	inviteChallengeFound inviteChallengeLookup = iota
	inviteChallengeMissing
	inviteChallengeExpired
)

func (s *invitePoWaDState) getChallenge(inviteID []byte, now time.Time) (pendingPoWaDChallenge, inviteChallengeLookup) {
	key := hex.EncodeToString(inviteID)
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.challenges[key]
	if !ok {
		return pendingPoWaDChallenge{}, inviteChallengeMissing
	}
	if c.ExpiresAt < uint64(now.Unix()) {
		delete(s.challenges, key)
		return pendingPoWaDChallenge{}, inviteChallengeExpired
	}
	return c, inviteChallengeFound
}

func (s *invitePoWaDState) deleteChallenge(inviteID []byte) {
	s.mu.Lock()
	delete(s.challenges, hex.EncodeToString(inviteID))
	s.mu.Unlock()
}

func nextChallengeNonce() uint64 {
	var b [8]byte
	if _, err := crand.Read(b[:]); err == nil {
		return binary.BigEndian.Uint64(b[:])
	}
	return uint64(time.Now().UnixNano())
}

func inviteChallengeBindBytes(fromID, toID [32]byte, scope uint32, nonce uint64, expiresAt uint64) []byte {
	buf := make([]byte, 0, len("web4:v0:powad_challenge|")+32+32+4+8+8)
	buf = append(buf, []byte("web4:v0:powad_challenge|")...)
	buf = append(buf, fromID[:]...)
	buf = append(buf, toID[:]...)
	var tmp4 [4]byte
	binary.BigEndian.PutUint32(tmp4[:], scope)
	buf = append(buf, tmp4[:]...)
	var tmp8 [8]byte
	binary.BigEndian.PutUint64(tmp8[:], nonce)
	buf = append(buf, tmp8[:]...)
	binary.BigEndian.PutUint64(tmp8[:], expiresAt)
	buf = append(buf, tmp8[:]...)
	return buf
}

func deriveInviteID(fromID, toID [32]byte, scope uint32, nonce uint64, expiresAt uint64) []byte {
	sum := crypto.SHA3_256(inviteChallengeBindBytes(fromID, toID, scope, nonce, expiresAt))
	id := make([]byte, len(sum))
	copy(id, sum)
	return id
}

func issueInviteCert(self *node.Node, inviteePub []byte, inviteID []byte, scope uint32, powBits uint8, powNonce uint64, now time.Time) ([]byte, error) {
	if self == nil {
		return nil, fmt.Errorf("node unavailable")
	}
	cert := proto.InviteCert{
		V:          1,
		InviterPub: self.PubKey,
		InviteePub: inviteePub,
		InviteID:   inviteID,
		IssuedAt:   uint64(now.Unix()),
		ExpiresAt:  uint64(now.Add(inviteCertTTL()).Unix()),
		Scope:      scope,
		PowBits:    powBits,
		PowNonce:   powNonce,
	}
	signBytes, err := proto.EncodeInviteCertForSig(cert)
	if err != nil {
		return nil, err
	}
	sig, err := crypto.SignDigest(self.PrivKey, crypto.SHA3_256(signBytes))
	if err != nil {
		return nil, err
	}
	cert.Sig = sig
	msg := proto.InviteCertMsgFromCert(cert)
	return proto.EncodeInviteCertMsg(msg)
}

func handleInviteRequest(self *node.Node, data []byte) ([]byte, error) {
	msg, err := proto.DecodeInviteRequestMsg(data)
	if err != nil {
		return nil, err
	}
	fromID, err := proto.DecodeNodeIDHex(msg.FromNodeID)
	if err != nil {
		return nil, fmt.Errorf("bad from_node_id")
	}
	toID, err := proto.DecodeNodeIDHex(msg.ToNodeID)
	if err != nil {
		return nil, fmt.Errorf("bad to_node_id")
	}
	if self == nil || toID != self.ID {
		return nil, fmt.Errorf("invite_request to_id mismatch")
	}
	fromPub, err := hex.DecodeString(msg.FromPub)
	if err != nil || len(fromPub) == 0 || !crypto.IsRSAPublicKey(fromPub) {
		return nil, fmt.Errorf("bad from_pub")
	}
	if node.DeriveNodeID(fromPub) != fromID {
		return nil, fmt.Errorf("invite_request from_id mismatch")
	}
	if msg.Scope == 0 {
		return nil, fmt.Errorf("missing scope")
	}
	fromHex := hex.EncodeToString(fromID[:])
	key := "invite_req:" + fromHex
	now := time.Now()
	if !recvNodeLimiter.Allow(key) {
		return nil, fmt.Errorf("rate limited")
	}
	if !invitePoWaD.allowBackoff(key, now) {
		return nil, fmt.Errorf("backoff active")
	}

	nonce := nextChallengeNonce()
	expiresAt := uint64(now.Add(inviteChallengeTTL()).Unix())
	inviteID := deriveInviteID(fromID, toID, msg.Scope, nonce, expiresAt)
	invitePoWaD.putChallenge(pendingPoWaDChallenge{
		FromID:         fromID,
		ToID:           toID,
		FromPub:        fromPub,
		Scope:          msg.Scope,
		ChallengeNonce: nonce,
		ExpiresAt:      expiresAt,
		PowBits:        proto.InvitePoWaDBits,
		InviteID:       inviteID,
	})
	invitePoWaD.clearBackoff(key)

	chal := proto.PoWaDChallengeMsg{
		FromNodeID:     hex.EncodeToString(self.ID[:]),
		ToNodeID:       msg.FromNodeID,
		Scope:          msg.Scope,
		ChallengeNonce: nonce,
		ExpiresAt:      expiresAt,
		PowBits:        proto.InvitePoWaDBits,
		InviteID:       hex.EncodeToString(inviteID),
	}
	return proto.EncodePoWaDChallengeMsg(chal)
}

func handlePoWaDSolution(self *node.Node, data []byte) ([]byte, error) {
	msg, err := proto.DecodePoWaDSolutionMsg(data)
	if err != nil {
		return nil, err
	}
	fromID, err := proto.DecodeNodeIDHex(msg.FromNodeID)
	if err != nil {
		return nil, fmt.Errorf("bad from_node_id")
	}
	toID, err := proto.DecodeNodeIDHex(msg.ToNodeID)
	if err != nil {
		return nil, fmt.Errorf("bad to_node_id")
	}
	if self == nil || toID != self.ID {
		return nil, fmt.Errorf("powad_solution to_id mismatch")
	}
	fromPub, err := hex.DecodeString(msg.FromPub)
	if err != nil || len(fromPub) == 0 || !crypto.IsRSAPublicKey(fromPub) {
		return nil, fmt.Errorf("bad from_pub")
	}
	if node.DeriveNodeID(fromPub) != fromID {
		return nil, fmt.Errorf("powad_solution from_id mismatch")
	}
	inviteID, err := hex.DecodeString(msg.InviteID)
	if err != nil || len(inviteID) != 32 {
		return nil, fmt.Errorf("bad invite_id")
	}
	fromHex := hex.EncodeToString(fromID[:])
	key := "powad_sol:" + fromHex
	now := time.Now()
	if !recvNodeLimiter.Allow(key) {
		return nil, fmt.Errorf("rate limited")
	}
	if !invitePoWaD.allowBackoff(key, now) {
		return nil, fmt.Errorf("backoff active")
	}
	chal, lookup := invitePoWaD.getChallenge(inviteID, now)
	if lookup != inviteChallengeFound {
		invitePoWaD.failBackoff(key, now)
		switch lookup {
		case inviteChallengeExpired:
			return nil, fmt.Errorf("challenge expired")
		default:
			return nil, fmt.Errorf("challenge missing")
		}
	}
	expectedInviteID := deriveInviteID(fromID, toID, msg.Scope, msg.ChallengeNonce, msg.ExpiresAt)
	if !bytes.Equal(expectedInviteID, inviteID) {
		invitePoWaD.failBackoff(key, now)
		return nil, fmt.Errorf("challenge key mismatch expected=%s got=%s", hex.EncodeToString(expectedInviteID), hex.EncodeToString(inviteID))
	}
	if chal.FromID != fromID || chal.ToID != toID || chal.Scope != msg.Scope ||
		chal.ChallengeNonce != msg.ChallengeNonce || chal.ExpiresAt != msg.ExpiresAt ||
		chal.PowBits != msg.PowBits || !bytes.Equal(chal.InviteID, inviteID) {
		invitePoWaD.failBackoff(key, now)
		return nil, fmt.Errorf("challenge bind mismatch")
	}
	if !crypto.PoWaDCheck(inviteID, fromID[:], msg.PowNonce, msg.PowBits) {
		invitePoWaD.failBackoff(key, now)
		return nil, fmt.Errorf("powad failed")
	}
	invitePoWaD.deleteChallenge(inviteID)
	invitePoWaD.clearBackoff(key)
	return issueInviteCert(self, fromPub, inviteID, msg.Scope, msg.PowBits, msg.PowNonce, now)
}
