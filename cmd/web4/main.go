// cmd/web4/main.go
package main

import (
	"bufio"
	"bytes"
	"container/list"
	"context"
	crand "crypto/rand"
	stdsha256 "crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	mrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"web4mvp/internal/crypto"
	"web4mvp/internal/daemon"
	"web4mvp/internal/math4"
	"web4mvp/internal/network"
	"web4mvp/internal/node"
	"web4mvp/internal/peer"
	"web4mvp/internal/proto"
	"web4mvp/internal/state"
	"web4mvp/internal/store"
	"web4mvp/internal/zk/linear"
	"web4mvp/internal/zk/pedersen"
)

func die(msg string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", msg, err)
	os.Exit(1)
}

func dieMsg(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}

func homeDir() string {
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".web4mvp")
}

func writeMsg(outPath string, data []byte) error {
	return os.WriteFile(outPath, data, 0600)
}

const (
	invalidMessage       = "invalid message"
	defaultPeerExchangeK = 16
	maxPeerExchangeK     = 64
	defaultGossipFanout  = 2
	maxGossipFanout      = 8
	defaultGossipHops    = 8
	gossipCacheCap       = 2048
	gossipCacheTTL       = 2 * time.Minute
)

func ensureKeypair(root string) error {
	_, _, err := crypto.LoadKeypair(root)
	if err == nil {
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	pub, priv, err := crypto.GenKeypair()
	if err != nil {
		return err
	}
	return crypto.SaveKeypair(root, pub, priv)
}

func maxSizeForType(t string) int {
	return proto.MaxSizeForType(t)
}

func enforceTypeMax(t string, n int) error {
	maxSize := maxSizeForType(t)
	if maxSize > 0 && n > maxSize {
		return fmt.Errorf("payload too large for type %s", t)
	}
	return nil
}

func findContractByID(st *store.Store, cid [32]byte) (*proto.Contract, error) {
	cs, err := st.ListContracts()
	if err != nil {
		return nil, err
	}
	for i := range cs {
		id := proto.ContractID(cs[i].IOU)
		if bytes.Equal(id[:], cid[:]) {
			return &cs[i], nil
		}
	}
	return nil, nil
}

func e2eSeal(_ string, _ [32]byte, _ uint64, _ []byte, payload []byte) ([]byte, []byte, error) {
	if len(payload) == 0 {
		return nil, nil, nil
	}
	return nil, payload, nil
}

func e2eOpen(_ string, _ [32]byte, _ uint64, _ []byte, _ []byte, sealed []byte) ([]byte, error) {
	if len(sealed) == 0 {
		return nil, nil
	}
	return sealed, nil
}

func sealSecureEnvelope(self *node.Node, peerID [32]byte, msgType string, channelID string, payload []byte) ([]byte, error) {
	if self == nil || self.Sessions == nil {
		return nil, fmt.Errorf("session unavailable")
	}
	st, ok := self.Sessions.Get(peerID)
	if !ok || st == nil {
		return nil, fmt.Errorf("missing session")
	}
	seq, err := st.NextSendSeq()
	if err != nil {
		return nil, err
	}

	nonce, err := crypto.NonceFromBase(st.NonceBaseSend, seq)
	if err != nil {
		return nil, err
	}
	aad := crypto.BuildAAD(msgType, seq, self.ID, peerID, channelID)
	sealed, err := crypto.XSealWithNonce(st.SendKey, nonce, payload, aad)
	if err != nil {
		return nil, err
	}
	env := proto.SecureEnvelope{
		Type:       proto.MsgTypeSecureEnvelope,
		MsgType:    msgType,
		FromNodeID: hex.EncodeToString(self.ID[:]),
		ToNodeID:   hex.EncodeToString(peerID[:]),
		ChannelID:  channelID,
		Seq:        seq,
		Sealed:     proto.EncodeSealedPayload(sealed),
	}
	return proto.EncodeSecureEnvelope(env)
}

func openSecureEnvelope(self *node.Node, env proto.SecureEnvelope) (string, []byte, [32]byte, error) {
	var zero [32]byte
	if self == nil || self.Sessions == nil {
		return "", nil, zero, fmt.Errorf("session unavailable")
	}
	fromID, err := proto.DecodeNodeIDHex(env.FromNodeID)
	if err != nil {
		return "", nil, zero, err
	}
	toID, err := proto.DecodeNodeIDHex(env.ToNodeID)
	if err != nil {
		return "", nil, zero, err
	}
	if toID != self.ID {
		return "", nil, zero, fmt.Errorf("to_id mismatch")
	}
	if env.MsgType == "" {
		return "", nil, zero, fmt.Errorf("missing msg_type")
	}
	st, ok := self.Sessions.Get(fromID)
	if !ok || st == nil {
		return "", nil, zero, fmt.Errorf("missing session")
	}
	if err := st.AcceptRecvSeq(env.Seq); err != nil {
		return "", nil, zero, err
	}

	nonce, err := crypto.NonceFromBase(st.NonceBaseRecv, env.Seq)
	if err != nil {
		return "", nil, zero, err
	}
	aad := crypto.BuildAAD(env.MsgType, env.Seq, fromID, toID, env.ChannelID)
	sealed, err := proto.DecodeSealedPayload(env.Sealed)
	if err != nil {
		return "", nil, zero, err
	}
	plain, err := crypto.XOpen(st.RecvKey, nonce, sealed, aad)
	if err != nil {
		return "", nil, zero, err
	}
	return env.MsgType, plain, fromID, nil
}

type exchangeFunc func(ctx context.Context, addr string, data []byte, insecure bool, devTLS bool, devTLSCAPath string) ([]byte, error)

func handshakeWithPeer(self *node.Node, peerID [32]byte, addr string, devTLS bool, devTLSCA string) error {
	return handshakeWithPeerWithExchange(self, peerID, addr, devTLS, devTLSCA, network.ExchangeOnceWithContext)
}

func handshakeWithPeerWithExchange(self *node.Node, peerID [32]byte, addr string, devTLS bool, devTLSCA string, exchange exchangeFunc) error {
	if self == nil {
		return fmt.Errorf("missing node")
	}
	if addr == "" {
		return fmt.Errorf("missing addr")
	}
	if exchange == nil {
		return fmt.Errorf("missing exchange")
	}
	const maxAttempts = 3
	backoff := 100 * time.Millisecond
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		hello1, err := self.BuildHello1(peerID)
		if err != nil {
			return err
		}
		data, err := proto.EncodeHello1Msg(hello1)
		if err != nil {
			return err
		}
		if err := enforceTypeMax(proto.MsgTypeHello1, len(data)); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		respData, err := exchange(ctx, addr, data, false, devTLS, devTLSCA)
		cancel()
		if err != nil {
			debugCount.incSend("handshake_exchange")
			lastErr = err
			if attempt < maxAttempts-1 {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			return err
		}
		respType := ""
		if len(respData) > 0 {
			var respHdr struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(respData, &respHdr); err == nil {
				respType = respHdr.Type
			}
		}
		if os.Getenv("WEB4_DEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "handshakeWithPeer got resp type=%s len=%d\n", respType, len(respData))
		}
		resp, err := proto.DecodeHello2Msg(respData)
		if err != nil {
			if os.Getenv("WEB4_DEBUG") == "1" {
				fmt.Fprintf(os.Stderr, "handshakeWithPeer decode hello2 failed: %v\n", err)
			}
			lastErr = err
			if attempt < maxAttempts-1 {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			return err
		}
		if err := self.HandleHello2(resp); err != nil {
			lastErr = err
			if attempt < maxAttempts-1 {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			return err
		}
		return nil
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("handshake failed")
}

type recvError struct {
	msg string
	err error
}

func (e recvError) Error() string {
	return fmt.Sprintf("%s: %v", e.msg, e.err)
}

func hello1SigInput(suiteID byte, fromID, toID [32]byte, ea, na, sessionID []byte) []byte {
	buf := make([]byte, 0, len("web4:h1:v3")+1+32+32+len(ea)+len(na)+len(sessionID))
	buf = append(buf, []byte("web4:h1:v3")...)
	buf = append(buf, suiteID)
	buf = append(buf, fromID[:]...)
	buf = append(buf, toID[:]...)
	buf = append(buf, ea...)
	buf = append(buf, na...)
	buf = append(buf, sessionID...)
	return buf
}

func hello1SigInputLegacy(suiteID byte, fromID, toID [32]byte, ea, na []byte) []byte {
	buf := make([]byte, 0, len("web4:h1:v2")+1+32+32+len(ea)+len(na))
	buf = append(buf, []byte("web4:h1:v2")...)
	buf = append(buf, suiteID)
	buf = append(buf, fromID[:]...)
	buf = append(buf, toID[:]...)
	buf = append(buf, ea...)
	buf = append(buf, na...)
	return buf
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

func zero32() []byte {
	return make([]byte, 32)
}

func hello1TranscriptBytes(suiteID byte, fromID, toID [32]byte, ea, na, mlkemPub []byte) []byte {
	base := proto.Hello1Bytes(fromID, toID, ea, na)
	out := make([]byte, 0, len(base)+1+len(mlkemPub))
	out = append(out, base...)
	out = append(out, suiteID)
	out = append(out, mlkemPub...)
	return out
}

func pqBindInput(nodeID [32]byte, pqPub []byte) []byte {
	buf := make([]byte, 0, len("WEB4/pqbind")+32+len(pqPub))
	buf = append(buf, []byte("WEB4/pqbind")...)
	buf = append(buf, nodeID[:]...)
	buf = append(buf, pqPub...)
	return buf
}

func decodeHexOptional(v string) ([]byte, error) {
	if strings.TrimSpace(v) == "" {
		return nil, nil
	}
	return hex.DecodeString(v)
}

func verifyHelloBySuite(suiteID byte, rsaPub, pqPub, input, sig []byte) bool {
	digest := crypto.SHA3_256(input)
	if suiteID == 0 {
		if len(pqPub) == 0 || len(sig) < 64 {
			return false
		}
		return crypto.SLHDSAVerify(pqPub, digest, sig)
	}
	return crypto.VerifyDigest(rsaPub, digest, sig)
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

func updateFromParties(a, b []byte, v uint64) (math4.Update, error) {
	if len(a) == 0 || len(b) == 0 {
		return math4.Update{}, fmt.Errorf("missing party id")
	}
	if v > math.MaxInt64 {
		return math4.Update{}, fmt.Errorf("delta too large")
	}
	A := partyIDFromBytes(a)
	B := partyIDFromBytes(b)
	return math4.Update{A: A, B: B, V: int64(v)}, nil
}

func partyIDFromBytes(b []byte) [32]byte {
	buf := make([]byte, 0, len("web4:party:v1:")+len(b))
	buf = append(buf, []byte("web4:party:v1:")...)
	buf = append(buf, b...)
	sum := crypto.SHA3_256(buf)
	var id [32]byte
	copy(id[:], sum)
	return id
}

func recvData(data []byte, st *store.Store, self *node.Node, checker math4.LocalChecker) error {
	_, _, err := recvDataWithResponse(data, st, self, checker, "")
	if err != nil {
		return err
	}
	return nil
}

func recvDataWithResponse(data []byte, st *store.Store, self *node.Node, checker math4.LocalChecker, senderAddr string) ([]byte, bool, *recvError) {
	debugRecv := func(format string, args ...any) {
		if os.Getenv("WEB4_DEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "recv: "+format+"\n", args...)
		}
	}
	reject := func(msg string, err error) *recvError {
		if os.Getenv("WEB4_DEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "recv reject: %s: %v\n", msg, err)
		}
		debugCount.incDrop(msg)
		return &recvError{msg: msg, err: err}
	}

	var hdr struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &hdr); err != nil {
		return nil, false, reject("decode message type failed", err)
	}
	debugRecv("recv top-level type=%s sender=%s", hdr.Type, senderAddr)
	if err := enforceTypeMax(hdr.Type, len(data)); err != nil {
		return nil, false, reject("message too large", err)
	}
	if self == nil {
		return nil, false, reject("node unavailable", fmt.Errorf("missing node"))
	}
	if senderAddr != "" {
		host := hostForAddr(senderAddr)
		if !recvHostLimiter.Allow(host) {
			return nil, false, reject("rate_limit_host", errors.New("rate limited"))
		}
	}
	wasSecure := false
	var secureFromID [32]byte
	if hdr.Type == proto.MsgTypeSecureEnvelope {
		env, err := proto.DecodeSecureEnvelope(data)
		if err != nil {
			return nil, false, reject("decode secure envelope failed", err)
		}
		fromID, err := proto.DecodeNodeIDHex(env.FromNodeID)
		if err != nil {
			return nil, false, reject("decode secure envelope failed", err)
		}
		toID, err := proto.DecodeNodeIDHex(env.ToNodeID)
		if err != nil {
			return nil, false, reject("decode secure envelope failed", err)
		}
		if toID != self.ID {
			return nil, false, reject("open secure envelope failed", fmt.Errorf("to_id mismatch"))
		}
		if self.Peers == nil {
			return nil, false, reject("node unavailable", fmt.Errorf("peer store unavailable"))
		}
		if senderAddr != "" {
			if mapped, ok := findPeerByAddr(self.Peers.List(), senderAddr); ok && mapped.NodeID != fromID {
				return nil, false, reject("addr conflict", fmt.Errorf("addr maps to different node_id"))
			}
		}
		if !hasPeerID(self.Peers.List(), fromID) {
			return nil, false, reject("unknown peer", fmt.Errorf("missing peer"))
		}
		if self.Sessions == nil || !self.Sessions.Has(fromID) {
			return nil, false, reject("unknown sender", fmt.Errorf("missing session"))
		}
		if !recvNodeLimiter.Allow(hex.EncodeToString(fromID[:])) {
			return nil, false, reject("rate_limit_node", errors.New("rate limited"))
		}
		msgType, plain, fromID, err := openSecureEnvelope(self, env)
		if err != nil {
			debugCount.incDecrypt("secure_envelope")
			return nil, false, reject("open secure envelope failed", err)
		}
		data = plain
		hdr.Type = msgType
		wasSecure = true
		secureFromID = fromID
		debugRecv("parsed type=%s secure=true sender=%s from_id=%x", hdr.Type, senderAddr, secureFromID[:])
		if err := enforceTypeMax(hdr.Type, len(data)); err != nil {
			return nil, false, reject("message too large", err)
		}
		debugCount.incRecv(hdr.Type)
		if senderAddr != "" && self.Peers != nil {
			if p, ok := findPeerByNodeID(self.Peers.List(), fromID); ok && len(p.PubKey) > 0 {
				if changed, err := self.Peers.ObserveAddr(peer.Peer{NodeID: fromID, PubKey: p.PubKey}, senderAddr, "", false, true); err != nil {
					return nil, false, reject("addr observe failed", err)
				} else if changed {
					debugCount.incAddrChange("observe")
				}
			}
		}
	}
	if !wasSecure && hdr.Type != proto.MsgTypeHello1 && hdr.Type != proto.MsgTypeHello2 && hdr.Type != proto.MsgTypeGossipPush {
		if hdr.Type != proto.MsgTypeInviteCert && hdr.Type != proto.MsgTypeInviteBundle && hdr.Type != proto.MsgTypeRevoke {
			return nil, false, reject("handshake required", fmt.Errorf("missing secure envelope"))
		}
	}
	if !wasSecure {
		debugCount.incRecv(hdr.Type)
	}

	if wasSecure {
		if scope, ok := requiredMemberScope(hdr.Type); ok {
			if self.Members == nil || !self.Members.HasScope(secureFromID, scope) {
				if os.Getenv("WEB4_DEBUG") == "1" {
					fmt.Fprintf(os.Stderr, "recv drop: membership_gate type=%s sender=%x scope=%d\n", hdr.Type, secureFromID[:], scope)
				}
				return nil, false, reject("membership_gate", fmt.Errorf("sender not member"))
			}
		}
	}

	switch hdr.Type {
	case proto.MsgTypeHello1:
		m, err := proto.DecodeHello1Msg(data)
		if err != nil {
			return nil, false, reject("decode hello1 failed", err)
		}
		fromID, toID, _, _, _, _, err := proto.DecodeHello1Fields(m)
		if err != nil {
			return nil, false, reject("decode hello1 failed", err)
		}
		if os.Getenv("WEB4_DEBUG") == "1" {
			via := "direct"
			if wasSecure || senderAddr == "" {
				via = "gossip"
			}
			fmt.Fprintf(os.Stderr, "hello1 recv from=%x to=%x via=%s\n", fromID[:], toID[:], via)
		}
		if fromID == self.ID {
			return nil, false, reject("invalid hello1", errors.New("hello1 from_id self"))
		}
		if toID != self.ID {
			return nil, false, reject("invalid hello1", errors.New("hello1 to_id mismatch"))
		}
		prevAddr := ""
		if senderAddr != "" {
			if existing, ok := findPeerByNodeID(self.Peers.List(), fromID); ok {
				prevAddr = existing.Addr
			}
		}
		resp, err := self.HandleHello1From(m, senderAddr)
		if err != nil {
			if strings.Contains(err.Error(), "signature") {
				debugCount.incVerify("hello1")
			}
			return nil, false, reject("invalid hello1", err)
		}
		if senderAddr != "" {
			if updated, ok := findPeerByNodeID(self.Peers.List(), fromID); ok && updated.Addr != "" && updated.Addr != prevAddr {
				debugCount.incAddrChange("hello1")
			}
		}
		if wasSecure || senderAddr == "" {
			return nil, false, nil
		}
		respData, err := proto.EncodeHello2Msg(resp)
		if err != nil {
			return nil, false, reject("encode hello2 failed", err)
		}
		return respData, false, nil

	case proto.MsgTypeHello2:
		m, err := proto.DecodeHello2Msg(data)
		if err != nil {
			return nil, false, reject("decode hello2 failed", err)
		}
		prevAddr := ""
		var fromID [32]byte
		if senderAddr != "" {
			if id, err := decodeNodeIDHex(m.FromNodeID); err == nil {
				fromID = id
				if existing, ok := findPeerByNodeID(self.Peers.List(), fromID); ok {
					prevAddr = existing.Addr
				}
			}
		}
		if err := self.HandleHello2From(m, senderAddr); err != nil {
			if strings.Contains(err.Error(), "signature") {
				debugCount.incVerify("hello2")
			}
			return nil, false, reject("invalid hello2", err)
		}
		if senderAddr != "" && !isZeroNodeID(fromID) {
			if updated, ok := findPeerByNodeID(self.Peers.List(), fromID); ok && updated.Addr != "" && updated.Addr != prevAddr {
				debugCount.incAddrChange("hello2")
			}
		}
		return nil, false, nil

	case proto.MsgTypeGossipPush:
		resp, newState, err := handleGossipPush(data, st, self, checker, senderAddr)
		if err != nil {
			return nil, false, reject(err.msg, err.err)
		}
		return resp, newState, nil

	case proto.MsgTypePeerExchangeReq:
		req, err := proto.DecodePeerExchangeReq(data)
		if err != nil {
			return nil, false, reject("decode peer exchange req failed", err)
		}
		resp, err := buildPeerExchangeResp(self, req.K)
		if err != nil {
			return nil, false, reject("peer exchange failed", err)
		}
		respData, err := proto.EncodePeerExchangeResp(resp)
		if err != nil {
			return nil, false, reject("encode peer exchange resp failed", err)
		}
		if err := enforceTypeMax(proto.MsgTypePeerExchangeResp, len(respData)); err != nil {
			return nil, false, reject("peer exchange resp too large", err)
		}
		if wasSecure {
			respData, err = sealSecureEnvelope(self, secureFromID, proto.MsgTypePeerExchangeResp, "", respData)
			if err != nil {
				return nil, false, reject("encode secure peer exchange resp failed", err)
			}
		}
		return respData, false, nil

	case proto.MsgTypePeerExchangeResp:
		resp, err := proto.DecodePeerExchangeResp(data)
		if err != nil {
			return nil, false, reject("decode peer exchange resp failed", err)
		}
		added, err := applyPeerExchangeResp(self, resp)
		if err != nil {
			return nil, false, reject("apply peer exchange resp failed", err)
		}
		fmt.Println("RECV PEER EXCHANGE", added)
		return nil, false, nil

	case proto.MsgTypeInviteCert:
		if inviteThreshold() > 1 {
			return nil, false, reject("invalid invite cert", fmt.Errorf("invite threshold requires invite bundle"))
		}
		msg, err := proto.DecodeInviteCertMsg(data)
		if err != nil {
			return nil, false, reject("decode invite cert failed", err)
		}
		cert, err := proto.InviteCertFromMsg(msg)
		if err != nil {
			return nil, false, reject("invalid invite cert", err)
		}
		if self.Invites == nil {
			return nil, false, reject("invite store unavailable", fmt.Errorf("missing invite store"))
		}
		if self.Members == nil {
			return nil, false, reject("member store unavailable", fmt.Errorf("missing member store"))
		}
		inviterID, inviteeID, err := validateInviteCert(cert, self.Invites, time.Now())
		if err != nil {
			if os.Getenv("WEB4_DEBUG") == "1" {
				fmt.Fprintf(os.Stderr, "recv drop: invite_cert err=%v\n", err)
			}
			return nil, false, reject("invalid invite cert", err)
		}
		if cert.Scope == 0 {
			return nil, false, reject("invalid invite cert", fmt.Errorf("missing scope"))
		}
		if self.Peers != nil {
			_ = self.Peers.Upsert(peer.Peer{NodeID: inviterID, PubKey: cert.InviterPub}, true)
			_ = self.Peers.Upsert(peer.Peer{NodeID: inviteeID, PubKey: cert.InviteePub}, true)
		}
		if err := self.Members.AddWithScope(inviterID, proto.InviteScopeAll, true); err != nil {
			return nil, false, reject("store member failed", err)
		}
		if err := self.Members.AddInvitedWithScope(inviteeID, cert.Scope, inviterID, true); err != nil {
			return nil, false, reject("store member failed", err)
		}
		if err := self.Invites.Mark(inviterID, cert.InviteID, cert.ExpiresAt, true); err != nil {
			return nil, false, reject("store invite failed", err)
		}
		fmt.Fprintf(os.Stderr, "RECV INVITE OK invitee=%x inviter=%x scope=%d\n", inviteeID[:], inviterID[:], cert.Scope)
		return nil, true, nil

	case proto.MsgTypeInviteBundle:
		msg, err := proto.DecodeInviteBundleMsg(data)
		if err != nil {
			return nil, false, reject("decode invite bundle failed", err)
		}
		if self.Invites == nil {
			return nil, false, reject("invite store unavailable", fmt.Errorf("missing invite store"))
		}
		if self.Members == nil {
			return nil, false, reject("member store unavailable", fmt.Errorf("missing member store"))
		}
		inviteID, err := proto.DecodeInviteIDHex(msg.InviteID)
		if err != nil {
			return nil, false, reject("invalid invite bundle", err)
		}
		inviteePub, err := hex.DecodeString(msg.InviteePub)
		if err != nil || !crypto.IsRSAPublicKey(inviteePub) {
			return nil, false, reject("invalid invite bundle", fmt.Errorf("bad invitee pubkey"))
		}
		inviteeID := node.DeriveNodeID(inviteePub)
		if msg.InviteeNodeID != "" {
			expected, err := decodeNodeIDHex(msg.InviteeNodeID)
			if err != nil {
				return nil, false, reject("invalid invite bundle", err)
			}
			if expected != inviteeID {
				return nil, false, reject("invalid invite bundle", fmt.Errorf("invitee node_id mismatch"))
			}
		}
		if msg.ExpiresAt == 0 {
			return nil, false, reject("invalid invite bundle", fmt.Errorf("missing expires_at"))
		}
		if msg.Scope == 0 {
			return nil, false, reject("invalid invite bundle", fmt.Errorf("missing scope"))
		}
		nowUnix := uint64(time.Now().Unix())
		if msg.ExpiresAt < nowUnix {
			return nil, false, reject("invalid invite bundle", fmt.Errorf("invite expired"))
		}
		if len(msg.Approvals) == 0 {
			return nil, false, reject("invalid invite bundle", fmt.Errorf("missing approvals"))
		}
		signBytes, err := proto.InviteApproveSignBytes(inviteID, inviteeID, msg.ExpiresAt, msg.Scope)
		if err != nil {
			return nil, false, reject("invalid invite bundle", err)
		}
		sigDigest := crypto.SHA3_256(signBytes)
		distinct := make(map[string]struct{}, len(msg.Approvals))
		approvals := 0
		var inviterID [32]byte
		inviterSet := false
		for _, approval := range msg.Approvals {
			approverID, err := decodeNodeIDHex(approval.ApproverNodeID)
			if err != nil {
				return nil, false, reject("invalid invite bundle", err)
			}
			key := hex.EncodeToString(approverID[:])
			if _, seen := distinct[key]; seen {
				continue
			}
			if !self.Members.HasScope(approverID, 0) {
				return nil, false, reject("invalid invite bundle", fmt.Errorf("approver not member"))
			}
			sig, err := decodeSigHex(approval.Sig)
			if err != nil || len(sig) == 0 {
				return nil, false, reject("invalid invite bundle", fmt.Errorf("bad approval signature"))
			}
			pub := []byte(nil)
			if approverID == self.ID {
				pub = self.PubKey
			} else if self.Peers != nil {
				if p, ok := findPeerByNodeID(self.Peers.List(), approverID); ok && len(p.PubKey) > 0 {
					pub = p.PubKey
				}
			}
			if len(pub) == 0 || !crypto.VerifyDigest(pub, sigDigest, sig) {
				return nil, false, reject("invalid invite bundle", fmt.Errorf("approval verify failed"))
			}
			distinct[key] = struct{}{}
			approvals++
			if !inviterSet {
				inviterID = approverID
				inviterSet = true
			}
		}
		threshold := inviteThreshold()
		if approvals < threshold {
			return nil, false, reject("invalid invite bundle", fmt.Errorf("insufficient approvals"))
		}
		if self.Invites.Seen(inviteeID, inviteID) {
			return nil, false, reject("invalid invite bundle", fmt.Errorf("invite replay"))
		}
		if self.Peers != nil {
			_ = self.Peers.Upsert(peer.Peer{NodeID: inviteeID, PubKey: inviteePub}, true)
		}
		if inviterSet {
			if err := self.Members.AddInvitedWithScope(inviteeID, msg.Scope, inviterID, true); err != nil {
				return nil, false, reject("store member failed", err)
			}
		} else {
			if err := self.Members.AddWithScope(inviteeID, msg.Scope, true); err != nil {
				return nil, false, reject("store member failed", err)
			}
		}
		if err := self.Invites.Mark(inviteeID, inviteID, msg.ExpiresAt, true); err != nil {
			return nil, false, reject("store invite failed", err)
		}
		fmt.Fprintf(os.Stderr, "RECV INVITE BUNDLE OK invitee=%x approvals=%d scope=%d\n", inviteeID[:], approvals, msg.Scope)
		return nil, true, nil

	case proto.MsgTypeRevoke:
		msg, err := proto.DecodeRevokeMsg(data)
		if err != nil {
			return nil, false, reject("decode revoke failed", err)
		}
		if self.Members == nil {
			return nil, false, reject("member store unavailable", fmt.Errorf("missing member store"))
		}
		if self.Revokes == nil {
			return nil, false, reject("revoke store unavailable", fmt.Errorf("missing revoke store"))
		}
		revokerID, err := decodeNodeIDHex(msg.RevokerNodeID)
		if err != nil {
			return nil, false, reject("invalid revoke", err)
		}
		targetID, err := decodeNodeIDHex(msg.TargetNodeID)
		if err != nil {
			return nil, false, reject("invalid revoke", err)
		}
		revokeID, err := proto.DecodeRevokeIDHex(msg.RevokeID)
		if err != nil {
			return nil, false, reject("invalid revoke", err)
		}
		sig, err := decodeSigHex(msg.Sig)
		if err != nil || len(sig) == 0 {
			return nil, false, reject("invalid revoke", fmt.Errorf("bad sig"))
		}
		if msg.IssuedAt == 0 {
			return nil, false, reject("invalid revoke", fmt.Errorf("missing issued_at"))
		}
		skew := 5 * time.Minute
		nowUnix := uint64(time.Now().Unix())
		if msg.IssuedAt > nowUnix+uint64(skew.Seconds()) {
			return nil, false, reject("invalid revoke", fmt.Errorf("issued_at in future"))
		}
		if !self.Members.HasScope(revokerID, 0) {
			if os.Getenv("WEB4_DEBUG") == "1" {
				fmt.Fprintf(os.Stderr, "recv drop: membership_gate type=%s sender=%x scope=0\n", hdr.Type, revokerID[:])
			}
			return nil, false, reject("membership_gate", fmt.Errorf("revoker not member"))
		}
		if inviterID, ok := self.Members.InviterFor(targetID); !ok || inviterID != revokerID {
			return nil, false, reject("invalid revoke", fmt.Errorf("revoker not inviter"))
		}
		pub := []byte(nil)
		if revokerID == self.ID {
			pub = self.PubKey
		} else if self.Peers != nil {
			if p, ok := findPeerByNodeID(self.Peers.List(), revokerID); ok && len(p.PubKey) > 0 {
				pub = p.PubKey
			}
		}
		if len(pub) == 0 {
			return nil, false, reject("invalid revoke", fmt.Errorf("revoker pubkey missing"))
		}
		signBytes, err := proto.RevokeSignBytes(revokerID, targetID, revokeID, msg.IssuedAt, msg.Reason)
		if err != nil {
			return nil, false, reject("invalid revoke", err)
		}
		if !crypto.VerifyDigest(pub, crypto.SHA3_256(signBytes), sig) {
			debugCount.incVerify("revoke")
			return nil, false, reject("invalid revoke", fmt.Errorf("signature check failed"))
		}
		if self.Revokes.Seen(revokerID, revokeID) {
			return nil, false, reject("invalid revoke", fmt.Errorf("revoke replay"))
		}
		if err := self.Members.SetScope(targetID, 0, true); err != nil {
			return nil, false, reject("store member failed", err)
		}
		if err := self.Revokes.Mark(revokerID, revokeID, targetID, msg.IssuedAt, true); err != nil {
			return nil, false, reject("store revoke failed", err)
		}
		fmt.Fprintf(os.Stderr, "RECV REVOKE OK target=%x revoker=%x reason=%s\n", targetID[:], revokerID[:], msg.Reason)
		return nil, true, nil

	case proto.MsgTypeContractOpen:
		m, err := proto.DecodeContractOpenMsg(data)
		if err != nil {
			return nil, false, reject("decode contract open failed", err)
		}
		if err := proto.ValidateWireMeta(m.ProtoVersion, m.Suite); err != nil {
			return nil, false, reject("invalid wire metadata", err)
		}
		c, err := proto.ContractFromOpenMsg(m)
		if err != nil {
			return nil, false, reject("invalid contract open", err)
		}
		id := proto.ContractID(c.IOU)
		if !crypto.Verify(c.IOU.Debtor, crypto.SHA3_256(proto.OpenSignBytes(c.IOU, c.EphemeralPub, c.Sealed)), c.SigDebt) {
			debugCount.incVerify("contract_open")
			return nil, false, reject("invalid sigb", fmt.Errorf("debtor signature check failed"))
		}
		plain, err := e2eOpen(proto.MsgTypeContractOpen, id, 0, self.PrivKey, c.EphemeralPub, c.Sealed)
		if err != nil {
			return nil, false, reject("sealed open failed", err)
		}
		var p proto.OpenPayload
		if err := json.Unmarshal(plain, &p); err != nil {
			return nil, false, reject("decode open payload failed", err)
		}
		if p.Type != proto.MsgTypeContractOpen ||
			!strings.EqualFold(p.Creditor, m.Creditor) ||
			!strings.EqualFold(p.Debtor, m.Debtor) ||
			p.Amount != m.Amount ||
			p.Nonce != m.Nonce {
			return nil, false, reject("open payload mismatch", fmt.Errorf("payload/header mismatch"))
		}
		if zkMode() {
			ctx, err := openPayloadContext(p)
			if err != nil {
				return nil, false, reject("invalid zk context", err)
			}
			if err := verifyDeltaProof(c.IOU.Amount, ctx, p.ZK); err != nil {
				if os.Getenv("WEB4_DEBUG") == "1" {
					fmt.Fprintf(os.Stderr, "recv drop: zk invalid (open) err=%v\n", err)
				}
				return nil, false, reject("invalid zk proof", err)
			}
		}
		if existing, _ := findContractByID(st, id); existing != nil {
			if existing.Status == "CLOSED" {
				return nil, false, reject("contract already closed", fmt.Errorf("cannot reopen closed contract"))
			}
			fmt.Println("RECV OPEN duplicate", hex.EncodeToString(id[:]))
			return nil, false, nil
		}
		update, err := updateFromParties(c.IOU.Debtor, c.IOU.Creditor, c.IOU.Amount)
		if err != nil {
			return nil, false, reject("invalid update", err)
		}
		if err := checker.Check(update); err != nil {
			return nil, false, reject("local constraint rejected", err)
		}
		if err := st.AddContract(c); err != nil {
			return nil, false, reject("store contract failed", err)
		}
		fmt.Println("RECV OPEN", hex.EncodeToString(id[:]))
		return nil, true, nil

	case proto.MsgTypeRepayReq:
		m, err := proto.DecodeRepayReqMsg(data)
		if err != nil {
			return nil, false, reject("decode repay request failed", err)
		}
		if err := proto.ValidateWireMeta(m.ProtoVersion, m.Suite); err != nil {
			return nil, false, reject("invalid wire metadata", err)
		}
		req, sigB, err := proto.RepayReqFromMsg(m)
		if err != nil {
			return nil, false, reject("invalid repay request", err)
		}
		cidBytes, err := hex.DecodeString(m.ContractID)
		if err != nil || len(cidBytes) != 32 {
			return nil, false, reject("invalid contract id", fmt.Errorf("bad contract_id"))
		}
		var cid [32]byte
		copy(cid[:], cidBytes)
		c, err := findContractByID(st, cid)
		if err != nil {
			return nil, false, reject("contract lookup failed", err)
		}
		if c == nil {
			return nil, false, reject("unknown contract", fmt.Errorf("missing contract for repay request"))
		}
		if c.Status == "CLOSED" {
			return nil, false, reject("contract already closed", fmt.Errorf("reject repay request"))
		}
		ephPub, sealed, err := proto.DecodeSealedFields(m.EphemeralPub, m.Sealed)
		if err != nil {
			return nil, false, reject("invalid repay request fields", err)
		}
		reqSign := proto.RepayReqSignBytes(req, ephPub, sealed)
		if !crypto.Verify(c.IOU.Debtor, crypto.SHA3_256(reqSign), sigB) {
			debugCount.incVerify("repay_req")
			return nil, false, reject("invalid sigb", fmt.Errorf("debtor signature check failed"))
		}
		plain, err := e2eOpen(proto.MsgTypeRepayReq, cid, req.ReqNonce, self.PrivKey, ephPub, sealed)
		if err != nil {
			return nil, false, reject("sealed repay request failed", err)
		}
		var p proto.RepayPayload
		if err := json.Unmarshal(plain, &p); err != nil {
			return nil, false, reject("decode repay payload failed", err)
		}
		if p.Type != proto.MsgTypeRepayReq ||
			!strings.EqualFold(p.ContractID, m.ContractID) ||
			p.ReqNonce != m.ReqNonce ||
			p.Close != m.Close {
			return nil, false, reject("repay payload mismatch", fmt.Errorf("payload/header mismatch"))
		}
		if exists, err := st.HasRepayReq(m.ContractID, m.ReqNonce); err == nil && exists {
			fmt.Println("RECV REPAY-REQ duplicate", m.ContractID)
			return nil, false, nil
		}
		if maxNonce, ok, err := st.MaxRepayReqNonce(m.ContractID); err != nil {
			return nil, false, reject("repay request scan failed", err)
		} else if ok && req.ReqNonce <= maxNonce {
			return nil, false, reject("repay req nonce out of order", fmt.Errorf("non-monotonic reqnonce"))
		}
		if err := st.AddRepayReqIfNew(m); err != nil {
			return nil, false, reject("store repay request failed", err)
		}
		fmt.Println("RECV REPAY-REQ", m.ContractID)
		return nil, true, nil

	case proto.MsgTypeAck:
		m, err := proto.DecodeAckMsg(data)
		if err != nil {
			return nil, false, reject("decode ack failed", err)
		}
		if err := proto.ValidateWireMeta(m.ProtoVersion, m.Suite); err != nil {
			return nil, false, reject("invalid wire metadata", err)
		}
		a, sigA, err := proto.AckFromMsg(m)
		if err != nil {
			return nil, false, reject("invalid ack", err)
		}
		c, err := findContractByID(st, a.ContractID)
		if err != nil {
			return nil, false, reject("contract lookup failed", err)
		}
		if c == nil {
			return nil, false, reject("unknown contract", fmt.Errorf("missing contract for ack"))
		}
		if c.Status == "CLOSED" {
			return nil, false, reject("contract already closed", fmt.Errorf("reject ack"))
		}
		maxNonce, ok, err := st.MaxRepayReqNonce(m.ContractID)
		if err != nil {
			return nil, false, reject("repay req scan failed", err)
		}
		if !ok {
			return nil, false, reject("missing repay request", fmt.Errorf("ack without repay request"))
		}
		reqMsg, err := st.FindRepayReq(m.ContractID, maxNonce)
		if err != nil {
			return nil, false, reject("repay req lookup failed", err)
		}
		if reqMsg == nil {
			return nil, false, reject("missing repay request", fmt.Errorf("ack without repay request"))
		}
		ackSign := proto.AckSignBytes(a.ContractID, a.Decision, a.Close, a.EphemeralPub, a.Sealed)
		if !crypto.Verify(c.IOU.Creditor, crypto.SHA3_256(ackSign), sigA) {
			debugCount.incVerify("repay_ack")
			return nil, false, reject("invalid siga", fmt.Errorf("creditor signature check failed"))
		}
		if reqMsg.Close != a.Close {
			return nil, false, reject("ack close mismatch", fmt.Errorf("close flag mismatch"))
		}
		plain, err := e2eOpen(proto.MsgTypeAck, a.ContractID, maxNonce, self.PrivKey, a.EphemeralPub, a.Sealed)
		if err != nil {
			return nil, false, reject("sealed ack failed", err)
		}
		var p proto.AckPayload
		if err := json.Unmarshal(plain, &p); err != nil {
			return nil, false, reject("decode ack payload failed", err)
		}
		if p.Type != proto.MsgTypeAck ||
			!strings.EqualFold(p.ContractID, m.ContractID) ||
			p.Decision != m.Decision ||
			p.Close != m.Close {
			return nil, false, reject("ack payload mismatch", fmt.Errorf("payload/header mismatch"))
		}
		if zkMode() && p.Decision == 1 {
			ctx, err := ackPayloadContext(p)
			if err != nil {
				return nil, false, reject("invalid zk context", err)
			}
			if err := verifyDeltaProof(c.IOU.Amount, ctx, p.ZK); err != nil {
				if os.Getenv("WEB4_DEBUG") == "1" {
					fmt.Fprintf(os.Stderr, "recv drop: zk invalid (ack) err=%v\n", err)
				}
				return nil, false, reject("invalid zk proof", err)
			}
		}
		a.ReqNonce = maxNonce
		if exists, err := st.HasAck(m.ContractID, maxNonce); err == nil && exists {
			fmt.Println("RECV ACK duplicate", m.ContractID)
			return nil, false, nil
		}
		if a.Decision == 1 {
			update, err := updateFromParties(c.IOU.Creditor, c.IOU.Debtor, c.IOU.Amount)
			if err != nil {
				return nil, false, reject("invalid update", err)
			}
			if err := checker.Check(update); err != nil {
				return nil, false, reject("local constraint rejected", err)
			}
		}
		if err := st.AddAckIfNew(a, sigA); err != nil {
			return nil, false, reject("store ack failed", err)
		}
		if a.Decision == 1 {
			if err := st.MarkClosed(a.ContractID, false); err != nil {
				return nil, false, reject("mark closed failed", err)
			}
		}
		fmt.Println("RECV ACK", m.ContractID)
		return nil, true, nil

	case proto.MsgTypeDeltaB:
		if deltaMode() != "deltab" {
			return nil, false, reject("delta_b disabled", fmt.Errorf("delta mode not enabled"))
		}
		m, err := proto.DecodeDeltaBMsg(data)
		if err != nil {
			return nil, false, reject("decode delta_b failed", err)
		}
		if err := proto.ValidateWireMeta(m.ProtoVersion, m.Suite); err != nil {
			return nil, false, reject("invalid wire metadata", err)
		}
		canonMsg, _, deltaID, err := canonicalDeltaB(m)
		if err != nil {
			return nil, false, reject("invalid delta_b", err)
		}
		canonMsgZK := canonMsg
		canonMsgZK.ZK = m.ZK
		if deltabSeen.Seen(deltaID) {
			if os.Getenv("WEB4_DEBUG") == "1" {
				fmt.Fprintf(os.Stderr, "drop deltab duplicate id=%x\n", deltaID[:])
			}
			return nil, false, reject("duplicate delta_b", fmt.Errorf("duplicate delta_id"))
		}
		deltas, members, viewID, scopeHash, err := verifyDeltaBBasic(canonMsg, self)
		if err != nil {
			if os.Getenv("WEB4_DEBUG") == "1" {
				fmt.Fprintf(os.Stderr, "recv drop: delta_b invalid err=%v\n", err)
				if strings.Contains(err.Error(), "node_id not member") {
					fmt.Fprintf(os.Stderr, "recv drop: delta_b non_member\n")
				}
				if strings.Contains(err.Error(), "view_id mismatch") {
					fmt.Fprintf(os.Stderr, "recv drop: delta_b view_mismatch\n")
				}
			}
			return nil, false, reject("invalid delta_b", err)
		}
		scopeHex := hex.EncodeToString(scopeHash[:])
		senderKey := ""
		if wasSecure {
			senderKey = hex.EncodeToString(secureFromID[:])
		} else if senderAddr != "" {
			senderKey = senderAddr
		}
		rateKey := senderKey + ":" + scopeHex
		if !deltabLimiter.Allow(rateKey) {
			if os.Getenv("WEB4_DEBUG") == "1" {
				fmt.Fprintf(os.Stderr, "drop deltab rate_limited key=%s\n", rateKey)
			}
			return nil, false, reject("rate_limited", fmt.Errorf("delta_b rate limited"))
		}
		if zkMode() {
			if err := verifyDeltaBZK(canonMsgZK, viewID); err != nil {
				if os.Getenv("WEB4_DEBUG") == "1" {
					fmt.Fprintf(os.Stderr, "recv drop: delta_b zk invalid err=%v\n", err)
				}
				return nil, false, reject("invalid delta_b zk", err)
			}
		}
		if self.Field == nil {
			self.Field = state.NewField()
		}
		if err := self.Field.ApplyDelta(members, deltas, deltaRelaxIters()); err != nil {
			return nil, false, reject("apply delta_b failed", err)
		}
		deltabSeen.Add(deltaID)
		if os.Getenv("WEB4_DEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "RECV DELTA_B entries=%d\n", len(m.Entries))
		}
		return nil, true, nil

	default:
		return nil, false, reject("unknown message type", fmt.Errorf("%s", hdr.Type))
	}
}

var gossipSeen = newGossipCache(gossipCacheCap, gossipCacheTTL)
var gossipRand = mrand.New(mrand.NewSource(time.Now().UnixNano()))
var gossipRandMu sync.Mutex
var sendFunc = network.Send
var exchangeFn = network.ExchangeWithContext

const (
	deltabCacheCap = 4096
	deltabCacheTTL = 10 * time.Minute
)

var deltabSeen = newDeltabCache(deltabCacheCap, deltabCacheTTL)
var deltabLimiter = newDeltabRateLimiter(10, 20, 10*time.Minute)

func gossipDebugf(format string, args ...any) {
	if os.Getenv("WEB4_DEBUG") == "1" {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}
}

func nodeIDHexFromPub(pub []byte) string {
	if len(pub) == 0 {
		return ""
	}
	id := node.DeriveNodeID(pub)
	return hex.EncodeToString(id[:])
}

func hashHex(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	sum := crypto.SHA3_256(data)
	return hex.EncodeToString(sum[:])
}

func sha256Hex(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	sum := stdsha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

func msgIDFor(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	sum := stdsha256.Sum256(data)
	return hex.EncodeToString(sum[:])[:12]
}

func check6Enabled() bool {
	return os.Getenv("WEB4_CHECK6_DEBUG") == "1"
}

func check6Phase(format string, args ...any) {
	if !check6Enabled() {
		return
	}
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func check6Drop(msgID string, reason string, details string) {
	if !check6Enabled() {
		return
	}
	if details == "" {
		details = "-"
	}
	fmt.Fprintf(os.Stderr, "DROP msg_id=%s reason=%s details=%s\n", msgID, reason, details)
}

func isZeroNodeID(id [32]byte) bool {
	var zero [32]byte
	return id == zero
}

type gossipCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	cap     int
	order   *list.List
	entries map[[32]byte]*list.Element
}

type deltabCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	cap     int
	order   *list.List
	entries map[[32]byte]*list.Element
}

type deltabEntry struct {
	hash    [32]byte
	expires time.Time
}

func newDeltabCache(capacity int, ttl time.Duration) *deltabCache {
	if capacity <= 0 {
		capacity = deltabCacheCap
	}
	if ttl <= 0 {
		ttl = deltabCacheTTL
	}
	if v, ok := envInt("WEB4_DELTA_CACHE_CAP"); ok && v > 0 {
		capacity = v
	}
	if v, ok := envInt("WEB4_DELTA_CACHE_TTL_SEC"); ok && v > 0 {
		ttl = time.Duration(v) * time.Second
	}
	return &deltabCache{
		ttl:     ttl,
		cap:     capacity,
		order:   list.New(),
		entries: make(map[[32]byte]*list.Element),
	}
}

func (c *deltabCache) Seen(hash [32]byte) bool {
	now := time.Now()
	c.mu.Lock()
	c.pruneLocked(now)
	if el, ok := c.entries[hash]; ok {
		ent := el.Value.(*deltabEntry)
		if ent.expires.After(now) {
			c.order.MoveToFront(el)
			c.mu.Unlock()
			return true
		}
		delete(c.entries, hash)
		c.order.Remove(el)
	}
	c.mu.Unlock()
	return false
}

func (c *deltabCache) Add(hash [32]byte) {
	now := time.Now()
	c.mu.Lock()
	c.pruneLocked(now)
	if el, ok := c.entries[hash]; ok {
		ent := el.Value.(*deltabEntry)
		ent.expires = now.Add(c.ttl)
		c.order.MoveToFront(el)
		c.mu.Unlock()
		return
	}
	ent := &deltabEntry{hash: hash, expires: now.Add(c.ttl)}
	el := c.order.PushFront(ent)
	c.entries[hash] = el
	for c.cap > 0 && len(c.entries) > c.cap {
		back := c.order.Back()
		if back == nil {
			break
		}
		old := back.Value.(*deltabEntry)
		delete(c.entries, old.hash)
		c.order.Remove(back)
	}
	c.mu.Unlock()
}

func (c *deltabCache) pruneLocked(now time.Time) {
	for el := c.order.Back(); el != nil; {
		prev := el.Prev()
		ent := el.Value.(*deltabEntry)
		if ent.expires.After(now) {
			el = prev
			continue
		}
		delete(c.entries, ent.hash)
		c.order.Remove(el)
		el = prev
	}
}

type deltabRateLimiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	ttl     time.Duration
	entries map[string]*rateEntry
}

type rateEntry struct {
	tokens float64
	last   time.Time
}

func newDeltabRateLimiter(rate float64, burst float64, ttl time.Duration) *deltabRateLimiter {
	if v, ok := envInt("WEB4_DELTA_RATE"); ok && v >= 0 {
		rate = float64(v)
	}
	if v, ok := envInt("WEB4_DELTA_BURST"); ok && v >= 0 {
		burst = float64(v)
	}
	if v, ok := envInt("WEB4_DELTA_RATE_TTL_SEC"); ok && v > 0 {
		ttl = time.Duration(v) * time.Second
	}
	return &deltabRateLimiter{
		rate:    rate,
		burst:   burst,
		ttl:     ttl,
		entries: make(map[string]*rateEntry),
	}
}

func (l *deltabRateLimiter) Allow(key string) bool {
	if key == "" || l.rate <= 0 || l.burst <= 0 {
		return true
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if ent, ok := l.entries[key]; ok {
		if now.Sub(ent.last) > l.ttl {
			delete(l.entries, key)
		}
	}
	ent := l.entries[key]
	if ent == nil {
		ent = &rateEntry{tokens: l.burst, last: now}
		l.entries[key] = ent
	}
	elapsed := now.Sub(ent.last).Seconds()
	if elapsed > 0 {
		ent.tokens += elapsed * l.rate
		if ent.tokens > l.burst {
			ent.tokens = l.burst
		}
		ent.last = now
	}
	if ent.tokens < 1 {
		return false
	}
	ent.tokens -= 1
	return true
}

type gossipEntry struct {
	hash    [32]byte
	expires time.Time
}

func newGossipCache(capacity int, ttl time.Duration) *gossipCache {
	if capacity <= 0 {
		capacity = gossipCacheCap
	}
	if ttl <= 0 {
		ttl = gossipCacheTTL
	}
	return &gossipCache{
		ttl:     ttl,
		cap:     capacity,
		order:   list.New(),
		entries: make(map[[32]byte]*list.Element),
	}
}

func (c *gossipCache) Seen(hash [32]byte) bool {
	now := time.Now()
	c.mu.Lock()
	c.pruneLocked(now)
	if el, ok := c.entries[hash]; ok {
		ent := el.Value.(*gossipEntry)
		if ent.expires.After(now) {
			c.order.MoveToFront(el)
			c.mu.Unlock()
			return true
		}
		delete(c.entries, hash)
		c.order.Remove(el)
	}
	c.mu.Unlock()
	return false
}

func (c *gossipCache) Add(hash [32]byte) {
	now := time.Now()
	c.mu.Lock()
	c.pruneLocked(now)
	if el, ok := c.entries[hash]; ok {
		ent := el.Value.(*gossipEntry)
		ent.expires = now.Add(c.ttl)
		c.order.MoveToFront(el)
		c.mu.Unlock()
		return
	}
	ent := &gossipEntry{hash: hash, expires: now.Add(c.ttl)}
	el := c.order.PushFront(ent)
	c.entries[hash] = el
	for c.cap > 0 && len(c.entries) > c.cap {
		back := c.order.Back()
		if back == nil {
			break
		}
		old := back.Value.(*gossipEntry)
		delete(c.entries, old.hash)
		c.order.Remove(back)
	}
	c.mu.Unlock()
}

func (c *gossipCache) pruneLocked(now time.Time) {
	for el := c.order.Back(); el != nil; {
		prev := el.Prev()
		ent := el.Value.(*gossipEntry)
		if ent.expires.After(now) {
			el = prev
			continue
		}
		delete(c.entries, ent.hash)
		c.order.Remove(el)
		el = prev
	}
}

func handleGossipPush(data []byte, st *store.Store, self *node.Node, checker math4.LocalChecker, senderAddr string) ([]byte, bool, *recvError) {
	msgID := msgIDFor(data)
	check6Phase("PHASE recv_push msg_id=%s", msgID)
	drop := func(reason string, t string, err error) {
		msg := ""
		if err != nil {
			msg = err.Error()
		}
		fmt.Fprintf(os.Stderr, "DROP reason=%s from=%s type=%s err=%s\n", reason, senderAddr, t, msg)
	}
	msg, err := proto.DecodeGossipPushMsg(data)
	if err != nil {
		drop("decode_gossip_push", "gossip_push", err)
		check6Drop(msgID, "bad_json", err.Error())
		return nil, false, &recvError{msg: "decode gossip push failed", err: err}
	}
	ackResp := []byte(nil)
	ackSHA := ""
	if os.Getenv("WEB4_CHECK6_ACK") == "1" {
		ackSHA = sha256Hex(data)
		ack := proto.GossipAckMsg{Sha256: ackSHA}
		if self != nil {
			ack.FromNodeID = hex.EncodeToString(self.ID[:])
		}
		if encoded, err := proto.EncodeGossipAckMsg(ack); err == nil {
			ackResp = encoded
		} else {
			fmt.Fprintf(os.Stderr, "gossip_ack encode failed: %v\n", err)
		}
	}
	if check6Enabled() {
		check6Phase("PARSE_OK msg_id=%s type=%s", msgID, msg.Type)
		if ackResp != nil {
			fmt.Fprintf(os.Stderr, "ACK_SENT msg_id=%s sha256=%s\n", msgID, ackSHA)
		}
		go func() {
			_, _ = handleGossipPushInner(msg, data, st, self, checker, senderAddr, msgID, drop)
		}()
		return ackResp, false, nil
	}
	newState, recvErr := handleGossipPushInner(msg, data, st, self, checker, senderAddr, msgID, drop)
	if recvErr != nil {
		return nil, false, recvErr
	}
	if ackResp != nil {
		fmt.Fprintf(os.Stderr, "ACK_SENT msg_id=%s sha256=%s\n", msgID, ackSHA)
	}
	return ackResp, newState, nil
}

func handleGossipPushInner(msg proto.GossipPushMsg, data []byte, st *store.Store, self *node.Node, checker math4.LocalChecker, senderAddr string, msgID string, drop func(string, string, error)) (bool, *recvError) {
	gossipDebugf("gossip_push start incoming_type=%s inner_type=? forward_addr=? outbound_type=? addr=%s from_node_id=%s hops=%d", msg.Type, senderAddr, msg.FromNodeID, msg.Hops)
	if self == nil || self.Peers == nil {
		drop("peer_store_unavailable", msg.Type, fmt.Errorf("peer store unavailable"))
		check6Drop(msgID, "no_members", "peer store unavailable")
		return false, &recvError{msg: "node unavailable", err: fmt.Errorf("peer store unavailable")}
	}
	if err := self.Peers.Refresh(); err != nil {
		gossipDebugf("gossip_push peer refresh failed: %v", err)
	}
	if self.Members != nil {
		if err := self.Members.Refresh(); err != nil {
			gossipDebugf("gossip_push member refresh failed: %v", err)
		}
	}
	fromID, err := decodeNodeIDHex(msg.FromNodeID)
	if err != nil {
		gossipDebugf("drop gossip_push: bad from_node_id=%s", msg.FromNodeID)
		drop("bad_from_node_id", msg.Type, err)
		check6Drop(msgID, "bad_json", err.Error())
		return false, nil
	}
	forwarder, ok := findPeerByNodeID(self.Peers.List(), fromID)
	if !ok || len(forwarder.PubKey) == 0 {
		gossipDebugf("drop gossip_push: unknown forwarder node_id=%x addr=%s", fromID[:], senderAddr)
		drop("unknown_forwarder", msg.Type, fmt.Errorf("forwarder missing"))
		check6Drop(msgID, "no_members", "unknown forwarder")
		return false, nil
	}
	gossipDebugf("gossip_push forwarder node_id=%x addr=%s", fromID[:], senderAddr)
	gossipDebugf("gossip_push recv msg.from_node_id=%x sender_pub_node_id=%s sender_pub_hash=%s", fromID[:], nodeIDHexFromPub(forwarder.PubKey), nodeIDHexFromPub(forwarder.PubKey))
	if self.Members == nil || !self.Members.HasScope(fromID, proto.InviteScopeGossip) {
		gossipDebugf("drop gossip_push: forwarder not member node_id=%x", fromID[:])
		drop("membership_gate", msg.Type, fmt.Errorf("forwarder not member"))
		check6Drop(msgID, "no_members", "forwarder not member")
		return false, nil
	}
	gossipDebugf("gossip_push forwarder ok node_id=%x", fromID[:])
	sig, err := decodeSigHex(msg.SigFrom)
	if err != nil {
		gossipDebugf("drop gossip_push: bad sig_from")
		drop("bad_sig_from", msg.Type, err)
		check6Drop(msgID, "bad_sig", err.Error())
		return false, nil
	}
	payloadMsg := msg
	payloadMsg.SigFrom = ""
	payload, err := proto.EncodeGossipPushMsg(payloadMsg)
	if err != nil {
		check6Drop(msgID, "bad_json", err.Error())
		return false, &recvError{msg: "encode gossip push failed", err: err}
	}
	version := payloadMsg.ProtoVersion
	if version == "" {
		version = proto.ProtoVersion
	}
	suite := payloadMsg.Suite
	if suite == "" {
		suite = proto.Suite
	}
	mt := payloadMsg.Type
	if mt == "" {
		mt = proto.MsgTypeGossipPush
	}
	if !verifySigFrom(version, suite, mt, fromID, payload, sig, forwarder.PubKey) {
		debugCount.incVerify("gossip_push")
		gossipDebugf("drop gossip_push: sig verify failed node_id=%x", fromID[:])
		drop("sig_verify_failed", msg.Type, fmt.Errorf("sig verify failed"))
		check6Drop(msgID, "bad_sig", "sig verify failed")
		return false, nil
	}
	gossipDebugf("gossip_push sig verify ok node_id=%x", fromID[:])
	ephPub, sealed, err := proto.DecodeSealedFields(msg.EphemeralPub, msg.Sealed)
	if err != nil {
		gossipDebugf("drop gossip_push: bad sealed fields err=%v", err)
		check6Drop(msgID, "bad_json", err.Error())
		return false, &recvError{msg: "decode gossip envelope failed", err: err}
	}
	selfPubNodeID := nodeIDHexFromPub(self.PubKey)
	gossipDebugf("gossip_push self_node_id=%x self_pub_node_id=%s self_pub_hash=%s", self.ID[:], selfPubNodeID, hashHex(self.PubKey))
	gossipDebugf("gossip_push open using msg.from_node_id=%x sender_pub_node_id=%s sender_pub_hash=%s", fromID[:], nodeIDHexFromPub(forwarder.PubKey), hashHex(forwarder.PubKey))
	var zero [32]byte
	envelope, err := e2eOpen(proto.MsgTypeGossipPush, zero, 0, self.PrivKey, ephPub, sealed)
	if err != nil {
		debugCount.incDecrypt("gossip_push")
		gossipDebugf("gossip_push open failed msg.from_node_id=%x sender_pub_node_id=%s sender_pub_hash=%s", fromID[:], nodeIDHexFromPub(forwarder.PubKey), hashHex(forwarder.PubKey))
		gossipDebugf("drop gossip_push: envelope open failed err=%v", err)
		drop("open_failed", msg.Type, err)
		check6Drop(msgID, "bad_json", err.Error())
		return false, &recvError{msg: "decode gossip envelope failed", err: err}
	}
	var hdr struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(envelope, &hdr)
	check6Phase("PHASE parse_inner msg_id=%s inner_type=%s", msgID, hdr.Type)
	if os.Getenv("WEB4_DEBUG") == "1" {
		gossipDebugf("gossip_push opened payload_len=%d type=%s", len(envelope), hdr.Type)
	}
	var hash [32]byte
	hashInput := make([]byte, 0, len(envelope)+len(self.ID))
	hashInput = append(hashInput, envelope...)
	hashInput = append(hashInput, self.ID[:]...)
	copy(hash[:], crypto.SHA3_256(hashInput))
	if gossipSeen.Seen(hash) {
		gossipDebugf("drop gossip_push: already seen hash=%x", hash[:])
		drop("already_seen", msg.Type, fmt.Errorf("already seen"))
		check6Drop(msgID, "no_members", "already seen")
		return false, nil
	}
	gossipDebugf("gossip_push new hash=%x", hash[:])
	var newState bool
	var innerErr error
	if hdr.Type == proto.MsgTypeHello1 {
		newState, innerErr = handleGossipHello1Payload(envelope, self, senderAddr, fromID)
	} else {
		_, newState, innerErr = recvDataWithResponse(envelope, st, self, checker, "")
	}
	if innerErr != nil {
		gossipDebugf("drop gossip_push: payload recv failed err=%v", innerErr)
		drop("payload_recv_failed", hdr.Type, innerErr)
		check6Drop(msgID, "bad_json", innerErr.Error())
		return false, &recvError{msg: "gossip payload failed", err: innerErr}
	}
	gossipSeen.Add(hash)
	gossipDebugf("forward gossip_push: peers=%d", len(self.Peers.List()))
	forwardGossip(msg, envelope, hdr.Type, msgID, self, senderAddr)
	gossipDebugf("gossip_push end incoming_type=%s inner_type=%s forward_addr=%s outbound_type=gossip_push", msg.Type, hdr.Type, senderAddr)
	return newState, nil
}

func forwardGossip(msg proto.GossipPushMsg, envelope []byte, innerType string, msgID string, self *node.Node, senderAddr string) {
	if self == nil || self.Peers == nil {
		check6Drop(msgID, "no_members", "peer store unavailable")
		return
	}
	hops := msg.Hops
	if hops <= 0 {
		hops = gossipHops()
	}
	if hops <= 1 {
		gossipDebugf("skip gossip_forward: hops=%d", hops)
		check6Phase("PHASE ttl_check msg_id=%s ttl=%d decision=drop", msgID, hops)
		check6Drop(msgID, "ttl_zero", fmt.Sprintf("hops=%d", hops))
		return
	}
	check6Phase("PHASE ttl_check msg_id=%s ttl=%d decision=pass", msgID, hops)
	fanout := gossipFanout()
	if fanout <= 0 {
		gossipDebugf("skip gossip_forward: fanout=%d", fanout)
		check6Drop(msgID, "no_members", "fanout disabled")
		return
	}
	candidates := filterGossipPeers(self.Peers.List(), senderAddr, self.Peers, self.ID)
	fromMembers := false
	if self.Members != nil {
		memberCandidates := filterMemberPeers(candidates, self.Members)
		if len(memberCandidates) > 0 {
			fromMembers = true
			candidates = memberCandidates
		}
	}
	if len(candidates) == 0 {
		gossipDebugf("skip gossip_forward: no candidates")
		check6Phase("PHASE membership_lookup msg_id=%s targets=0", msgID)
		check6Drop(msgID, "no_members", "no candidates")
		return
	}
	check6Phase("PHASE membership_lookup msg_id=%s targets=%d", msgID, len(candidates))
	gossipDebugf("gossip_forward candidates=%d fanout=%d hops=%d", len(candidates), fanout, hops)
	gossipDebugf("gossip_forward self_node_id=%x signing_pub_node_id=%s sealing_priv_node_id=%x", self.ID[:], nodeIDHexFromPub(self.PubKey), self.ID[:])
	selected := pickRandomPeers(candidates, fanout)
	if len(selected) == 0 {
		gossipDebugf("skip gossip_forward: empty selection")
		check6Drop(msgID, "no_members", "empty selection")
		return
	}
	for _, p := range selected {
		addrSource := "default"
		if fromMembers {
			addrSource = "members"
		}
		gossipDebugf("forward attempt node_id=%x addr=%s", p.NodeID[:], p.Addr)
		if p.NodeID == self.ID {
			check6Drop(msgID, "self_target", "target is self")
			continue
		}
		if p.Addr == "" {
			gossipDebugf("forward skip reason=missing_addr node_id=%x", p.NodeID[:])
			check6Drop(msgID, "no_addr_for_target", "missing addr")
			continue
		}
		if isZeroNodeID(p.NodeID) {
			gossipDebugf("forward skip reason=missing_node_id addr=%s", p.Addr)
			check6Drop(msgID, "no_members", "missing node id")
			continue
		}
		if mapped, ok := findPeerByAddr(self.Peers.List(), p.Addr); ok && mapped.NodeID != p.NodeID {
			gossipDebugf("forward skip reason=addr_mismatch addr=%s want=%x got=%x", p.Addr, p.NodeID[:], mapped.NodeID[:])
			check6Drop(msgID, "self_target", "addr mismatch")
			continue
		}
		peerForSeal := p
		if byID, ok := findPeerByNodeID(self.Peers.List(), p.NodeID); ok && len(byID.PubKey) > 0 {
			peerForSeal = byID
			peerForSeal.Addr = p.Addr
			if byID.Addr != "" {
				addrSource = "peer.addr"
			}
		}
		if len(peerForSeal.PubKey) == 0 {
			gossipDebugf("forward skip reason=missing_pubkey node_id=%x addr=%s", p.NodeID[:], p.Addr)
			check6Drop(msgID, "no_members", "missing pubkey")
			continue
		}
		if addrSource == "default" {
			addrSource = "peer.addr"
		}
		check6Phase("PHASE send_attempt msg_id=%s target=%x addr=%s addr_source=%s", msgID, p.NodeID[:], p.Addr, addrSource)
		gossipDebugf("gossip_forward target_peer_node_id=%x target_peer_pub_node_id=%s", peerForSeal.NodeID[:], nodeIDHexFromPub(peerForSeal.PubKey))
		out, err := buildGossipPushForPeer(peerForSeal, envelope, hops-1, self)
		if err != nil {
			gossipDebugf("forward skip reason=seal_error node_id=%x addr=%s err=%v", p.NodeID[:], p.Addr, err)
			check6Drop(msgID, "bad_json", err.Error())
			continue
		}
		forwardSHA := sha256Hex(out)
		forwardMsgID := ""
		if forwardSHA != "" {
			forwardMsgID = forwardSHA[:12]
		}
		if check6Enabled() {
			fmt.Fprintf(os.Stderr, "FORWARD payload msg_id=%s forward_msg_id=%s sha256=%s len=%d\n", msgID, forwardMsgID, forwardSHA, len(out))
		}
		var outHdr struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(out, &outHdr); err != nil || outHdr.Type != proto.MsgTypeGossipPush {
			panic(fmt.Sprintf("gossip forward produced non-gossip_push outbound=%q inner=%s addr=%s err=%v", outHdr.Type, innerType, p.Addr, err))
		}
		gossipDebugf("gossip_push forward meta incoming_type=%s inner_type=%s forward_addr=%s outbound_type=%s", msg.Type, innerType, p.Addr, outHdr.Type)
		if os.Getenv("WEB4_DEBUG") == "1" {
			var top struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(out, &top); err == nil && top.Type != "" {
				gossipDebugf("forward send type=%s to=%s", top.Type, p.Addr)
			} else {
				gossipDebugf("forward send type=unknown to=%s", p.Addr)
			}
		}
		gossipDebugf("forward seal ok to node_id=%x addr=%s", p.NodeID[:], p.Addr)
		if check6Enabled() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			resp, err := exchangeFn(ctx, p.Addr, out, false, true, "")
			cancel()
			if err != nil {
				debugCount.incSend("gossip_forward")
				errStr := err.Error()
				reason := "send_error"
				if errors.Is(err, context.DeadlineExceeded) {
					reason = "ctx_deadline"
				} else if strings.Contains(strings.ToLower(errStr), "rate") {
					reason = "rate_limited"
				} else if strings.Contains(strings.ToLower(errStr), "dial") {
					reason = "send_error"
				}
				check6Phase("PHASE send_result msg_id=%s target=%x ok=0 err=%s", msgID, p.NodeID[:], errStr)
				check6Drop(msgID, reason, errStr)
				fmt.Fprintf(os.Stderr, "FORWARD_ACK msg_id=%s forward_msg_id=%s sha256=%s ack_sha= status=error err=%s\n", msgID, forwardMsgID, forwardSHA, errStr)
				continue
			}
			ack, err := proto.DecodeGossipAckMsg(resp)
			if err != nil {
				errStr := err.Error()
				check6Phase("PHASE send_result msg_id=%s target=%x ok=0 err=%s", msgID, p.NodeID[:], errStr)
				check6Drop(msgID, "bad_json", errStr)
				fmt.Fprintf(os.Stderr, "FORWARD_ACK msg_id=%s forward_msg_id=%s sha256=%s ack_sha= status=decode_error err=%s\n", msgID, forwardMsgID, forwardSHA, errStr)
				continue
			}
			if ack.Sha256 != forwardSHA {
				errStr := fmt.Sprintf("ack sha mismatch want=%s got=%s", forwardSHA, ack.Sha256)
				check6Phase("PHASE send_result msg_id=%s target=%x ok=0 err=%s", msgID, p.NodeID[:], errStr)
				check6Drop(msgID, "bad_json", errStr)
				fmt.Fprintf(os.Stderr, "FORWARD_ACK msg_id=%s forward_msg_id=%s sha256=%s ack_sha=%s status=mismatch err=%s\n", msgID, forwardMsgID, forwardSHA, ack.Sha256, errStr)
				continue
			}
			check6Phase("PHASE send_result msg_id=%s target=%x ok=1 err=", msgID, p.NodeID[:])
			fmt.Fprintf(os.Stderr, "FORWARD_ACK msg_id=%s forward_msg_id=%s sha256=%s ack_sha=%s status=ok err=\n", msgID, forwardMsgID, forwardSHA, ack.Sha256)
			debugCount.incSend("gossip_forward")
			continue
		}
		if err := sendFunc(p.Addr, out, false, true, ""); err != nil {
			debugCount.incSend("gossip_forward")
			gossipDebugf("forward failed reason=send_error node_id=%x addr=%s err=%v", p.NodeID[:], p.Addr, err)
			if os.Getenv("WEB4_DEBUG") == "1" {
				fmt.Fprintf(os.Stderr, "gossip forward failed: %v\n", err)
			}
			errStr := err.Error()
			reason := "send_error"
			if errors.Is(err, context.DeadlineExceeded) {
				reason = "ctx_deadline"
			} else if strings.Contains(strings.ToLower(errStr), "rate") {
				reason = "rate_limited"
			}
			check6Phase("PHASE send_result msg_id=%s target=%x ok=0 err=%s", msgID, p.NodeID[:], errStr)
			check6Drop(msgID, reason, errStr)
			continue
		}
		check6Phase("PHASE send_result msg_id=%s target=%x ok=1 err=", msgID, p.NodeID[:])
		gossipDebugf("gossip forward ok: node_id=%x addr=%s", p.NodeID[:], p.Addr)
	}
}

func handleGossipHello1Payload(data []byte, self *node.Node, senderAddr string, relayNodeID [32]byte) (bool, error) {
	if self == nil || self.Peers == nil {
		return false, errors.New("peer store unavailable")
	}
	if err := enforceTypeMax(proto.MsgTypeHello1, len(data)); err != nil {
		return false, err
	}
	m, err := proto.DecodeHello1Msg(data)
	if err != nil {
		return false, err
	}
	fromID, toID, fromPub, ea, na, sig, err := proto.DecodeHello1Fields(m)
	if err != nil {
		return false, err
	}
	if os.Getenv("WEB4_DEBUG") == "1" {
		fmt.Fprintf(os.Stderr, "hello1 recv from=%x to=%x via=gossip\n", fromID[:], toID[:])
	}
	derived := node.DeriveNodeID(fromPub)
	if derived != fromID {
		return false, errors.New("hello1 from_id mismatch")
	}
	if fromID == self.ID {
		return false, errors.New("hello1 from_id self")
	}
	// Rate-limit gossip hello by sender identity before any expensive signature checks.
	fromKey := hex.EncodeToString(fromID[:])
	if !recvNodeLimiter.Allow(fromKey) {
		return false, errors.New("rate limited")
	}
	// Optional relay dimension to limit one sender fanning through many forwarders.
	if !isZeroNodeID(relayNodeID) {
		relayKey := fromKey + "|relay:" + hex.EncodeToString(relayNodeID[:])
		if !recvNodeLimiter.Allow(relayKey) {
			return false, errors.New("rate limited")
		}
	}
	suiteID := byte(m.SuiteID)
	mlkemPub, err := decodeHexOptional(m.MLKEMPub)
	if err != nil {
		return false, errors.New("bad mlkem_pub")
	}
	pqPub, err := decodeHexOptional(m.PQPub)
	if err != nil {
		return false, errors.New("bad pq_pub")
	}
	pqBindSig, err := decodeHexOptional(m.PQBindSig)
	if err != nil {
		return false, errors.New("bad pq_bind_sig")
	}
	if suiteID == 0 {
		if len(mlkemPub) != crypto.MLKEM768PublicKeySize || len(pqPub) == 0 || len(pqBindSig) == 0 {
			return false, errors.New("missing pq fields")
		}
		bind := pqBindInput(fromID, pqPub)
		if !crypto.VerifyDigest(fromPub, crypto.SHA3_256(bind), pqBindSig) {
			return false, errors.New("bad pq binding")
		}
	}
	h1Bytes := hello1TranscriptBytes(suiteID, fromID, toID, ea, na, mlkemPub)
	h1TranscriptHash := crypto.SHA3_256(h1Bytes)
	sessionID, err := decodeSessionIDHex(m.SessionID)
	if err != nil {
		if !allowLegacyHelloSig() {
			return false, err
		}
	}
	expectedSID := sessionIDForHandshake(suiteID, fromID, toID, ea, zero32(), h1TranscriptHash)
	if len(sessionID) > 0 && !bytesEqual(sessionID, expectedSID) {
		return false, errors.New("hello1 session_id mismatch")
	}
	sigInput := hello1SigInput(suiteID, fromID, toID, ea, na, sessionID)
	if len(sessionID) == 0 {
		sigInput = hello1SigInputLegacy(suiteID, fromID, toID, ea, na)
	}
	if !verifyHelloBySuite(suiteID, fromPub, pqPub, sigInput, sig) {
		debugCount.incVerify("hello1")
		return false, errors.New("bad hello1 signature")
	}
	newState := true
	if _, ok := findPeerByNodeID(self.Peers.List(), fromID); ok {
		newState = false
	}
	peerInfo := peer.Peer{NodeID: fromID, PubKey: fromPub}
	if err := self.Peers.Upsert(peerInfo, true); err != nil {
		return false, err
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
			verified = true
		} else if senderAddr != "" {
			candidateAddr = senderAddr
			verified = true
		}
		if _, err := self.Peers.ObserveAddr(peerInfo, observedAddr, candidateAddr, verified, true); err != nil {
			return false, err
		}
	}
	return newState, nil
}

func filterGossipPeers(peers []peer.Peer, excludeAddr string, store *peer.Store, selfID [32]byte) []peer.Peer {
	out := make([]peer.Peer, 0, len(peers))
	for _, p := range peers {
		if p.NodeID == selfID {
			continue
		}
		addr := p.Addr
		if addr == "" && store != nil {
			if hint, ok := store.AddrHint(p.NodeID); ok {
				addr = hint
			}
		}
		if addr == "" || len(p.PubKey) == 0 {
			continue
		}
		if excludeAddr != "" && addr == excludeAddr {
			continue
		}
		cp := p
		cp.Addr = addr
		out = append(out, cp)
	}
	return out
}

func filterMemberPeers(peers []peer.Peer, members *peer.MemberStore) []peer.Peer {
	if members == nil {
		return peers
	}
	out := make([]peer.Peer, 0, len(peers))
	for _, p := range peers {
		if members.HasScope(p.NodeID, proto.InviteScopeGossip) {
			out = append(out, p)
		}
	}
	return out
}

func pickRandomPeers(peers []peer.Peer, fanout int) []peer.Peer {
	if fanout <= 0 || len(peers) == 0 {
		return nil
	}
	if fanout > len(peers) {
		fanout = len(peers)
	}
	out := make([]peer.Peer, len(peers))
	copy(out, peers)
	gossipRandMu.Lock()
	gossipRand.Shuffle(len(out), func(i, j int) {
		out[i], out[j] = out[j], out[i]
	})
	gossipRandMu.Unlock()
	return out[:fanout]
}

func gossipFanout() int {
	if v, ok := envInt("WEB4_GOSSIP_FANOUT"); ok {
		if v <= 0 {
			return 0
		}
		if v > maxGossipFanout {
			return maxGossipFanout
		}
		return v
	}
	return defaultGossipFanout
}

func gossipHops() int {
	if v, ok := envInt("WEB4_GOSSIP_TTL_HOPS"); ok {
		if v <= 0 {
			return 0
		}
		return v
	}
	return defaultGossipHops
}

func envInt(name string) (int, bool) {
	s := strings.TrimSpace(os.Getenv(name))
	if s == "" {
		return 0, false
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return v, true
}

func zkMode() bool {
	return os.Getenv("WEB4_ZK_MODE") == "1"
}

func deltaMode() string {
	mode := strings.TrimSpace(os.Getenv("WEB4_DELTA_MODE"))
	if mode == "" {
		return "legacy"
	}
	return mode
}

func deltaConstraintMatrix() [][]int64 {
	return [][]int64{{1, 1}}
}

func deltaScalars(amount uint64) ([]pedersen.Scalar, error) {
	if amount > math.MaxInt64 {
		return nil, fmt.Errorf("amount too large")
	}
	v := int64(amount)
	return linear.ScalarsFromInt64([]int64{-v, v})
}

func openPayloadContext(p proto.OpenPayload) ([]byte, error) {
	p.ZK = nil
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	sum := crypto.SHA3_256(raw)
	return sum[:], nil
}

func ackPayloadContext(p proto.AckPayload) ([]byte, error) {
	p.ZK = nil
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	sum := crypto.SHA3_256(raw)
	return sum[:], nil
}

func buildDeltaProof(amount uint64, ctx []byte) (*proto.ZKLinearProof, error) {
	x, err := deltaScalars(amount)
	if err != nil {
		return nil, err
	}
	C, r, err := pedersen.CommitVector(x, ctx)
	if err != nil {
		return nil, err
	}
	bundle, err := linear.ProveLinearNullspace(deltaConstraintMatrix(), C, r, ctx)
	if err != nil {
		return nil, err
	}
	return linear.EncodeLinearProof(C, bundle)
}

func verifyDeltaProof(amount uint64, ctx []byte, zk *proto.ZKLinearProof) error {
	if zk == nil {
		return fmt.Errorf("missing proof")
	}
	if _, err := deltaScalars(amount); err != nil {
		return err
	}
	C, bundle, err := linear.DecodeLinearProof(zk)
	if err != nil {
		return err
	}
	if !linear.VerifyLinearNullspace(deltaConstraintMatrix(), C, bundle, ctx) {
		return fmt.Errorf("zk verify failed")
	}
	return nil
}

func membersViewID(members [][32]byte) [32]byte {
	out := make([][32]byte, len(members))
	copy(out, members)
	sort.Slice(out, func(i, j int) bool {
		return bytes.Compare(out[i][:], out[j][:]) < 0
	})
	buf := make([]byte, 0, 32*len(out)+8)
	tmp := make([]byte, 8)
	binary.BigEndian.PutUint64(tmp, uint64(len(out)))
	buf = append(buf, tmp...)
	for _, id := range out {
		buf = append(buf, id[:]...)
	}
	sum := crypto.SHA3_256(append([]byte("web4/deltab/view/v0"), buf...))
	var id [32]byte
	copy(id[:], sum[:])
	return id
}

func deltaBContext(msg proto.DeltaBMsg, viewID [32]byte) ([]byte, error) {
	msg.ZK = nil
	canonEntries, err := proto.CanonicalizeDeltaBEntries(msg.Entries)
	if err != nil {
		return nil, err
	}
	msg.Entries = canonEntries
	scopeHash, err := deltaBScopeHash(canonEntries)
	if err != nil {
		return nil, err
	}
	tag := msg.CtxTag
	if tag == "" {
		tag = "web4/deltab/v0"
	}
	var claimID []byte
	if msg.ClaimID != "" {
		rawID, err := hex.DecodeString(msg.ClaimID)
		if err != nil || len(rawID) != 32 {
			return nil, fmt.Errorf("invalid claim_id")
		}
		claimID = rawID
	}
	buf := make([]byte, 0, len(tag)+32*3)
	buf = append(buf, []byte(tag)...)
	buf = append(buf, scopeHash[:]...)
	buf = append(buf, viewID[:]...)
	if len(claimID) > 0 {
		buf = append(buf, claimID...)
	} else {
		raw, err := proto.EncodeDeltaBMsg(msg)
		if err != nil {
			return nil, err
		}
		deltaHash := crypto.SHA3_256(raw)
		buf = append(buf, deltaHash[:]...)
	}
	sum := crypto.SHA3_256(buf)
	return sum[:], nil
}

func deltaBScopeHash(entries []proto.DeltaBEntry) ([32]byte, error) {
	out := make([]proto.DeltaBEntry, len(entries))
	copy(out, entries)
	sort.Slice(out, func(i, j int) bool {
		return out[i].NodeID < out[j].NodeID
	})
	buf := make([]byte, 0, len(out)*32+8)
	tmp := make([]byte, 8)
	binary.BigEndian.PutUint64(tmp, uint64(len(out)))
	buf = append(buf, tmp...)
	for _, e := range out {
		id, err := decodeNodeIDHex(e.NodeID)
		if err != nil {
			return [32]byte{}, err
		}
		buf = append(buf, id[:]...)
	}
	sum := crypto.SHA3_256(append([]byte("web4/deltab/scope/v0"), buf...))
	var outSum [32]byte
	copy(outSum[:], sum[:])
	return outSum, nil
}

func canonicalDeltaB(msg proto.DeltaBMsg) (proto.DeltaBMsg, []byte, [32]byte, error) {
	entries, err := proto.CanonicalizeDeltaBEntries(msg.Entries)
	if err != nil {
		return proto.DeltaBMsg{}, nil, [32]byte{}, err
	}
	out := msg
	out.Type = proto.MsgTypeDeltaB
	out.ZK = nil
	out.Entries = entries
	data, err := proto.EncodeDeltaBMsg(out)
	if err != nil {
		return proto.DeltaBMsg{}, nil, [32]byte{}, err
	}
	sum := crypto.SHA3_256(data)
	var id [32]byte
	copy(id[:], sum[:])
	return out, data, id, nil
}

func deltaMaxAbs() (int64, bool) {
	raw := strings.TrimSpace(os.Getenv("WEB4_DELTA_MAX_ABS"))
	if raw == "" {
		return 0, false
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v <= 0 {
		return 0, false
	}
	return v, true
}

func deltaRelaxIters() int {
	raw := strings.TrimSpace(os.Getenv("WEB4_DELTA_RELAX_ITERS"))
	if raw == "" {
		return 2
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 0 {
		return 0
	}
	return v
}

func verifyDeltaBBasic(msg proto.DeltaBMsg, self *node.Node) (map[[32]byte]int64, [][32]byte, [32]byte, [32]byte, error) {
	if self == nil || self.Members == nil {
		return nil, nil, [32]byte{}, [32]byte{}, fmt.Errorf("missing member store")
	}
	viewIDBytes, err := hex.DecodeString(msg.ViewID)
	if err != nil || len(viewIDBytes) != 32 {
		return nil, nil, [32]byte{}, [32]byte{}, fmt.Errorf("invalid view_id")
	}
	var viewID [32]byte
	copy(viewID[:], viewIDBytes)

	members := self.Members.List()
	if len(members) == 0 {
		return nil, nil, [32]byte{}, [32]byte{}, fmt.Errorf("empty member set")
	}
	expectedView := membersViewID(members)
	if !bytes.Equal(expectedView[:], viewID[:]) {
		return nil, nil, [32]byte{}, [32]byte{}, fmt.Errorf("view_id mismatch")
	}
	memberSet := make(map[string]struct{}, len(members))
	for _, id := range members {
		memberSet[hex.EncodeToString(id[:])] = struct{}{}
	}

	deltas := make(map[[32]byte]int64, len(msg.Entries))
	seen := make(map[string]struct{}, len(msg.Entries))
	var sum int64
	maxAbs, bound := deltaMaxAbs()
	for _, e := range msg.Entries {
		id, err := decodeNodeIDHex(e.NodeID)
		if err != nil {
			return nil, nil, [32]byte{}, [32]byte{}, fmt.Errorf("bad node_id")
		}
		key := hex.EncodeToString(id[:])
		if _, ok := memberSet[key]; !ok {
			return nil, nil, [32]byte{}, [32]byte{}, fmt.Errorf("node_id not member")
		}
		if _, ok := seen[key]; ok {
			return nil, nil, [32]byte{}, [32]byte{}, fmt.Errorf("duplicate node_id")
		}
		seen[key] = struct{}{}
		if bound && abs64(e.Delta) > maxAbs {
			return nil, nil, [32]byte{}, [32]byte{}, fmt.Errorf("delta exceeds max abs")
		}
		sum += e.Delta
		deltas[id] = e.Delta
	}
	if sum != 0 {
		return nil, nil, [32]byte{}, [32]byte{}, fmt.Errorf("sum delta != 0")
	}

	scopeHash, err := deltaBScopeHash(msg.Entries)
	if err != nil {
		return nil, nil, [32]byte{}, [32]byte{}, err
	}
	return deltas, members, viewID, scopeHash, nil
}

func buildDeltaBProof(msg proto.DeltaBMsg, viewID [32]byte) (*proto.ZKLinearProof, error) {
	entries, err := proto.CanonicalizeDeltaBEntries(msg.Entries)
	if err != nil {
		return nil, err
	}
	values := make([]int64, len(entries))
	for i, e := range entries {
		values[i] = e.Delta
	}
	x, err := linear.ScalarsFromInt64(values)
	if err != nil {
		return nil, err
	}
	msg.Entries = entries
	ctx, err := deltaBContext(msg, viewID)
	if err != nil {
		return nil, err
	}
	L := [][]int64{make([]int64, len(values))}
	for i := range values {
		L[0][i] = 1
	}
	C, r, err := pedersen.CommitVector(x, ctx)
	if err != nil {
		return nil, err
	}
	bundle, err := linear.ProveLinearNullspace(L, C, r, ctx)
	if err != nil {
		return nil, err
	}
	return linear.EncodeLinearProof(C, bundle)
}

func verifyDeltaBZK(msg proto.DeltaBMsg, viewID [32]byte) error {
	entries, err := proto.CanonicalizeDeltaBEntries(msg.Entries)
	if err != nil {
		return err
	}
	msg.Entries = entries
	ctx, err := deltaBContext(msg, viewID)
	if err != nil {
		return fmt.Errorf("zk context failed")
	}
	if msg.ZK == nil {
		return fmt.Errorf("missing zk proof")
	}
	entries = make([]proto.DeltaBEntry, len(msg.Entries))
	copy(entries, msg.Entries)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].NodeID < entries[j].NodeID
	})
	values := make([]int64, len(entries))
	for i, e := range entries {
		values[i] = e.Delta
	}
	if _, err := linear.ScalarsFromInt64(values); err != nil {
		return fmt.Errorf("zk scalars failed")
	}
	C, bundle, err := linear.DecodeLinearProof(msg.ZK)
	if err != nil {
		return fmt.Errorf("zk decode failed")
	}
	L := [][]int64{make([]int64, len(values))}
	for i := range values {
		L[0][i] = 1
	}
	if len(C) != len(values) {
		return fmt.Errorf("zk commitment length mismatch")
	}
	if !linear.VerifyLinearNullspace(L, C, bundle, ctx) {
		return fmt.Errorf("zk verify failed")
	}
	return nil
}

func openGossipEnvelope(self *node.Node, msg proto.GossipPushMsg) ([]byte, error) {
	if self == nil {
		return nil, fmt.Errorf("missing node")
	}
	ephPub, sealed, err := proto.DecodeSealedFields(msg.EphemeralPub, msg.Sealed)
	if err != nil {
		return nil, err
	}
	var zero [32]byte
	return e2eOpen(proto.MsgTypeGossipPush, zero, 0, self.PrivKey, ephPub, sealed)
}

func buildGossipPushForPeer(p peer.Peer, envelope []byte, hops int, self *node.Node) ([]byte, error) {
	if len(p.PubKey) == 0 {
		return nil, fmt.Errorf("missing peer pubkey")
	}
	if self == nil || len(self.PrivKey) == 0 {
		return nil, fmt.Errorf("missing sender key")
	}
	derived := node.DeriveNodeID(p.PubKey)
	if derived != p.NodeID {
		gossipDebugf("gossip seal peer mismatch target_peer_node_id=%x target_peer_pub_node_id=%x addr=%s", p.NodeID[:], derived[:], p.Addr)
	} else {
		gossipDebugf("gossip seal peer match target_peer_node_id=%x target_peer_pub_node_id=%x addr=%s", p.NodeID[:], derived[:], p.Addr)
	}
	selfDerived := node.DeriveNodeID(self.PubKey)
	if selfDerived != self.ID {
		gossipDebugf("gossip seal sender mismatch sender_node_id=%x derived=%x", self.ID[:], selfDerived[:])
	}
	senderPubHash := hashHex(self.PubKey)
	recipientPubHash := hashHex(p.PubKey)
	gossipDebugf("gossip seal sender_node_id=%x sender_pub_hash=%s recipient_peer_node_id=%x recipient_pub_hash=%s", self.ID[:], senderPubHash, p.NodeID[:], recipientPubHash)
	var zero [32]byte
	ephPub, sealed, err := e2eSeal(proto.MsgTypeGossipPush, zero, 0, p.PubKey, envelope)
	if err != nil {
		return nil, err
	}
	gossipDebugf("gossip seal sealed_len=%d", len(sealed))
	msg := proto.GossipPushMsg{
		Type:         proto.MsgTypeGossipPush,
		ProtoVersion: proto.ProtoVersion,
		Suite:        proto.Suite,
		EphemeralPub: base64.StdEncoding.EncodeToString(ephPub),
		Sealed:       base64.StdEncoding.EncodeToString(sealed),
		Hops:         hops,
	}
	fromID := node.DeriveNodeID(self.PubKey)
	gossipDebugf("gossip seal from_node_id=%x signing_pub_node_id=%s sealing_priv_node_id=%x", fromID[:], nodeIDHexFromPub(self.PubKey), self.ID[:])
	msg.FromNodeID = hex.EncodeToString(fromID[:])
	payloadMsg := msg
	payloadMsg.SigFrom = ""
	payload, err := proto.EncodeGossipPushMsg(payloadMsg)
	if err != nil {
		return nil, err
	}
	sig := sigFromBytes(msg.ProtoVersion, msg.Suite, msg.Type, fromID, payload, self.PrivKey)
	msg.SigFrom = hex.EncodeToString(sig)
	data, err := proto.EncodeGossipPushMsg(msg)
	if err != nil {
		return nil, err
	}
	if err := enforceTypeMax(proto.MsgTypeGossipPush, len(data)); err != nil {
		return nil, err
	}
	return data, nil
}

func findPeerByAddr(peers []peer.Peer, addr string) (peer.Peer, bool) {
	for _, p := range peers {
		if p.Addr == addr {
			return p, true
		}
	}
	return peer.Peer{}, false
}

func hostForAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func previewBytes(b []byte, max int) string {
	if max <= 0 {
		return ""
	}
	if len(b) > max {
		b = b[:max]
	}
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 32 && c < 127 {
			out[i] = c
		} else {
			out[i] = '.'
		}
	}
	return string(out)
}

func handshakeSuiteIDLabel(payload []byte) string {
	var hdr struct {
		Type    string `json:"type"`
		SuiteID *int   `json:"suite_id"`
	}
	if err := json.Unmarshal(payload, &hdr); err != nil {
		return "n/a"
	}
	if hdr.Type != proto.MsgTypeHello1 && hdr.Type != proto.MsgTypeHello2 {
		return "n/a"
	}
	if hdr.SuiteID == nil {
		return "n/a"
	}
	return strconv.Itoa(*hdr.SuiteID)
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

func verifiedPeerForAddr(peers []peer.Peer, addr string, store *peer.Store) (peer.Peer, bool) {
	if addr == "" {
		return peer.Peer{}, false
	}
	if p, ok := findPeerByAddr(peers, addr); ok && len(p.PubKey) > 0 {
		if store == nil || store.IsAddrVerified(p.NodeID) {
			return p, true
		}
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	for _, p := range peers {
		if len(p.PubKey) == 0 || p.Addr == "" {
			continue
		}
		if store != nil && !store.IsAddrVerified(p.NodeID) {
			continue
		}
		peerHost, _, err := net.SplitHostPort(p.Addr)
		if err != nil {
			peerHost = p.Addr
		}
		if peerHost == host {
			return p, true
		}
	}
	return peer.Peer{}, false
}

func isVerifiedSender(peers []peer.Peer, addr string, store *peer.Store) bool {
	_, ok := verifiedPeerForAddr(peers, addr, store)
	return ok
}

func candidateAddrForSender(pool *peer.CandidatePool, senderAddr string) (string, bool) {
	if pool == nil || senderAddr == "" {
		return "", false
	}
	senderHost, _, err := net.SplitHostPort(senderAddr)
	if err != nil {
		senderHost = senderAddr
	}
	for _, addr := range pool.List() {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		if host == senderHost {
			return addr, true
		}
	}
	return "", false
}

func buildPeerExchangeResp(self *node.Node, k int) (proto.PeerExchangeRespMsg, error) {
	if self == nil || self.Peers == nil {
		return proto.PeerExchangeRespMsg{}, fmt.Errorf("peer store unavailable")
	}
	if k <= 0 {
		k = defaultPeerExchangeK
	}
	if k > maxPeerExchangeK {
		k = maxPeerExchangeK
	}
	peers := self.Peers.List()
	respPeers := make([]proto.PeerExchangePeer, 0, k)
	for _, p := range peers {
		if len(respPeers) >= k {
			break
		}
		if p.Addr == "" || len(p.PubKey) == 0 {
			continue
		}
		id := p.NodeID
		if isZeroNodeID(id) {
			id = node.DeriveNodeID(p.PubKey)
		}
		peerMsg := proto.PeerExchangePeer{
			Addr:   p.Addr,
			NodeID: hex.EncodeToString(id[:]),
			PubKey: hex.EncodeToString(p.PubKey),
		}
		respPeers = append(respPeers, peerMsg)
	}
	msg := proto.PeerExchangeRespMsg{
		Type:         proto.MsgTypePeerExchangeResp,
		ProtoVersion: proto.ProtoVersion,
		Suite:        proto.Suite,
		Peers:        respPeers,
	}
	fromID := self.ID
	msg.FromNodeID = hex.EncodeToString(fromID[:])
	payloadMsg := msg
	payloadMsg.SigFrom = ""
	payload, err := proto.EncodePeerExchangeResp(payloadMsg)
	if err != nil {
		return proto.PeerExchangeRespMsg{}, err
	}
	sig := sigFromBytes(msg.ProtoVersion, msg.Suite, msg.Type, fromID, payload, self.PrivKey)
	msg.SigFrom = hex.EncodeToString(sig)
	return msg, nil
}

func applyPeerExchangeResp(self *node.Node, resp proto.PeerExchangeRespMsg) (int, error) {
	if self == nil || self.Peers == nil {
		return 0, fmt.Errorf("peer store unavailable")
	}
	added := 0
	limit := len(resp.Peers)
	if limit > maxPeerExchangeK {
		limit = maxPeerExchangeK
	}
	for i := 0; i < limit; i++ {
		p, err := decodePeerExchangePeer(resp.Peers[i])
		if err != nil {
			return added, err
		}
		if p.Addr != "" && self.Candidates != nil {
			self.Candidates.Add(p.Addr)
		}
		if p.Addr != "" && self.Peers != nil {
			_, _ = self.Peers.SetAddrUnverified(p, p.Addr, true)
		}
		p.Addr = ""
		persist := len(p.PubKey) > 0
		if err := self.Peers.Upsert(p, persist); err != nil {
			return added, err
		}
		added++
	}
	return added, nil
}

func decodePeerExchangePeer(w proto.PeerExchangePeer) (peer.Peer, error) {
	var id [32]byte
	idSet := false
	if w.NodeID != "" {
		idBytes, err := hex.DecodeString(w.NodeID)
		if err != nil || len(idBytes) != 32 {
			return peer.Peer{}, fmt.Errorf("bad node_id")
		}
		copy(id[:], idBytes)
		idSet = true
	}
	var pub []byte
	if w.PubKey == "" {
		return peer.Peer{}, fmt.Errorf("missing pubkey")
	}
	pubBytes, err := hex.DecodeString(w.PubKey)
	if err != nil || !crypto.IsRSAPublicKey(pubBytes) {
		return peer.Peer{}, fmt.Errorf("bad pubkey")
	}
	pub = pubBytes
	derived := node.DeriveNodeID(pub)
	if idSet && derived != id {
		return peer.Peer{}, fmt.Errorf("node_id mismatch")
	}
	if !idSet {
		id = derived
		idSet = true
	}
	return peer.Peer{NodeID: id, PubKey: pub, Addr: w.Addr}, nil
}

func findPeerByNodeID(peers []peer.Peer, id [32]byte) (peer.Peer, bool) {
	for _, p := range peers {
		if p.NodeID == id && len(p.PubKey) > 0 {
			return p, true
		}
	}
	return peer.Peer{}, false
}

func hasPeerID(peers []peer.Peer, id [32]byte) bool {
	for _, p := range peers {
		if p.NodeID == id {
			return true
		}
	}
	return false
}

func signInputBytes(version, suite, msgType string, fromID [32]byte, payload []byte) []byte {
	buf := make([]byte, 0, len(version)+len(suite)+len(msgType)+len(fromID)+len(payload))
	buf = append(buf, version...)
	buf = append(buf, suite...)
	buf = append(buf, msgType...)
	buf = append(buf, fromID[:]...)
	buf = append(buf, payload...)
	return buf
}

func sigFromBytes(version, suite, msgType string, fromID [32]byte, payload []byte, priv []byte) []byte {
	_ = version
	_ = suite
	_ = msgType
	_ = fromID
	_ = payload
	_ = priv
	return nil
}

func verifySigFrom(version, suite, msgType string, fromID [32]byte, payload []byte, sig, pub []byte) bool {
	_ = version
	_ = suite
	_ = msgType
	_ = fromID
	_ = payload
	_ = sig
	_ = pub
	return true
}

func requiredMemberScope(msgType string) (uint32, bool) {
	switch msgType {
	case proto.MsgTypeContractOpen, proto.MsgTypeRepayReq, proto.MsgTypeAck, proto.MsgTypeDeltaB:
		return proto.InviteScopeContract, true
	default:
		return 0, false
	}
}

func validateInviteCert(cert proto.InviteCert, invites *peer.InviteStore, now time.Time) ([32]byte, [32]byte, error) {
	var zero [32]byte
	if len(cert.InviteePub) == 0 {
		return zero, zero, fmt.Errorf("missing invitee_pub")
	}
	if len(cert.InviterPub) == 0 {
		return zero, zero, fmt.Errorf("missing inviter_pub")
	}
	if !crypto.IsRSAPublicKey(cert.InviteePub) {
		return zero, zero, fmt.Errorf("invitee node_id mismatch")
	}
	if !crypto.IsRSAPublicKey(cert.InviterPub) {
		return zero, zero, fmt.Errorf("inviter node_id mismatch")
	}
	if len(cert.InviteID) != 16 && len(cert.InviteID) != 32 {
		return zero, zero, fmt.Errorf("bad invite_id length")
	}
	inviteeHash := crypto.SHA3_256(cert.InviteePub)
	inviterHash := crypto.SHA3_256(cert.InviterPub)
	var inviteeID [32]byte
	var inviterID [32]byte
	copy(inviteeID[:], inviteeHash)
	copy(inviterID[:], inviterHash)
	if isZeroNodeID(inviteeID) {
		return zero, zero, fmt.Errorf("invitee node_id missing")
	}
	if isZeroNodeID(inviterID) {
		return zero, zero, fmt.Errorf("inviter node_id missing")
	}
	if cert.ExpiresAt == 0 {
		return zero, zero, fmt.Errorf("missing expires_at")
	}
	if cert.IssuedAt == 0 {
		return zero, zero, fmt.Errorf("missing issued_at")
	}
	if cert.ExpiresAt < cert.IssuedAt {
		return zero, zero, fmt.Errorf("expires before issued")
	}
	skew := 5 * time.Minute
	nowUnix := uint64(now.Unix())
	if cert.IssuedAt > nowUnix+uint64(skew.Seconds()) {
		return zero, zero, fmt.Errorf("issued_at in future")
	}
	if cert.ExpiresAt < nowUnix {
		return zero, zero, fmt.Errorf("invite expired")
	}
	if cert.PowBits != proto.InvitePoWaDBits {
		return zero, zero, fmt.Errorf("pow bits mismatch")
	}
	signBytes, err := proto.EncodeInviteCertForSig(cert)
	if err != nil {
		return zero, zero, err
	}
	if !crypto.VerifyDigest(cert.InviterPub, crypto.SHA3_256(signBytes), cert.Sig) {
		return zero, zero, fmt.Errorf("bad signature")
	}
	if !crypto.PoWaDCheck(cert.InviteID, inviteeID[:], cert.PowNonce, cert.PowBits) {
		return zero, zero, fmt.Errorf("powad failed")
	}
	if invites != nil && invites.Seen(inviterID, cert.InviteID) {
		return zero, zero, fmt.Errorf("invite replay")
	}
	return inviterID, inviteeID, nil
}

func decodeNodeIDHex(s string) ([32]byte, error) {
	var id [32]byte
	if s == "" {
		return id, fmt.Errorf("missing from_node_id")
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return id, fmt.Errorf("bad from_node_id")
	}
	copy(id[:], b)
	return id, nil
}

func decodeSigHex(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("bad sig_from")
	}
	return b, nil
}

func parseInviteScope(s string) (uint32, error) {
	if s == "" {
		return proto.InviteScopeGossip, nil
	}
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "all" {
		return proto.InviteScopeAll, nil
	}
	parts := strings.Split(s, ",")
	var scope uint32
	for _, p := range parts {
		p = strings.TrimSpace(p)
		switch p {
		case "gossip":
			scope |= proto.InviteScopeGossip
		case "contract":
			scope |= proto.InviteScopeContract
		case "":
		default:
			return 0, fmt.Errorf("unknown scope: %s", p)
		}
	}
	if scope == 0 {
		return 0, fmt.Errorf("empty scope")
	}
	return scope, nil
}

func inviteThreshold() int {
	raw := strings.TrimSpace(os.Getenv("WEB4_INVITE_THRESHOLD"))
	if raw == "" {
		return 1
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 1
	}
	return n
}

func verifySignedMessage(data []byte, msgType string, self *node.Node) *recvError {
	_ = data
	_ = msgType
	_ = self
	return nil
}

func ensureSignedOutgoing(data []byte, self *node.Node) ([]byte, error) {
	_ = self
	return data, nil
}
func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: web4 <keygen|open|list|close|ack|recv|quic-listen|quic-send|quic-send-secure|node|gossip>")
		os.Exit(1)
	}

	root := homeDir()
	_ = os.MkdirAll(root, 0700)
	if err := ensureKeypair(root); err != nil {
		die("load keys failed", err)
	}

	st := store.New(
		filepath.Join(root, "contracts.jsonl"),
		filepath.Join(root, "acks.jsonl"),
		filepath.Join(root, "repayreqs.jsonl"),
	)
	checker := math4.NewLocalChecker(math4.Options{})

	switch os.Args[1] {

	case "keygen":
		pub, priv, err := crypto.GenKeypair()
		if err != nil {
			die("keygen failed", err)
		}
		if err := crypto.SaveKeypair(root, pub, priv); err != nil {
			die("save keys failed", err)
		}
		fmt.Println("OK keypair generated")
		fmt.Println("pub:", hex.EncodeToString(pub))

	case "open":
		fs := flag.NewFlagSet("open", flag.ExitOnError)
		toHex := fs.String("to", "", "counterparty pubkey hex")
		amount := fs.Uint64("amount", 0, "amount")
		nonce := fs.Uint64("nonce", 0, "nonce (monotonic per counterparty)")
		outPath := fs.String("out", "", "write ContractOpenMsg to file and exit")
		_ = fs.Parse(os.Args[2:])

		pub, priv, err := crypto.LoadKeypair(root)
		if err != nil {
			die("load keys failed", err)
		}
		to, err := hex.DecodeString(*toHex)
		if err != nil || !crypto.IsRSAPublicKey(to) {
			die("invalid --to pubkey", fmt.Errorf("need RSA public key DER hex"))
		}

		iou := proto.IOU{Creditor: to, Debtor: pub, Amount: *amount, Nonce: *nonce}
		cid := proto.ContractID(iou)
		credHex := hex.EncodeToString(to)
		debtHex := hex.EncodeToString(pub)
		openPayload := proto.OpenPayload{
			Type:     proto.MsgTypeContractOpen,
			Creditor: credHex,
			Debtor:   debtHex,
			Amount:   *amount,
			Nonce:    *nonce,
		}
		if zkMode() {
			ctx, err := openPayloadContext(openPayload)
			if err != nil {
				die("encode open payload failed", err)
			}
			zk, err := buildDeltaProof(*amount, ctx)
			if err != nil {
				die("build zk proof failed", err)
			}
			openPayload.ZK = zk
		}
		payload, err := json.Marshal(openPayload)
		if err != nil {
			die("encode open payload failed", err)
		}
		ephPub, sealed, err := e2eSeal(proto.MsgTypeContractOpen, cid, 0, to, payload)
		if err != nil {
			die("e2e seal failed", err)
		}

		// v0.0.2: sign over SHA3_256(message)
		iouMsg := proto.OpenSignBytes(iou, ephPub, sealed)
		sigB := crypto.Sign(priv, crypto.SHA3_256(iouMsg))

		// NOTE: in real life creditor also signs; for MVP we allow "half-open" then later attach creditor sig.
		c := proto.Contract{
			IOU:          iou,
			SigCred:      nil,
			SigDebt:      sigB,
			EphemeralPub: ephPub,
			Sealed:       sealed,
			Status:       "OPEN",
		}
		if err := st.AddContract(c); err != nil {
			die("store failed", err)
		}
		if *outPath != "" {
			msg := proto.ContractOpenMsgFromContract(c)
			fromID := node.DeriveNodeID(pub)
			msg.FromNodeID = hex.EncodeToString(fromID[:])
			payloadMsg := msg
			payloadMsg.SigFrom = ""
			payload, err := proto.EncodeContractOpenMsg(payloadMsg)
			if err != nil {
				die("encode message failed", err)
			}
			sigFrom := sigFromBytes(msg.ProtoVersion, msg.Suite, msg.Type, fromID, payload, priv)
			msg.SigFrom = hex.EncodeToString(sigFrom)
			data, err := proto.EncodeContractOpenMsg(msg)
			if err != nil {
				die("encode message failed", err)
			}
			if err := writeMsg(*outPath, data); err != nil {
				die("write message failed", err)
			}
			return
		}
		fmt.Println("OPEN", hex.EncodeToString(cid[:]))

	case "list":
		cs, err := st.ListContracts()
		if err != nil {
			die("list failed", err)
		}
		for _, c := range cs {
			id := proto.ContractID(c.IOU)
			fmt.Printf("%s  %s  amt=%d nonce=%d\n", c.Status, hex.EncodeToString(id[:]), c.IOU.Amount, c.IOU.Nonce)
		}

	case "close":
		fs := flag.NewFlagSet("close", flag.ExitOnError)
		idHex := fs.String("id", "", "contract id hex")
		reqNonce := fs.Uint64("reqnonce", 1, "request nonce")
		outPath := fs.String("out", "", "write RepayReqMsg to file and exit")
		_ = fs.Parse(os.Args[2:])

		pub, priv, err := crypto.LoadKeypair(root)
		if err != nil {
			die("load keys failed", err)
		}
		idBytes, err := hex.DecodeString(*idHex)
		if err != nil || len(idBytes) != 32 {
			die("invalid --id", fmt.Errorf("need 32 bytes hex"))
		}
		var cid [32]byte
		copy(cid[:], idBytes)

		c, err := findContractByID(st, cid)
		if err != nil {
			die("contract lookup failed", err)
		}
		if c == nil {
			die("contract lookup failed", fmt.Errorf("contract not found"))
		}
		if !bytes.Equal(c.IOU.Debtor, pub) {
			die("debtor mismatch", fmt.Errorf("only debtor can close"))
		}

		req := proto.RepayReq{ContractID: cid, ReqNonce: *reqNonce, Close: true}
		payload, err := proto.EncodeRepayPayload(*idHex, *reqNonce, true)
		if err != nil {
			die("encode repay payload failed", err)
		}
		ephPub, sealed, err := e2eSeal(proto.MsgTypeRepayReq, cid, *reqNonce, c.IOU.Creditor, payload)
		if err != nil {
			die("e2e seal failed", err)
		}

		// v0.0.2: sign over SHA3_256(message)
		reqMsg := proto.RepayReqSignBytes(req, ephPub, sealed)
		sig := crypto.Sign(priv, crypto.SHA3_256(reqMsg))

		_ = pub // (debtor pub already in key file)

		msg := proto.RepayReqMsgFromReq(req, sig, ephPub, sealed)
		if err := st.AddRepayReqIfNew(msg); err != nil {
			die("store repay request failed", err)
		}
		if *outPath != "" {
			fromID := node.DeriveNodeID(pub)
			msg.FromNodeID = hex.EncodeToString(fromID[:])
			payloadMsg := msg
			payloadMsg.SigFrom = ""
			payload, err := proto.EncodeRepayReqMsg(payloadMsg)
			if err != nil {
				die("encode message failed", err)
			}
			sigFrom := sigFromBytes(msg.ProtoVersion, msg.Suite, msg.Type, fromID, payload, priv)
			msg.SigFrom = hex.EncodeToString(sigFrom)
			data, err := proto.EncodeRepayReqMsg(msg)
			if err != nil {
				die("encode message failed", err)
			}
			if err := writeMsg(*outPath, data); err != nil {
				die("write message failed", err)
			}
			return
		}

		fmt.Println("SEND repay-request")
		fmt.Println("contract:", *idHex)
		fmt.Println("reqnonce:", *reqNonce)
		fmt.Println("sigB:", hex.EncodeToString(sig))
		fmt.Println("(paste this to the creditor, then they run: web4 ack --id <id> --reqnonce <n> --sigb <hex>)")

	case "ack":
		fs := flag.NewFlagSet("ack", flag.ExitOnError)
		idHex := fs.String("id", "", "contract id hex")
		reqNonce := fs.Uint64("reqnonce", 1, "request nonce")
		sigBHex := fs.String("sigb", "", "debtor signature hex on RepayReq")
		decision := fs.Int("decision", 1, "1=accept 0=reject")
		forget := fs.Bool("forget", false, "if accept, mark closed (and optionally forget)")
		outPath := fs.String("out", "", "write AckMsg to file and exit")
		_ = fs.Parse(os.Args[2:])

		if *decision != 0 && *decision != 1 {
			die("invalid decision", fmt.Errorf("need 0 or 1"))
		}
		if *decision == 0 && *forget {
			die("invalid forget", fmt.Errorf("forget only allowed on accept"))
		}

		pubA, privA, err := crypto.LoadKeypair(root)
		if err != nil {
			die("load keys failed", err)
		}
		idBytes, err := hex.DecodeString(*idHex)
		if err != nil || len(idBytes) != 32 {
			die("invalid --id", fmt.Errorf("need 32 bytes hex"))
		}
		var cid [32]byte
		copy(cid[:], idBytes)

		reqMsg, err := st.FindRepayReq(*idHex, *reqNonce)
		if err != nil {
			die("find repay request failed", err)
		}
		if reqMsg == nil {
			die("missing repay request", fmt.Errorf("recv a repay request first"))
		}
		if *sigBHex == "" {
			if reqMsg.SigB == "" {
				die("missing sigb", fmt.Errorf("provide --sigb or recv a repay request"))
			}
			*sigBHex = reqMsg.SigB
		}
		sigB, err := hex.DecodeString(*sigBHex)
		if err != nil {
			die("invalid sigb", err)
		}

		c, err := findContractByID(st, cid)
		if err != nil {
			die("contract lookup failed", err)
		}
		if c == nil {
			die("contract lookup failed", fmt.Errorf("contract not found"))
		}
		if !bytes.Equal(c.IOU.Creditor, pubA) {
			die("creditor mismatch", fmt.Errorf("only creditor can ack"))
		}
		ephPub, sealed, err := proto.DecodeSealedFields(reqMsg.EphemeralPub, reqMsg.Sealed)
		if err != nil {
			die("invalid repay request fields", err)
		}
		req := proto.RepayReq{ContractID: cid, ReqNonce: *reqNonce, Close: reqMsg.Close}
		reqSign := proto.RepayReqSignBytes(req, ephPub, sealed)
		if !crypto.Verify(c.IOU.Debtor, crypto.SHA3_256(reqSign), sigB) {
			die("invalid sigb", fmt.Errorf("debtor signature check failed"))
		}

		ack := proto.Ack{
			ContractID: cid,
			ReqNonce:   *reqNonce,
			Decision:   uint8(*decision),
			Close:      *decision == 1,
		}
		ackPayload := proto.AckPayload{
			Type:       proto.MsgTypeAck,
			ContractID: *idHex,
			Decision:   ack.Decision,
			Close:      ack.Close,
		}
		if zkMode() && ack.Decision == 1 {
			ctx, err := ackPayloadContext(ackPayload)
			if err != nil {
				die("encode ack payload failed", err)
			}
			zk, err := buildDeltaProof(c.IOU.Amount, ctx)
			if err != nil {
				die("build zk proof failed", err)
			}
			ackPayload.ZK = zk
		}
		payloadBytes, err := json.Marshal(ackPayload)
		if err != nil {
			die("encode ack payload failed", err)
		}
		ackEph, ackSealed, err := e2eSeal(proto.MsgTypeAck, cid, *reqNonce, c.IOU.Debtor, payloadBytes)
		if err != nil {
			die("e2e seal failed", err)
		}
		ack.EphemeralPub = ackEph
		ack.Sealed = ackSealed

		// v0.0.2: sign over SHA3_256(message)
		ackSign := proto.AckSignBytes(cid, ack.Decision, ack.Close, ackEph, ackSealed)
		sigA := crypto.Sign(privA, crypto.SHA3_256(ackSign))

		if *decision == 1 {
			if err := st.MarkClosed(cid, *forget); err != nil {
				die("mark closed failed", err)
			}
		}
		if err := st.AddAck(ack, sigA); err != nil {
			die("store ack failed", err)
		}

		if *outPath != "" {
			msg := proto.AckMsgFromAck(ack, sigA)
			fromID := node.DeriveNodeID(pubA)
			msg.FromNodeID = hex.EncodeToString(fromID[:])
			payloadMsg := msg
			payloadMsg.SigFrom = ""
			payload, err := proto.EncodeAckMsg(payloadMsg)
			if err != nil {
				die("encode message failed", err)
			}
			sigFrom := sigFromBytes(msg.ProtoVersion, msg.Suite, msg.Type, fromID, payload, privA)
			msg.SigFrom = hex.EncodeToString(sigFrom)
			data, err := proto.EncodeAckMsg(msg)
			if err != nil {
				die("encode message failed", err)
			}
			if err := writeMsg(*outPath, data); err != nil {
				die("write message failed", err)
			}
			return
		}

		fmt.Println("ACK sigA:", hex.EncodeToString(sigA))
		if *decision == 1 {
			fmt.Println("CLOSED", *idHex)
		} else {
			fmt.Println("REJECTED", *idHex)
		}

	case "recv":
		fs := flag.NewFlagSet("recv", flag.ExitOnError)
		inPath := fs.String("in", "", "message file path")
		_ = fs.Parse(os.Args[2:])

		if *inPath == "" {
			die("missing --in", fmt.Errorf("path required"))
		}
		data, err := os.ReadFile(*inPath)
		if err != nil {
			die("read message failed", err)
		}
		runner, err := daemon.NewRunner(root, daemon.Options{Store: st, Checker: checker})
		if err != nil {
			die("load node failed", err)
		}
		payload, err := proto.ReadFrameWithTypeCap(bytes.NewReader(data), proto.SoftMaxFrameSize, proto.MaxSizeForType)
		if err == nil {
			if err := runner.HandleRaw(payload); err != nil {
				if os.Getenv("WEB4_DEBUG") == "1" {
					fmt.Fprintf(os.Stderr, "recv error: %v\n", err)
				}
				dieMsg(invalidMessage)
			}
			return
		}
		if err := runner.HandleRaw(data); err != nil {
			if os.Getenv("WEB4_DEBUG") == "1" {
				fmt.Fprintf(os.Stderr, "recv error: %v\n", err)
			}
			dieMsg(invalidMessage)
		}

	case "quic-listen":
		fs := flag.NewFlagSet("quic-listen", flag.ExitOnError)
		addr := fs.String("addr", "", "listen addr (host:port)")
		_ = fs.Bool("insecure", false, "skip certificate verification (client only)")
		devTLS := fs.Bool("devtls", false, "allow deterministic dev TLS certs (unsafe)")
		_ = fs.Parse(os.Args[2:])
		if *addr == "" {
			die("missing --addr", fmt.Errorf("address required"))
		}
		if !*devTLS {
			dieMsg("dev TLS disabled by default; pass --devtls to enable")
		}
		fmt.Fprintln(os.Stderr, "WARNING: using deterministic dev TLS certificates")
		fmt.Println("QUIC LISTEN", *addr)
		runner, err := daemon.NewRunner(root, daemon.Options{Store: st, Checker: checker})
		if err != nil {
			die("load keys failed", err)
		}
		if err := runner.Run(*addr, *devTLS); err != nil {
			die("quic listen failed", err)
		}

	case "quic-send":
		fs := flag.NewFlagSet("quic-send", flag.ExitOnError)
		addr := fs.String("addr", "", "server addr (host:port)")
		inPath := fs.String("in", "", "message file path")
		insecure := fs.Bool("insecure", false, "skip certificate verification")
		devTLS := fs.Bool("devtls", false, "allow deterministic dev TLS certs (unsafe)")
		devTLSCA := fs.String("devtls-ca", "", "dev TLS CA PEM path")
		_ = fs.Parse(os.Args[2:])
		if *addr == "" {
			die("missing --addr", fmt.Errorf("address required"))
		}
		if *inPath == "" {
			die("missing --in", fmt.Errorf("path required"))
		}
		if !*devTLS {
			dieMsg("dev TLS disabled by default; pass --devtls to enable")
		}
		fmt.Fprintln(os.Stderr, "WARNING: using deterministic dev TLS certificates")
		data, err := os.ReadFile(*inPath)
		if err != nil {
			die("read message failed", err)
		}
		self, err := node.NewNode(root, node.Options{})
		if err != nil {
			die("load node failed", err)
		}
		data, err = ensureSignedOutgoing(data, self)
		if err != nil {
			die("sign message failed", err)
		}
		if err := network.Send(*addr, data, *insecure, *devTLS, *devTLSCA); err != nil {
			die("quic send failed", err)
		}

	case "quic-send-secure":
		fs := flag.NewFlagSet("quic-send-secure", flag.ExitOnError)
		addr := fs.String("addr", "", "server addr (host:port)")
		inPath := fs.String("in", "", "message file path")
		toIDHex := fs.String("to-id", "", "recipient node id hex")
		stdinPaths := fs.Bool("stdin", false, "read message paths from stdin")
		devTLS := fs.Bool("devtls", false, "allow deterministic dev TLS certs (unsafe)")
		devTLSCA := fs.String("devtls-ca", "", "dev TLS CA PEM path")
		_ = fs.Parse(os.Args[2:])
		if *addr == "" {
			die("missing --addr", fmt.Errorf("address required"))
		}
		if *toIDHex == "" {
			die("missing --to-id", fmt.Errorf("recipient node id required"))
		}
		if !*stdinPaths && *inPath == "" {
			die("missing --in", fmt.Errorf("path required"))
		}
		if !*devTLS {
			dieMsg("dev TLS disabled by default; pass --devtls to enable")
		}
		fmt.Fprintln(os.Stderr, "WARNING: using deterministic dev TLS certificates")
		self, err := node.NewNode(root, node.Options{})
		if err != nil {
			die("load node failed", err)
		}
		toBytes, err := hex.DecodeString(*toIDHex)
		if err != nil || len(toBytes) != 32 {
			die("invalid --to-id", fmt.Errorf("need 32 bytes hex"))
		}
		var toID [32]byte
		copy(toID[:], toBytes)
		if err := handshakeWithPeer(self, toID, *addr, *devTLS, *devTLSCA); err != nil {
			die("handshake failed", err)
		}
		sendPath := func(path string) error {
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read message failed: %w", err)
			}
			payload := data
			if framePayload, err := proto.ReadFrameWithTypeCap(bytes.NewReader(data), proto.SoftMaxFrameSize, proto.MaxSizeForType); err == nil {
				payload = framePayload
			}
			payload, err = ensureSignedOutgoing(payload, self)
			if err != nil {
				return fmt.Errorf("sign message failed: %w", err)
			}
			var hdr struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(payload, &hdr); err != nil || hdr.Type == "" {
				return fmt.Errorf("missing message type")
			}
			if hdr.Type == proto.MsgTypeSecureEnvelope {
				return fmt.Errorf("unexpected secure envelope")
			}
			if err := enforceTypeMax(hdr.Type, len(payload)); err != nil {
				return err
			}
			secureOut, err := sealSecureEnvelope(self, toID, hdr.Type, "", payload)
			if err != nil {
				return fmt.Errorf("seal secure envelope failed: %w", err)
			}
			if err := network.Send(*addr, secureOut, false, *devTLS, *devTLSCA); err != nil {
				return fmt.Errorf("quic send failed: %w", err)
			}
			return nil
		}
		if *stdinPaths {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				path := strings.TrimSpace(scanner.Text())
				if path == "" {
					continue
				}
				if err := sendPath(path); err != nil {
					die("quic send secure failed", err)
				}
			}
			if err := scanner.Err(); err != nil {
				die("read stdin failed", err)
			}
			return
		}
		if err := sendPath(*inPath); err != nil {
			die("quic send secure failed", err)
		}

	case "node":
		if len(os.Args) < 3 {
			dieMsg("usage: web4 node <id|list|members|join|add|hello|exchange|invite|revoke|approve-invite>")
		}
		switch os.Args[2] {
		case "id":
			self, err := node.NewNode(root, node.Options{})
			if err != nil {
				die("load node failed", err)
			}
			fmt.Println("node_id:", hex.EncodeToString(self.ID[:]))
			fmt.Println("pub:", hex.EncodeToString(self.PubKey))
		case "list":
			self, err := node.NewNode(root, node.Options{})
			if err != nil {
				die("load node failed", err)
			}
			for _, p := range self.Peers.List() {
				if len(p.PubKey) == 0 {
					fmt.Printf("addr=%s\n", p.Addr)
					continue
				}
				fmt.Printf("%s  %s\n", hex.EncodeToString(p.NodeID[:]), hex.EncodeToString(p.PubKey))
			}
		case "members":
			self, err := node.NewNode(root, node.Options{})
			if err != nil {
				die("load node failed", err)
			}
			for _, id := range self.Members.List() {
				fmt.Println(hex.EncodeToString(id[:]))
			}
		case "join":
			fs := flag.NewFlagSet("node join", flag.ExitOnError)
			nodeIDHex := fs.String("node-id", "", "target node id hex")
			addr := fs.String("addr", "", "target addr (host:port)")
			bundlePath := fs.String("bundle", "", "invite bundle file to process")
			_ = fs.Parse(os.Args[3:])
			self, err := node.NewNode(root, node.Options{})
			if err != nil {
				die("load node failed", err)
			}
			if *bundlePath != "" {
				data, err := os.ReadFile(*bundlePath)
				if err != nil {
					die("read bundle failed", err)
				}
				runner, err := daemon.NewRunner(root, daemon.Options{Store: st, Checker: checker})
				if err != nil {
					die("load node failed", err)
				}
				if err := runner.HandleRaw(data); err != nil {
					die("join failed", err)
				}
				fmt.Println("OK join bundle")
				return
			}
			if *nodeIDHex == "" && *addr == "" {
				die("missing --node-id", fmt.Errorf("node id or addr required"))
			}
			var id [32]byte
			if *nodeIDHex != "" {
				idBytes, err := hex.DecodeString(*nodeIDHex)
				if err != nil || len(idBytes) != 32 {
					die("invalid node id", fmt.Errorf("need 32 bytes hex"))
				}
				copy(id[:], idBytes)
			} else {
				p, ok := findPeerByAddr(self.Peers.List(), *addr)
				if !ok {
					die("missing peer", fmt.Errorf("unknown addr"))
				}
				id = p.NodeID
			}
			if err := self.Members.Add(id, true); err != nil {
				die("join failed", err)
			}
			fmt.Println("OK node joined")
		case "invite":
			fs := flag.NewFlagSet("node invite", flag.ExitOnError)
			to := fs.String("to", "", "invitee pubkey hex or node id hex")
			scopeStr := fs.String("scope", "gossip", "scope: gossip,contract,all")
			powBits := fs.Uint("pow-bits", proto.InvitePoWaDBits, "PoWaD difficulty bits (fixed)")
			expires := fs.Int("expires", 3600, "expires seconds from now")
			_ = fs.Parse(os.Args[3:])
			if *to == "" {
				die("missing --to", fmt.Errorf("invitee pubkey or node id required"))
			}
			if *powBits != proto.InvitePoWaDBits {
				die("invalid --pow-bits", fmt.Errorf("pow bits fixed at %d", proto.InvitePoWaDBits))
			}
			if *expires <= 0 {
				die("invalid --expires", fmt.Errorf("expires must be > 0"))
			}
			scope, err := parseInviteScope(*scopeStr)
			if err != nil {
				die("invalid --scope", err)
			}
			self, err := node.NewNode(root, node.Options{})
			if err != nil {
				die("load node failed", err)
			}
			toBytes, err := hex.DecodeString(*to)
			if err != nil {
				die("invalid --to", fmt.Errorf("hex decode failed"))
			}
			var inviteePub []byte
			var inviteeID [32]byte
			if crypto.IsRSAPublicKey(toBytes) {
				inviteePub = toBytes
				inviteeID = node.DeriveNodeID(inviteePub)
			} else if len(toBytes) == 32 {
				copy(inviteeID[:], toBytes)
				if self.Peers == nil {
					die("missing peer store", fmt.Errorf("peer store unavailable"))
				}
				if p, ok := findPeerByNodeID(self.Peers.List(), inviteeID); ok && len(p.PubKey) > 0 {
					inviteePub = p.PubKey
				} else {
					die("missing invitee pubkey", fmt.Errorf("unknown node id"))
				}
			} else {
				die("invalid --to", fmt.Errorf("need pubkey hex or 32-byte node id"))
			}
			inviteID := make([]byte, 16)
			if _, err := crand.Read(inviteID); err != nil {
				die("invite id failed", err)
			}
			issuedAt := uint64(time.Now().Unix())
			expiresAt := issuedAt + uint64(*expires)
			cert := proto.InviteCert{
				V:          1,
				InviterPub: self.PubKey,
				InviteePub: inviteePub,
				InviteID:   inviteID,
				IssuedAt:   issuedAt,
				ExpiresAt:  expiresAt,
				Scope:      scope,
				PowBits:    proto.InvitePoWaDBits,
			}
			nonce, ok := crypto.PoWaDSolve(inviteID, inviteeID[:], cert.PowBits)
			if !ok {
				die("powad solve failed", fmt.Errorf("nonce search exhausted"))
			}
			cert.PowNonce = nonce
			signBytes, err := proto.EncodeInviteCertForSig(cert)
			if err != nil {
				die("invite sign bytes failed", err)
			}
			sig, err := crypto.SignDigest(self.PrivKey, crypto.SHA3_256(signBytes))
			if err != nil {
				die("invite sign failed", err)
			}
			cert.Sig = sig
			msg := proto.InviteCertMsgFromCert(cert)
			out, err := proto.EncodeInviteCertMsg(msg)
			if err != nil {
				die("encode invite cert failed", err)
			}
			fmt.Println(string(out))
		case "revoke":
			fs := flag.NewFlagSet("node revoke", flag.ExitOnError)
			to := fs.String("to", "", "target node id hex")
			reason := fs.String("reason", "", "revocation reason")
			revokeIDHex := fs.String("revoke-id", "", "revoke id hex (optional)")
			_ = fs.Parse(os.Args[3:])
			if *to == "" {
				die("missing --to", fmt.Errorf("target node id required"))
			}
			self, err := node.NewNode(root, node.Options{})
			if err != nil {
				die("load node failed", err)
			}
			toBytes, err := hex.DecodeString(*to)
			if err != nil || len(toBytes) != 32 {
				die("invalid --to", fmt.Errorf("need 32 bytes hex"))
			}
			var targetID [32]byte
			copy(targetID[:], toBytes)
			var revokeID []byte
			if *revokeIDHex != "" {
				revokeID, err = hex.DecodeString(*revokeIDHex)
				if err != nil || (len(revokeID) != 16 && len(revokeID) != 32) {
					die("invalid --revoke-id", fmt.Errorf("need 16 or 32 bytes hex"))
				}
			} else {
				revokeID = make([]byte, 16)
				if _, err := crand.Read(revokeID); err != nil {
					die("revoke id failed", err)
				}
			}
			issuedAt := uint64(time.Now().Unix())
			signBytes, err := proto.RevokeSignBytes(self.ID, targetID, revokeID, issuedAt, *reason)
			if err != nil {
				die("revoke sign bytes failed", err)
			}
			sig := crypto.Sign(self.PrivKey, crypto.SHA3_256(signBytes))
			msg := proto.RevokeMsg{
				Type:          proto.MsgTypeRevoke,
				RevokerNodeID: hex.EncodeToString(self.ID[:]),
				TargetNodeID:  hex.EncodeToString(targetID[:]),
				Reason:        *reason,
				IssuedAt:      issuedAt,
				RevokeID:      hex.EncodeToString(revokeID),
				Sig:           hex.EncodeToString(sig),
			}
			out, err := proto.EncodeRevokeMsg(msg)
			if err != nil {
				die("encode revoke failed", err)
			}
			fmt.Println(string(out))
		case "approve-invite":
			fs := flag.NewFlagSet("node approve-invite", flag.ExitOnError)
			inviteIDHex := fs.String("invite-id", "", "invite id hex")
			to := fs.String("to", "", "invitee pubkey hex or node id hex")
			scopeStr := fs.String("scope", "gossip", "scope: gossip,contract,all")
			expires := fs.Int("expires", 3600, "expires seconds from now")
			_ = fs.Parse(os.Args[3:])
			if *inviteIDHex == "" {
				die("missing --invite-id", fmt.Errorf("invite id required"))
			}
			if *to == "" {
				die("missing --to", fmt.Errorf("invitee pubkey or node id required"))
			}
			if *expires <= 0 {
				die("invalid --expires", fmt.Errorf("expires must be > 0"))
			}
			scope, err := parseInviteScope(*scopeStr)
			if err != nil {
				die("invalid --scope", err)
			}
			inviteID, err := hex.DecodeString(*inviteIDHex)
			if err != nil || (len(inviteID) != 16 && len(inviteID) != 32) {
				die("invalid --invite-id", fmt.Errorf("need 16 or 32 bytes hex"))
			}
			self, err := node.NewNode(root, node.Options{})
			if err != nil {
				die("load node failed", err)
			}
			toBytes, err := hex.DecodeString(*to)
			if err != nil {
				die("invalid --to", fmt.Errorf("need pubkey or node id hex"))
			}
			var inviteeID [32]byte
			if len(toBytes) == 32 {
				copy(inviteeID[:], toBytes)
			} else if crypto.IsRSAPublicKey(toBytes) {
				inviteeID = node.DeriveNodeID(toBytes)
			} else {
				die("invalid --to", fmt.Errorf("need pubkey or node id hex"))
			}
			expiresAt := uint64(time.Now().Unix() + int64(*expires))
			signBytes, err := proto.InviteApproveSignBytes(inviteID, inviteeID, expiresAt, scope)
			if err != nil {
				die("approval sign bytes failed", err)
			}
			sig := crypto.Sign(self.PrivKey, crypto.SHA3_256(signBytes))
			out := struct {
				InviteID       string `json:"invite_id"`
				InviteeNodeID  string `json:"invitee_node_id"`
				ExpiresAt      uint64 `json:"expires_at"`
				Scope          uint32 `json:"scope"`
				ApproverNodeID string `json:"approver_node_id"`
				Sig            string `json:"sig"`
			}{
				InviteID:       hex.EncodeToString(inviteID),
				InviteeNodeID:  hex.EncodeToString(inviteeID[:]),
				ExpiresAt:      expiresAt,
				Scope:          scope,
				ApproverNodeID: hex.EncodeToString(self.ID[:]),
				Sig:            hex.EncodeToString(sig),
			}
			encoded, err := json.Marshal(out)
			if err != nil {
				die("encode approval failed", err)
			}
			fmt.Println(string(encoded))
		case "add":
			fs := flag.NewFlagSet("node add", flag.ExitOnError)
			addr := fs.String("addr", "", "peer addr (host:port)")
			_ = fs.Parse(os.Args[3:])
			if *addr == "" {
				die("missing --addr", fmt.Errorf("address required"))
			}
			self, err := node.NewNode(root, node.Options{})
			if err != nil {
				die("load node failed", err)
			}
			self.Candidates.Add(*addr)
			fmt.Println("OK node candidate added")
		case "hello":
			fs := flag.NewFlagSet("node hello", flag.ExitOnError)
			addr := fs.String("addr", "", "target addr (host:port)")
			outPath := fs.String("out", "", "write Hello1Msg to file and exit")
			toIDHex := fs.String("to-id", "", "target node id (hex)")
			advertiseAddr := fs.String("advertise-addr", "", "advertise addr (host:port)")
			devTLS := fs.Bool("devtls", false, "allow deterministic dev TLS certs (unsafe)")
			devTLSCA := fs.String("devtls-ca", "", "dev TLS CA PEM path")
			_ = fs.Parse(os.Args[3:])
			if *addr == "" && *outPath == "" {
				die("missing --addr", fmt.Errorf("address required"))
			}
			if *outPath == "" {
				if !*devTLS {
					dieMsg("dev TLS disabled by default; pass --devtls to enable")
				}
				fmt.Fprintln(os.Stderr, "WARNING: using deterministic dev TLS certificates")
			}

			fail := func(msg string, err error) {
				if os.Getenv("WEB4_DEBUG") == "1" {
					die(msg, err)
				}
				if err != nil {
					die(invalidMessage, err)
				}
				dieMsg(invalidMessage)
			}

			self, err := node.NewNode(root, node.Options{})
			if err != nil {
				fail("load node failed", err)
			}
			var toID [32]byte
			if *toIDHex != "" {
				toBytes, err := hex.DecodeString(*toIDHex)
				if err != nil || len(toBytes) != 32 {
					fail("invalid --to-id", fmt.Errorf("need 32 bytes hex"))
				}
				copy(toID[:], toBytes)
			} else if *addr != "" {
				p, ok := findPeerByAddr(self.Peers.List(), *addr)
				if !ok {
					fail("missing peer", fmt.Errorf("unknown addr"))
				}
				toID = p.NodeID
			} else {
				fail("missing --to-id", fmt.Errorf("target node id required"))
			}

			if *outPath != "" {
				msg, err := self.BuildHello1(toID)
				if err != nil {
					fail("build hello1 failed", err)
				}
				msg.FromAddr = *advertiseAddr
				data, err := proto.EncodeHello1Msg(msg)
				if err != nil {
					fail("encode hello1 failed", err)
				}
				if err := enforceTypeMax(proto.MsgTypeHello1, len(data)); err != nil {
					fail("hello1 too large", err)
				}
				if err := writeMsg(*outPath, data); err != nil {
					fail("write hello1 failed", err)
				}
				fmt.Println("OK hello1 written")
				return
			}
			if *advertiseAddr != "" {
				msg, err := self.BuildHello1(toID)
				if err != nil {
					fail("build hello1 failed", err)
				}
				msg.FromAddr = *advertiseAddr
				data, err := proto.EncodeHello1Msg(msg)
				if err != nil {
					fail("encode hello1 failed", err)
				}
				if err := enforceTypeMax(proto.MsgTypeHello1, len(data)); err != nil {
					fail("hello1 too large", err)
				}
				respData, err := network.Exchange(*addr, data, false, *devTLS, *devTLSCA)
				if err != nil {
					fail("handshake failed", err)
				}
				resp, err := proto.DecodeHello2Msg(respData)
				if err != nil {
					fail("decode hello2 failed", err)
				}
				if err := self.HandleHello2(resp); err != nil {
					fail("handshake failed", err)
				}
			} else if err := handshakeWithPeer(self, toID, *addr, *devTLS, *devTLSCA); err != nil {
				fail("handshake failed", err)
			}
			self.Candidates.Add(*addr)
			fmt.Println("OK handshake complete")
		case "exchange":
			fs := flag.NewFlagSet("node exchange", flag.ExitOnError)
			addr := fs.String("addr", "", "target addr (host:port)")
			k := fs.Int("k", defaultPeerExchangeK, "max peers to request")
			toIDHex := fs.String("to-id", "", "target node id (hex)")
			devTLS := fs.Bool("devtls", false, "allow deterministic dev TLS certs (unsafe)")
			devTLSCA := fs.String("devtls-ca", "", "dev TLS CA PEM path")
			_ = fs.Parse(os.Args[3:])
			if *addr == "" {
				die("missing --addr", fmt.Errorf("address required"))
			}
			if !*devTLS {
				dieMsg("dev TLS disabled by default; pass --devtls to enable")
			}
			fmt.Fprintln(os.Stderr, "WARNING: using deterministic dev TLS certificates")

			fail := func(msg string, err error) {
				reason := msg
				if err != nil {
					reason = fmt.Sprintf("%s: %v", msg, err)
				}
				fmt.Fprintf(os.Stderr, "gossip push failed: %s\n", reason)
				if os.Getenv("WEB4_DEBUG") == "1" && err != nil {
					die(msg, err)
				}
				os.Exit(1)
			}

			self, err := node.NewNode(root, node.Options{})
			if err != nil {
				fail("load node failed", err)
			}
			var p peer.Peer
			if *toIDHex != "" {
				toBytes, err := hex.DecodeString(*toIDHex)
				if err != nil || len(toBytes) != 32 {
					fail("invalid --to-id", fmt.Errorf("need 32 bytes hex"))
				}
				copy(p.NodeID[:], toBytes)
				p.Addr = *addr
			} else {
				var ok bool
				p, ok = findPeerByAddr(self.Peers.List(), *addr)
				if !ok {
					fail("missing peer", fmt.Errorf("unknown addr"))
				}
			}
			if !self.Sessions.Has(p.NodeID) {
				if err := handshakeWithPeer(self, p.NodeID, *addr, *devTLS, *devTLSCA); err != nil {
					fail("handshake failed", err)
				}
			}
			if os.Getenv("WEB4_DEBUG") == "1" {
				fmt.Fprintln(os.Stderr, "sending peer_exchange_req")
			}
			reqK := *k
			if reqK <= 0 {
				reqK = defaultPeerExchangeK
			}
			if reqK > maxPeerExchangeK {
				reqK = maxPeerExchangeK
			}
			req := proto.PeerExchangeReqMsg{
				Type:         proto.MsgTypePeerExchangeReq,
				ProtoVersion: proto.ProtoVersion,
				Suite:        proto.Suite,
				K:            reqK,
			}
			req.FromNodeID = hex.EncodeToString(self.ID[:])
			data, err := proto.EncodePeerExchangeReq(req)
			if err != nil {
				fail("encode peer exchange req failed", err)
			}
			if err := enforceTypeMax(proto.MsgTypePeerExchangeReq, len(data)); err != nil {
				fail("peer exchange req too large", err)
			}
			secureReq, err := sealSecureEnvelope(self, p.NodeID, proto.MsgTypePeerExchangeReq, "", data)
			if err != nil {
				fail("missing session", err)
			}
			respData, err := network.Exchange(*addr, secureReq, false, *devTLS, *devTLSCA)
			if err != nil {
				fail("peer exchange failed", err)
			}
			env, err := proto.DecodeSecureEnvelope(respData)
			if err != nil {
				fail("decode secure envelope failed", err)
			}
			msgType, plain, _, err := openSecureEnvelope(self, env)
			if err != nil {
				fail("open secure envelope failed", err)
			}
			if msgType != proto.MsgTypePeerExchangeResp {
				fail("unexpected response type", fmt.Errorf("got %s", msgType))
			}
			if err := enforceTypeMax(proto.MsgTypePeerExchangeResp, len(plain)); err != nil {
				fail("peer exchange resp too large", err)
			}
			resp, err := proto.DecodePeerExchangeResp(plain)
			if err != nil {
				fail("decode peer exchange resp failed", err)
			}
			added, err := applyPeerExchangeResp(self, resp)
			if err != nil {
				fail("apply peer exchange resp failed", err)
			}
			fmt.Printf("OK node exchange (%d added)\n", added)
		default:
			dieMsg("usage: web4 node <id|list|members|join|add|hello|exchange|invite|revoke|approve-invite>")
		}

	case "gossip":
		if len(os.Args) < 3 {
			dieMsg("usage: web4 gossip <push>")
		}
		switch os.Args[2] {
		case "push":
			fs := flag.NewFlagSet("gossip push", flag.ExitOnError)
			addr := fs.String("addr", "", "target addr (host:port)")
			inPath := fs.String("in", "", "envelope file path")
			devTLS := fs.Bool("devtls", false, "allow deterministic dev TLS certs (unsafe)")
			devTLSCA := fs.String("devtls-ca", "", "dev TLS CA PEM path")
			_ = fs.Parse(os.Args[3:])
			if *addr == "" {
				die("missing --addr", fmt.Errorf("address required"))
			}
			if *inPath == "" {
				die("missing --in", fmt.Errorf("path required"))
			}
			if !*devTLS {
				dieMsg("dev TLS disabled by default; pass --devtls to enable")
			}
			fmt.Fprintln(os.Stderr, "WARNING: using deterministic dev TLS certificates")

			fail := func(msg string, err error) {
				if os.Getenv("WEB4_DEBUG") == "1" {
					die(msg, err)
				}
				dieMsg(invalidMessage)
			}

			data, err := os.ReadFile(*inPath)
			if err != nil {
				fail("read envelope failed", err)
			}
			inType := ""
			var inHdr struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(data, &inHdr) == nil {
				inType = inHdr.Type
			}
			hsID := handshakeSuiteIDLabel(data)
			fmt.Fprintf(os.Stderr, "OUTBOUND input type=%s bytes=%d handshake_suite_id=%s preview=%s\n", inType, len(data), hsID, previewBytes(data, 80))
			self, err := node.NewNode(root, node.Options{})
			if err != nil {
				fail("load node failed", err)
			}
			p, ok := findPeerByAddr(self.Peers.List(), *addr)
			if !ok || len(p.PubKey) == 0 {
				fail("missing peer pubkey", fmt.Errorf("peer for addr required"))
			}
			out, err := buildGossipPushForPeer(p, data, gossipHops(), self)
			if err != nil {
				fail("encode gossip push failed", err)
			}
			outType := ""
			var outHdr struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(out, &outHdr) == nil {
				outType = outHdr.Type
			}
			fmt.Fprintf(os.Stderr, "OUTBOUND top-level type=%s bytes=%d to=%s handshake_suite_id=%s preview=%s\n", outType, len(out), *addr, hsID, previewBytes(out, 80))
			if os.Getenv("WEB4_CHECK6_ACK") == "1" {
				resp, err := network.Exchange(*addr, out, false, *devTLS, *devTLSCA)
				if err != nil {
					fmt.Fprintf(os.Stderr, "GOSSIP_ACK status=error err=%v\n", err)
				} else if len(resp) == 0 {
					fmt.Fprintln(os.Stderr, "GOSSIP_ACK status=empty")
				} else if ack, err := proto.DecodeGossipAckMsg(resp); err != nil {
					fmt.Fprintf(os.Stderr, "GOSSIP_ACK status=error err=%v\n", err)
				} else {
					fmt.Fprintf(os.Stderr, "GOSSIP_ACK status=ok sha256=%s from_node_id=%s\n", ack.Sha256, ack.FromNodeID)
				}
			} else if err := network.Send(*addr, out, false, *devTLS, *devTLSCA); err != nil {
				fail("gossip push failed", err)
			}
			fmt.Println("OK gossip push sent")
			os.Exit(0)
		default:
			dieMsg("usage: web4 gossip <push>")
		}

	default:
		fmt.Println("unknown command")
		os.Exit(1)
	}
}
