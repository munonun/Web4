// cmd/web4/main.go
package main

import (
	"bytes"
	"container/list"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	mrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"web4mvp/internal/crypto"
	"web4mvp/internal/math4"
	"web4mvp/internal/network"
	"web4mvp/internal/node"
	"web4mvp/internal/peer"
	"web4mvp/internal/proto"
	"web4mvp/internal/store"
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

func e2eSeal(msgType string, contractID [32]byte, reqNonce uint64, peerEdPub, payload []byte) ([]byte, []byte, error) {
	eph, err := crypto.GenerateEphemeral()
	if err != nil {
		return nil, nil, err
	}
	defer eph.Destroy()
	peerXPub, err := crypto.Ed25519PubToX25519(peerEdPub)
	if err != nil {
		return nil, nil, err
	}
	ephPub, err := eph.Public()
	if err != nil {
		return nil, nil, err
	}
	shared, err := eph.Shared(peerXPub)
	if err != nil {
		return nil, nil, err
	}
	key, err := crypto.DeriveKeyE(shared, "web4:v0:e2e:"+msgType, crypto.XKeySize)
	if err != nil {
		return nil, nil, err
	}
	nonce := e2eNonce(contractID, reqNonce, ephPub)
	sealed, err := crypto.XSealWithNonce(key, nonce, payload, nil)
	if err != nil {
		return nil, nil, err
	}
	return ephPub, sealed, nil
}

func e2eOpen(msgType string, contractID [32]byte, reqNonce uint64, selfEdPriv, ephPub, sealed []byte) ([]byte, error) {
	privX, err := crypto.Ed25519PrivToX25519(selfEdPriv)
	if err != nil {
		return nil, err
	}
	shared, err := crypto.X25519Shared(privX, ephPub)
	if err != nil {
		return nil, err
	}
	key, err := crypto.DeriveKeyE(shared, "web4:v0:e2e:"+msgType, crypto.XKeySize)
	if err != nil {
		return nil, err
	}
	nonce := e2eNonce(contractID, reqNonce, ephPub)
	return crypto.XOpen(key, nonce, sealed, nil)
}

func e2eNonce(contractID [32]byte, reqNonce uint64, ephPub []byte) []byte {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], reqNonce)
	buf := make([]byte, 0, len("web4:v0:nonce|")+32+8+len(ephPub))
	buf = append(buf, []byte("web4:v0:nonce|")...)
	buf = append(buf, contractID[:]...)
	buf = append(buf, tmp[:]...)
	buf = append(buf, ephPub...)
	sum := crypto.SHA3_256(buf)
	return sum[:crypto.XNonceSize]
}

type recvError struct {
	msg string
	err error
}

func (e recvError) Error() string {
	return fmt.Sprintf("%s: %v", e.msg, e.err)
}

func updateFromParties(a, b []byte, v uint64) (math4.Update, error) {
	if len(a) != 32 || len(b) != 32 {
		return math4.Update{}, fmt.Errorf("invalid party id length")
	}
	if v > math.MaxInt64 {
		return math4.Update{}, fmt.Errorf("delta too large")
	}
	var A, B [32]byte
	copy(A[:], a)
	copy(B[:], b)
	return math4.Update{A: A, B: B, V: int64(v)}, nil
}

func recvData(data []byte, st *store.Store, self *node.Node, checker math4.LocalChecker) *recvError {
	_, _, err := recvDataWithResponse(data, st, self, checker, "")
	return err
}

func recvDataWithResponse(data []byte, st *store.Store, self *node.Node, checker math4.LocalChecker, senderAddr string) ([]byte, bool, *recvError) {
	var hdr struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &hdr); err != nil {
		return nil, false, &recvError{msg: "decode message type failed", err: err}
	}
	if err := enforceTypeMax(hdr.Type, len(data)); err != nil {
		return nil, false, &recvError{msg: "message too large", err: err}
	}
	if self == nil {
		return nil, false, &recvError{msg: "node unavailable", err: fmt.Errorf("missing node")}
	}
	if hdr.Type == proto.MsgTypeGossipPush {
		resp, newState, err := handleGossipPush(data, st, self, checker, senderAddr)
		if err != nil {
			return nil, false, err
		}
		return resp, newState, nil
	}
	if senderAddr != "" && hdr.Type != proto.MsgTypeNodeHello && hdr.Type != proto.MsgTypeGossipPush {
		if err := verifySignedMessage(data, hdr.Type, self); err != nil {
			return nil, false, err
		}
	}

	switch hdr.Type {
	case proto.MsgTypeNodeHello:
		m, err := proto.DecodeNodeHelloMsg(data)
		if err != nil {
			return nil, false, &recvError{msg: "decode node hello failed", err: err}
		}
		peerInfo, err := node.VerifyHello(m)
		if err != nil {
			return nil, false, &recvError{msg: "invalid node hello", err: err}
		}
		if peerInfo.Addr == "" && senderAddr != "" {
			peerAddr := ""
			if self.Candidates != nil {
				if candidateAddr, ok := candidateAddrForSender(self.Candidates, senderAddr); ok {
					peerAddr = candidateAddr
				}
			}
			if peerAddr != "" {
				peerInfo.Addr = peerAddr
			}
		}
		if existing, ok := findPeerByNodeID(self.Peers.List(), peerInfo.NodeID); ok && peerInfo.Addr == "" {
			peerInfo.Addr = existing.Addr
		}
		exists := hasPeerID(self.Peers.List(), peerInfo.NodeID)
		if err := self.Peers.Upsert(peerInfo, true); err != nil {
			return nil, false, &recvError{msg: "store peer failed", err: err}
		}
		fmt.Println("RECV NODE HELLO", hex.EncodeToString(peerInfo.NodeID[:]))
		return nil, !exists, nil

	case proto.MsgTypePeerExchangeReq:
		req, err := proto.DecodePeerExchangeReq(data)
		if err != nil {
			return nil, false, &recvError{msg: "decode peer exchange req failed", err: err}
		}
		resp, err := buildPeerExchangeResp(self, req.K)
		if err != nil {
			return nil, false, &recvError{msg: "peer exchange failed", err: err}
		}
		respData, err := proto.EncodePeerExchangeResp(resp)
		if err != nil {
			return nil, false, &recvError{msg: "encode peer exchange resp failed", err: err}
		}
		if err := enforceTypeMax(proto.MsgTypePeerExchangeResp, len(respData)); err != nil {
			return nil, false, &recvError{msg: "peer exchange resp too large", err: err}
		}
		return respData, false, nil

	case proto.MsgTypePeerExchangeResp:
		resp, err := proto.DecodePeerExchangeResp(data)
		if err != nil {
			return nil, false, &recvError{msg: "decode peer exchange resp failed", err: err}
		}
		added, err := applyPeerExchangeResp(self, resp)
		if err != nil {
			return nil, false, &recvError{msg: "apply peer exchange resp failed", err: err}
		}
		fmt.Println("RECV PEER EXCHANGE", added)
		return nil, false, nil

	case proto.MsgTypeGossipPush:
		return nil, false, nil

	case proto.MsgTypeContractOpen:
		m, err := proto.DecodeContractOpenMsg(data)
		if err != nil {
			return nil, false, &recvError{msg: "decode contract open failed", err: err}
		}
		if err := proto.ValidateWireMeta(m.ProtoVersion, m.Suite); err != nil {
			return nil, false, &recvError{msg: "invalid wire metadata", err: err}
		}
		c, err := proto.ContractFromOpenMsg(m)
		if err != nil {
			return nil, false, &recvError{msg: "invalid contract open", err: err}
		}
		id := proto.ContractID(c.IOU)
		if !crypto.Verify(c.IOU.Debtor, crypto.SHA3_256(proto.OpenSignBytes(c.IOU, c.EphemeralPub, c.Sealed)), c.SigDebt) {
			return nil, false, &recvError{msg: "invalid sigb", err: fmt.Errorf("debtor signature check failed")}
		}
		plain, err := e2eOpen(proto.MsgTypeContractOpen, id, 0, self.PrivKey, c.EphemeralPub, c.Sealed)
		if err != nil {
			return nil, false, &recvError{msg: "sealed open failed", err: err}
		}
		var p proto.OpenPayload
		if err := json.Unmarshal(plain, &p); err != nil {
			return nil, false, &recvError{msg: "decode open payload failed", err: err}
		}
		if p.Type != proto.MsgTypeContractOpen ||
			!strings.EqualFold(p.Creditor, m.Creditor) ||
			!strings.EqualFold(p.Debtor, m.Debtor) ||
			p.Amount != m.Amount ||
			p.Nonce != m.Nonce {
			return nil, false, &recvError{msg: "open payload mismatch", err: fmt.Errorf("payload/header mismatch")}
		}
		if existing, _ := findContractByID(st, id); existing != nil {
			if existing.Status == "CLOSED" {
				return nil, false, &recvError{msg: "contract already closed", err: fmt.Errorf("cannot reopen closed contract")}
			}
			fmt.Println("RECV OPEN duplicate", hex.EncodeToString(id[:]))
			return nil, false, nil
		}
		update, err := updateFromParties(c.IOU.Debtor, c.IOU.Creditor, c.IOU.Amount)
		if err != nil {
			return nil, false, &recvError{msg: "invalid update", err: err}
		}
		if err := checker.Check(update); err != nil {
			return nil, false, &recvError{msg: "local constraint rejected", err: err}
		}
		if err := st.AddContract(c); err != nil {
			return nil, false, &recvError{msg: "store contract failed", err: err}
		}
		fmt.Println("RECV OPEN", hex.EncodeToString(id[:]))
		return nil, true, nil

	case proto.MsgTypeRepayReq:
		m, err := proto.DecodeRepayReqMsg(data)
		if err != nil {
			return nil, false, &recvError{msg: "decode repay request failed", err: err}
		}
		if err := proto.ValidateWireMeta(m.ProtoVersion, m.Suite); err != nil {
			return nil, false, &recvError{msg: "invalid wire metadata", err: err}
		}
		req, sigB, err := proto.RepayReqFromMsg(m)
		if err != nil {
			return nil, false, &recvError{msg: "invalid repay request", err: err}
		}
		cidBytes, err := hex.DecodeString(m.ContractID)
		if err != nil || len(cidBytes) != 32 {
			return nil, false, &recvError{msg: "invalid contract id", err: fmt.Errorf("bad contract_id")}
		}
		var cid [32]byte
		copy(cid[:], cidBytes)
		c, err := findContractByID(st, cid)
		if err != nil {
			return nil, false, &recvError{msg: "contract lookup failed", err: err}
		}
		if c == nil {
			return nil, false, &recvError{msg: "unknown contract", err: fmt.Errorf("missing contract for repay request")}
		}
		if c.Status == "CLOSED" {
			return nil, false, &recvError{msg: "contract already closed", err: fmt.Errorf("reject repay request")}
		}
		ephPub, sealed, err := proto.DecodeSealedFields(m.EphemeralPub, m.Sealed)
		if err != nil {
			return nil, false, &recvError{msg: "invalid repay request fields", err: err}
		}
		reqSign := proto.RepayReqSignBytes(req, ephPub, sealed)
		if !crypto.Verify(c.IOU.Debtor, crypto.SHA3_256(reqSign), sigB) {
			return nil, false, &recvError{msg: "invalid sigb", err: fmt.Errorf("debtor signature check failed")}
		}
		plain, err := e2eOpen(proto.MsgTypeRepayReq, cid, req.ReqNonce, self.PrivKey, ephPub, sealed)
		if err != nil {
			return nil, false, &recvError{msg: "sealed repay request failed", err: err}
		}
		var p proto.RepayPayload
		if err := json.Unmarshal(plain, &p); err != nil {
			return nil, false, &recvError{msg: "decode repay payload failed", err: err}
		}
		if p.Type != proto.MsgTypeRepayReq ||
			!strings.EqualFold(p.ContractID, m.ContractID) ||
			p.ReqNonce != m.ReqNonce ||
			p.Close != m.Close {
			return nil, false, &recvError{msg: "repay payload mismatch", err: fmt.Errorf("payload/header mismatch")}
		}
		if exists, err := st.HasRepayReq(m.ContractID, m.ReqNonce); err == nil && exists {
			fmt.Println("RECV REPAY-REQ duplicate", m.ContractID)
			return nil, false, nil
		}
		if maxNonce, ok, err := st.MaxRepayReqNonce(m.ContractID); err != nil {
			return nil, false, &recvError{msg: "repay request scan failed", err: err}
		} else if ok && req.ReqNonce <= maxNonce {
			return nil, false, &recvError{msg: "repay req nonce out of order", err: fmt.Errorf("non-monotonic reqnonce")}
		}
		if err := st.AddRepayReqIfNew(m); err != nil {
			return nil, false, &recvError{msg: "store repay request failed", err: err}
		}
		fmt.Println("RECV REPAY-REQ", m.ContractID)
		return nil, true, nil

	case proto.MsgTypeAck:
		m, err := proto.DecodeAckMsg(data)
		if err != nil {
			return nil, false, &recvError{msg: "decode ack failed", err: err}
		}
		if err := proto.ValidateWireMeta(m.ProtoVersion, m.Suite); err != nil {
			return nil, false, &recvError{msg: "invalid wire metadata", err: err}
		}
		a, sigA, err := proto.AckFromMsg(m)
		if err != nil {
			return nil, false, &recvError{msg: "invalid ack", err: err}
		}
		c, err := findContractByID(st, a.ContractID)
		if err != nil {
			return nil, false, &recvError{msg: "contract lookup failed", err: err}
		}
		if c == nil {
			return nil, false, &recvError{msg: "unknown contract", err: fmt.Errorf("missing contract for ack")}
		}
		if c.Status == "CLOSED" {
			return nil, false, &recvError{msg: "contract already closed", err: fmt.Errorf("reject ack")}
		}
		maxNonce, ok, err := st.MaxRepayReqNonce(m.ContractID)
		if err != nil {
			return nil, false, &recvError{msg: "repay req scan failed", err: err}
		}
		if !ok {
			return nil, false, &recvError{msg: "missing repay request", err: fmt.Errorf("ack without repay request")}
		}
		reqMsg, err := st.FindRepayReq(m.ContractID, maxNonce)
		if err != nil {
			return nil, false, &recvError{msg: "repay req lookup failed", err: err}
		}
		if reqMsg == nil {
			return nil, false, &recvError{msg: "missing repay request", err: fmt.Errorf("ack without repay request")}
		}
		ackSign := proto.AckSignBytes(a.ContractID, a.Decision, a.Close, a.EphemeralPub, a.Sealed)
		if !crypto.Verify(c.IOU.Creditor, crypto.SHA3_256(ackSign), sigA) {
			return nil, false, &recvError{msg: "invalid siga", err: fmt.Errorf("creditor signature check failed")}
		}
		if reqMsg.Close != a.Close {
			return nil, false, &recvError{msg: "ack close mismatch", err: fmt.Errorf("close flag mismatch")}
		}
		plain, err := e2eOpen(proto.MsgTypeAck, a.ContractID, maxNonce, self.PrivKey, a.EphemeralPub, a.Sealed)
		if err != nil {
			return nil, false, &recvError{msg: "sealed ack failed", err: err}
		}
		var p proto.AckPayload
		if err := json.Unmarshal(plain, &p); err != nil {
			return nil, false, &recvError{msg: "decode ack payload failed", err: err}
		}
		if p.Type != proto.MsgTypeAck ||
			!strings.EqualFold(p.ContractID, m.ContractID) ||
			p.Decision != m.Decision ||
			p.Close != m.Close {
			return nil, false, &recvError{msg: "ack payload mismatch", err: fmt.Errorf("payload/header mismatch")}
		}
		a.ReqNonce = maxNonce
		if exists, err := st.HasAck(m.ContractID, maxNonce); err == nil && exists {
			fmt.Println("RECV ACK duplicate", m.ContractID)
			return nil, false, nil
		}
		if a.Decision == 1 {
			update, err := updateFromParties(c.IOU.Creditor, c.IOU.Debtor, c.IOU.Amount)
			if err != nil {
				return nil, false, &recvError{msg: "invalid update", err: err}
			}
			if err := checker.Check(update); err != nil {
				return nil, false, &recvError{msg: "local constraint rejected", err: err}
			}
		}
		if err := st.AddAckIfNew(a, sigA); err != nil {
			return nil, false, &recvError{msg: "store ack failed", err: err}
		}
		if a.Decision == 1 {
			if err := st.MarkClosed(a.ContractID, false); err != nil {
				return nil, false, &recvError{msg: "mark closed failed", err: err}
			}
		}
		fmt.Println("RECV ACK", m.ContractID)
		return nil, true, nil

	default:
		return nil, false, &recvError{msg: "unknown message type", err: fmt.Errorf("%s", hdr.Type)}
	}
	return nil, false, nil
}

var gossipSeen = newGossipCache(gossipCacheCap, gossipCacheTTL)
var gossipRand = mrand.New(mrand.NewSource(time.Now().UnixNano()))
var gossipRandMu sync.Mutex

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

func mustX25519Pub(pub []byte) []byte {
	xpub, err := crypto.Ed25519PubToX25519(pub)
	if err != nil {
		return nil
	}
	return xpub
}

func x25519PubFromEd25519Priv(priv []byte) []byte {
	privX, err := crypto.Ed25519PrivToX25519(priv)
	if err != nil {
		return nil
	}
	k, err := ecdh.X25519().NewPrivateKey(privX)
	if err != nil {
		return nil
	}
	return k.PublicKey().Bytes()
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
	msg, err := proto.DecodeGossipPushMsg(data)
	if err != nil {
		return nil, false, &recvError{msg: "decode gossip push failed", err: err}
	}
	gossipDebugf("recv gossip_push from addr=%s from_node_id=%s hops=%d", senderAddr, msg.FromNodeID, msg.Hops)
	if self == nil || self.Peers == nil {
		return nil, false, &recvError{msg: "node unavailable", err: fmt.Errorf("peer store unavailable")}
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
		return nil, false, nil
	}
	forwarder, ok := findPeerByNodeID(self.Peers.List(), fromID)
	if !ok || len(forwarder.PubKey) == 0 {
		gossipDebugf("drop gossip_push: unknown forwarder node_id=%x addr=%s", fromID[:], senderAddr)
		return nil, false, nil
	}
	gossipDebugf("gossip_push forwarder node_id=%x addr=%s", fromID[:], senderAddr)
	gossipDebugf("gossip_push recv msg.from_node_id=%x sender_pub_node_id=%s sender_pub_hash=%s", fromID[:], nodeIDHexFromPub(forwarder.PubKey), nodeIDHexFromPub(forwarder.PubKey))
	if self.Members == nil || !self.Members.Has(fromID) {
		gossipDebugf("drop gossip_push: forwarder not member node_id=%x", fromID[:])
		return nil, false, nil
	}
	gossipDebugf("gossip_push forwarder ok node_id=%x", fromID[:])
	sig, err := decodeSigHex(msg.SigFrom)
	if err != nil {
		gossipDebugf("drop gossip_push: bad sig_from")
		return nil, false, nil
	}
	payloadMsg := msg
	payloadMsg.SigFrom = ""
	payload, err := proto.EncodeGossipPushMsg(payloadMsg)
	if err != nil {
		return nil, false, &recvError{msg: "encode gossip push failed", err: err}
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
		gossipDebugf("drop gossip_push: sig verify failed node_id=%x", fromID[:])
		return nil, false, nil
	}
	gossipDebugf("gossip_push sig verify ok node_id=%x", fromID[:])
	ephPub, sealed, err := proto.DecodeSealedFields(msg.EphemeralPub, msg.Sealed)
	if err != nil {
		gossipDebugf("drop gossip_push: bad sealed fields err=%v", err)
		return nil, false, &recvError{msg: "decode gossip envelope failed", err: err}
	}
	var zero [32]byte
	nonce := e2eNonce(zero, 0, ephPub)
	noncePrefix := nonce
	if len(noncePrefix) > 8 {
		noncePrefix = noncePrefix[:8]
	}
	selfPubNodeID := nodeIDHexFromPub(self.PubKey)
	selfXPubHash := hashHex(mustX25519Pub(self.PubKey))
	selfXPubFromPrivHash := hashHex(x25519PubFromEd25519Priv(self.PrivKey))
	gossipDebugf("gossip_push self_node_id=%x self_ed25519_pub_node_id=%s self_x25519_pub_hash=%s self_x25519_pub_hash_from_priv=%s", self.ID[:], selfPubNodeID, selfXPubHash, selfXPubFromPrivHash)
	if selfXPubHash != "" && selfXPubFromPrivHash != "" && selfXPubHash != selfXPubFromPrivHash {
		gossipDebugf("gossip_push self x25519 pub mismatch")
	}
	gossipDebugf("gossip_push open using msg.from_node_id=%x sender_pub_node_id=%s sender_x25519_pub_hash=%s nonce_len=%d nonce_hex=%s aad_len=0", fromID[:], nodeIDHexFromPub(forwarder.PubKey), hashHex(mustX25519Pub(forwarder.PubKey)), len(nonce), hex.EncodeToString(noncePrefix))
	envelope, err := e2eOpen(proto.MsgTypeGossipPush, zero, 0, self.PrivKey, ephPub, sealed)
	if err != nil {
		gossipDebugf("gossip_push open failed msg.from_node_id=%x sender_pub_node_id=%s sender_x25519_pub_hash=%s", fromID[:], nodeIDHexFromPub(forwarder.PubKey), hashHex(mustX25519Pub(forwarder.PubKey)))
		gossipDebugf("drop gossip_push: envelope open failed err=%v", err)
		return nil, false, &recvError{msg: "decode gossip envelope failed", err: err}
	}
	if os.Getenv("WEB4_DEBUG") == "1" {
		var hdr struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal(envelope, &hdr)
		gossipDebugf("gossip_push opened payload_len=%d type=%s", len(envelope), hdr.Type)
	}
	var hash [32]byte
	hashInput := make([]byte, 0, len(envelope)+len(self.ID))
	hashInput = append(hashInput, envelope...)
	hashInput = append(hashInput, self.ID[:]...)
	copy(hash[:], crypto.SHA3_256(hashInput))
	if gossipSeen.Seen(hash) {
		gossipDebugf("drop gossip_push: already seen hash=%x", hash[:])
		return nil, false, nil
	}
	gossipDebugf("gossip_push new hash=%x", hash[:])
	_, newState, innerErr := recvDataWithResponse(envelope, st, self, checker, "")
	if innerErr != nil {
		gossipDebugf("drop gossip_push: payload recv failed err=%v", innerErr)
		return nil, false, &recvError{msg: "gossip payload failed", err: innerErr}
	}
	gossipSeen.Add(hash)
	if !newState {
		gossipDebugf("drop gossip_push: payload produced no new state")
		return nil, false, nil
	}
	gossipDebugf("forward gossip_push: peers=%d", len(self.Peers.List()))
	forwardGossip(msg, envelope, self, senderAddr)
	return nil, true, nil
}

func forwardGossip(msg proto.GossipPushMsg, envelope []byte, self *node.Node, senderAddr string) {
	if self == nil || self.Peers == nil {
		return
	}
	hops := msg.Hops
	if hops <= 0 {
		hops = gossipHops()
	}
	if hops <= 1 {
		gossipDebugf("skip gossip_forward: hops=%d", hops)
		return
	}
	fanout := gossipFanout()
	if fanout <= 0 {
		gossipDebugf("skip gossip_forward: fanout=%d", fanout)
		return
	}
	candidates := filterGossipPeers(self.Peers.List(), senderAddr)
	if len(candidates) == 0 {
		gossipDebugf("skip gossip_forward: no candidates")
		return
	}
	gossipDebugf("gossip_forward candidates=%d fanout=%d hops=%d", len(candidates), fanout, hops)
	gossipDebugf("gossip_forward self_node_id=%x signing_pub_node_id=%s sealing_priv_node_id=%x", self.ID[:], nodeIDHexFromPub(self.PubKey), self.ID[:])
	selected := pickRandomPeers(candidates, fanout)
	if len(selected) == 0 {
		gossipDebugf("skip gossip_forward: empty selection")
		return
	}
	for _, p := range selected {
		if p.Addr == "" || isZeroNodeID(p.NodeID) {
			continue
		}
		if mapped, ok := findPeerByAddr(self.Peers.List(), p.Addr); ok && mapped.NodeID != p.NodeID {
			gossipDebugf("gossip forward drop: addr node_id mismatch addr=%s want=%x got=%x", p.Addr, p.NodeID[:], mapped.NodeID[:])
			continue
		}
		peerForSeal := p
		if byID, ok := findPeerByNodeID(self.Peers.List(), p.NodeID); ok && len(byID.PubKey) > 0 {
			peerForSeal = byID
			peerForSeal.Addr = p.Addr
		}
		if len(peerForSeal.PubKey) == 0 {
			gossipDebugf("gossip forward skip: missing pubkey node_id=%x addr=%s", p.NodeID[:], p.Addr)
			continue
		}
		gossipDebugf("gossip_forward target_peer_node_id=%x target_peer_pub_node_id=%s", peerForSeal.NodeID[:], nodeIDHexFromPub(peerForSeal.PubKey))
		out, err := buildGossipPushForPeer(peerForSeal, envelope, hops-1, self)
		if err != nil {
			gossipDebugf("gossip forward skip: node_id=%x addr=%s err=%v", p.NodeID[:], p.Addr, err)
			continue
		}
		gossipDebugf("forward seal ok to node_id=%x addr=%s", p.NodeID[:], p.Addr)
		if err := network.Send(p.Addr, out, false, true, ""); err != nil {
			gossipDebugf("gossip forward failed: node_id=%x addr=%s err=%v", p.NodeID[:], p.Addr, err)
			if os.Getenv("WEB4_DEBUG") == "1" {
				fmt.Fprintf(os.Stderr, "gossip forward failed: %v\n", err)
			}
			continue
		}
		gossipDebugf("gossip forward ok: node_id=%x addr=%s", p.NodeID[:], p.Addr)
	}
}

func filterGossipPeers(peers []peer.Peer, excludeAddr string) []peer.Peer {
	out := make([]peer.Peer, 0, len(peers))
	for _, p := range peers {
		if p.Addr == "" || len(p.PubKey) == 0 {
			continue
		}
		if excludeAddr != "" && p.Addr == excludeAddr {
			continue
		}
		out = append(out, p)
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
		gossipDebugf("gossip seal sender mismatch sender_ed25519_node_id=%x derived=%x", self.ID[:], selfDerived[:])
	}
	senderXPubHash := hashHex(mustX25519Pub(self.PubKey))
	recipientXPubHash := hashHex(mustX25519Pub(p.PubKey))
	gossipDebugf("gossip seal sender_ed25519_node_id=%x sender_x25519_pub_hash=%s recipient_peer_node_id=%x recipient_x25519_pub_hash=%s", self.ID[:], senderXPubHash, p.NodeID[:], recipientXPubHash)
	var zero [32]byte
	ephPub, sealed, err := e2eSeal(proto.MsgTypeGossipPush, zero, 0, p.PubKey, envelope)
	if err != nil {
		return nil, err
	}
	nonce := e2eNonce(zero, 0, ephPub)
	noncePrefix := nonce
	if len(noncePrefix) > 8 {
		noncePrefix = noncePrefix[:8]
	}
	gossipDebugf("gossip seal nonce_len=%d nonce_hex=%s sealed_len=%d", len(nonce), hex.EncodeToString(noncePrefix), len(sealed))
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

func verifiedPeerForAddr(peers []peer.Peer, addr string) (peer.Peer, bool) {
	if addr == "" {
		return peer.Peer{}, false
	}
	if p, ok := findPeerByAddr(peers, addr); ok && len(p.PubKey) > 0 {
		return p, true
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	for _, p := range peers {
		if len(p.PubKey) == 0 || p.Addr == "" {
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

func isVerifiedSender(peers []peer.Peer, addr string) bool {
	_, ok := verifiedPeerForAddr(peers, addr)
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
	if err != nil || len(pubBytes) != crypto.PubLen {
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
	input := signInputBytes(version, suite, msgType, fromID, payload)
	return crypto.Sign(priv, crypto.SHA3_256(input))
}

func verifySigFrom(version, suite, msgType string, fromID [32]byte, payload []byte, sig, pub []byte) bool {
	input := signInputBytes(version, suite, msgType, fromID, payload)
	return crypto.Verify(pub, crypto.SHA3_256(input), sig)
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
		return nil, fmt.Errorf("missing sig_from")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("bad sig_from")
	}
	return b, nil
}

func verifySignedMessage(data []byte, msgType string, self *node.Node) *recvError {
	if self == nil || self.Peers == nil {
		return &recvError{msg: "node unavailable", err: fmt.Errorf("peer store unavailable")}
	}
	switch msgType {
	case proto.MsgTypeContractOpen:
		m, err := proto.DecodeContractOpenMsg(data)
		if err != nil {
			return &recvError{msg: "decode contract open failed", err: err}
		}
		fromID, err := decodeNodeIDHex(m.FromNodeID)
		if err != nil {
			return &recvError{msg: invalidMessage, err: err}
		}
		sig, err := decodeSigHex(m.SigFrom)
		if err != nil {
			return &recvError{msg: invalidMessage, err: err}
		}
		p, ok := findPeerByNodeID(self.Peers.List(), fromID)
		if !ok {
			return &recvError{msg: invalidMessage, err: fmt.Errorf("unknown sender")}
		}
		tmp := m
		tmp.SigFrom = ""
		payload, err := proto.EncodeContractOpenMsg(tmp)
		if err != nil {
			return &recvError{msg: "encode contract open failed", err: err}
		}
		version := tmp.ProtoVersion
		if version == "" {
			version = proto.ProtoVersion
		}
		suite := tmp.Suite
		if suite == "" {
			suite = proto.Suite
		}
		mt := tmp.Type
		if mt == "" {
			mt = proto.MsgTypeContractOpen
		}
		if !verifySigFrom(version, suite, mt, fromID, payload, sig, p.PubKey) {
			return &recvError{msg: invalidMessage, err: fmt.Errorf("invalid sig_from")}
		}
		return nil
	case proto.MsgTypeRepayReq:
		m, err := proto.DecodeRepayReqMsg(data)
		if err != nil {
			return &recvError{msg: "decode repay req failed", err: err}
		}
		fromID, err := decodeNodeIDHex(m.FromNodeID)
		if err != nil {
			return &recvError{msg: invalidMessage, err: err}
		}
		sig, err := decodeSigHex(m.SigFrom)
		if err != nil {
			return &recvError{msg: invalidMessage, err: err}
		}
		p, ok := findPeerByNodeID(self.Peers.List(), fromID)
		if !ok {
			return &recvError{msg: invalidMessage, err: fmt.Errorf("unknown sender")}
		}
		tmp := m
		tmp.SigFrom = ""
		payload, err := proto.EncodeRepayReqMsg(tmp)
		if err != nil {
			return &recvError{msg: "encode repay req failed", err: err}
		}
		version := tmp.ProtoVersion
		if version == "" {
			version = proto.ProtoVersion
		}
		suite := tmp.Suite
		if suite == "" {
			suite = proto.Suite
		}
		mt := tmp.Type
		if mt == "" {
			mt = proto.MsgTypeRepayReq
		}
		if !verifySigFrom(version, suite, mt, fromID, payload, sig, p.PubKey) {
			return &recvError{msg: invalidMessage, err: fmt.Errorf("invalid sig_from")}
		}
		return nil
	case proto.MsgTypeAck:
		m, err := proto.DecodeAckMsg(data)
		if err != nil {
			return &recvError{msg: "decode ack failed", err: err}
		}
		fromID, err := decodeNodeIDHex(m.FromNodeID)
		if err != nil {
			return &recvError{msg: invalidMessage, err: err}
		}
		sig, err := decodeSigHex(m.SigFrom)
		if err != nil {
			return &recvError{msg: invalidMessage, err: err}
		}
		p, ok := findPeerByNodeID(self.Peers.List(), fromID)
		if !ok {
			return &recvError{msg: invalidMessage, err: fmt.Errorf("unknown sender")}
		}
		tmp := m
		tmp.SigFrom = ""
		payload, err := proto.EncodeAckMsg(tmp)
		if err != nil {
			return &recvError{msg: "encode ack failed", err: err}
		}
		version := tmp.ProtoVersion
		if version == "" {
			version = proto.ProtoVersion
		}
		suite := tmp.Suite
		if suite == "" {
			suite = proto.Suite
		}
		mt := tmp.Type
		if mt == "" {
			mt = proto.MsgTypeAck
		}
		if !verifySigFrom(version, suite, mt, fromID, payload, sig, p.PubKey) {
			return &recvError{msg: invalidMessage, err: fmt.Errorf("invalid sig_from")}
		}
		return nil
	case proto.MsgTypePeerExchangeReq:
		logDrop := func(reason string, err error) *recvError {
			if os.Getenv("WEB4_DEBUG") == "1" {
				if err != nil {
					fmt.Fprintf(os.Stderr, "peer_exchange_req dropped: %s: %v\n", reason, err)
				} else {
					fmt.Fprintf(os.Stderr, "peer_exchange_req dropped: %s\n", reason)
				}
			}
			return &recvError{msg: invalidMessage, err: err}
		}
		m, err := proto.DecodePeerExchangeReq(data)
		if err != nil {
			if os.Getenv("WEB4_DEBUG") == "1" {
				fmt.Fprintf(os.Stderr, "peer_exchange_req dropped: decode failed: %v\n", err)
			}
			return &recvError{msg: "decode peer exchange req failed", err: err}
		}
		fromID, err := decodeNodeIDHex(m.FromNodeID)
		if err != nil {
			return logDrop("bad from_node_id", err)
		}
		sig, err := decodeSigHex(m.SigFrom)
		if err != nil {
			return logDrop("bad sig_from", err)
		}
		p, ok := findPeerByNodeID(self.Peers.List(), fromID)
		if !ok {
			return logDrop("unknown sender", fmt.Errorf("unknown sender"))
		}
		tmp := m
		tmp.SigFrom = ""
		payload, err := proto.EncodePeerExchangeReq(tmp)
		if err != nil {
			return &recvError{msg: "encode peer exchange req failed", err: err}
		}
		version := tmp.ProtoVersion
		if version == "" {
			version = proto.ProtoVersion
		}
		suite := tmp.Suite
		if suite == "" {
			suite = proto.Suite
		}
		mt := tmp.Type
		if mt == "" {
			mt = proto.MsgTypePeerExchangeReq
		}
		if !verifySigFrom(version, suite, mt, fromID, payload, sig, p.PubKey) {
			return logDrop("invalid sig_from", fmt.Errorf("invalid sig_from"))
		}
		return nil
	case proto.MsgTypePeerExchangeResp:
		m, err := proto.DecodePeerExchangeResp(data)
		if err != nil {
			return &recvError{msg: "decode peer exchange resp failed", err: err}
		}
		fromID, err := decodeNodeIDHex(m.FromNodeID)
		if err != nil {
			return &recvError{msg: invalidMessage, err: err}
		}
		sig, err := decodeSigHex(m.SigFrom)
		if err != nil {
			return &recvError{msg: invalidMessage, err: err}
		}
		p, ok := findPeerByNodeID(self.Peers.List(), fromID)
		if !ok {
			return &recvError{msg: invalidMessage, err: fmt.Errorf("unknown sender")}
		}
		tmp := m
		tmp.SigFrom = ""
		payload, err := proto.EncodePeerExchangeResp(tmp)
		if err != nil {
			return &recvError{msg: "encode peer exchange resp failed", err: err}
		}
		version := tmp.ProtoVersion
		if version == "" {
			version = proto.ProtoVersion
		}
		suite := tmp.Suite
		if suite == "" {
			suite = proto.Suite
		}
		mt := tmp.Type
		if mt == "" {
			mt = proto.MsgTypePeerExchangeResp
		}
		if !verifySigFrom(version, suite, mt, fromID, payload, sig, p.PubKey) {
			return &recvError{msg: invalidMessage, err: fmt.Errorf("invalid sig_from")}
		}
		return nil
	case proto.MsgTypeGossipPush:
		m, err := proto.DecodeGossipPushMsg(data)
		if err != nil {
			return &recvError{msg: "decode gossip push failed", err: err}
		}
		fromID, err := decodeNodeIDHex(m.FromNodeID)
		if err != nil {
			return &recvError{msg: invalidMessage, err: err}
		}
		sig, err := decodeSigHex(m.SigFrom)
		if err != nil {
			return &recvError{msg: invalidMessage, err: err}
		}
		if self.Members == nil || !self.Members.Has(fromID) {
			return &recvError{msg: invalidMessage, err: fmt.Errorf("unaccepted sender")}
		}
		p, ok := findPeerByNodeID(self.Peers.List(), fromID)
		if !ok {
			return &recvError{msg: invalidMessage, err: fmt.Errorf("unknown sender")}
		}
		tmp := m
		tmp.SigFrom = ""
		payload, err := proto.EncodeGossipPushMsg(tmp)
		if err != nil {
			return &recvError{msg: "encode gossip push failed", err: err}
		}
		version := tmp.ProtoVersion
		if version == "" {
			version = proto.ProtoVersion
		}
		suite := tmp.Suite
		if suite == "" {
			suite = proto.Suite
		}
		mt := tmp.Type
		if mt == "" {
			mt = proto.MsgTypeGossipPush
		}
		if !verifySigFrom(version, suite, mt, fromID, payload, sig, p.PubKey) {
			return &recvError{msg: invalidMessage, err: fmt.Errorf("invalid sig_from")}
		}
		return nil
	default:
		return nil
	}
}

func ensureSignedOutgoing(data []byte, self *node.Node) ([]byte, error) {
	if self == nil || len(self.PrivKey) == 0 {
		return data, nil
	}
	var hdr struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &hdr); err != nil {
		return data, nil
	}
	switch hdr.Type {
	case proto.MsgTypeContractOpen:
		m, err := proto.DecodeContractOpenMsg(data)
		if err != nil {
			return nil, err
		}
		if m.SigFrom != "" && m.FromNodeID != "" {
			return data, nil
		}
		fromID := self.ID
		m.FromNodeID = hex.EncodeToString(fromID[:])
		payloadMsg := m
		payloadMsg.SigFrom = ""
		payload, err := proto.EncodeContractOpenMsg(payloadMsg)
		if err != nil {
			return nil, err
		}
		version := payloadMsg.ProtoVersion
		if version == "" {
			version = proto.ProtoVersion
		}
		suite := payloadMsg.Suite
		if suite == "" {
			suite = proto.Suite
		}
		msgType := payloadMsg.Type
		if msgType == "" {
			msgType = proto.MsgTypeContractOpen
		}
		sig := sigFromBytes(version, suite, msgType, fromID, payload, self.PrivKey)
		m.SigFrom = hex.EncodeToString(sig)
		return proto.EncodeContractOpenMsg(m)
	case proto.MsgTypeRepayReq:
		m, err := proto.DecodeRepayReqMsg(data)
		if err != nil {
			return nil, err
		}
		if m.SigFrom != "" && m.FromNodeID != "" {
			return data, nil
		}
		fromID := self.ID
		m.FromNodeID = hex.EncodeToString(fromID[:])
		payloadMsg := m
		payloadMsg.SigFrom = ""
		payload, err := proto.EncodeRepayReqMsg(payloadMsg)
		if err != nil {
			return nil, err
		}
		version := payloadMsg.ProtoVersion
		if version == "" {
			version = proto.ProtoVersion
		}
		suite := payloadMsg.Suite
		if suite == "" {
			suite = proto.Suite
		}
		msgType := payloadMsg.Type
		if msgType == "" {
			msgType = proto.MsgTypeRepayReq
		}
		sig := sigFromBytes(version, suite, msgType, fromID, payload, self.PrivKey)
		m.SigFrom = hex.EncodeToString(sig)
		return proto.EncodeRepayReqMsg(m)
	case proto.MsgTypeAck:
		m, err := proto.DecodeAckMsg(data)
		if err != nil {
			return nil, err
		}
		if m.SigFrom != "" && m.FromNodeID != "" {
			return data, nil
		}
		fromID := self.ID
		m.FromNodeID = hex.EncodeToString(fromID[:])
		payloadMsg := m
		payloadMsg.SigFrom = ""
		payload, err := proto.EncodeAckMsg(payloadMsg)
		if err != nil {
			return nil, err
		}
		version := payloadMsg.ProtoVersion
		if version == "" {
			version = proto.ProtoVersion
		}
		suite := payloadMsg.Suite
		if suite == "" {
			suite = proto.Suite
		}
		msgType := payloadMsg.Type
		if msgType == "" {
			msgType = proto.MsgTypeAck
		}
		sig := sigFromBytes(version, suite, msgType, fromID, payload, self.PrivKey)
		m.SigFrom = hex.EncodeToString(sig)
		return proto.EncodeAckMsg(m)
	case proto.MsgTypePeerExchangeReq:
		m, err := proto.DecodePeerExchangeReq(data)
		if err != nil {
			return nil, err
		}
		if m.SigFrom != "" && m.FromNodeID != "" {
			return data, nil
		}
		fromID := self.ID
		m.FromNodeID = hex.EncodeToString(fromID[:])
		payloadMsg := m
		payloadMsg.SigFrom = ""
		payload, err := proto.EncodePeerExchangeReq(payloadMsg)
		if err != nil {
			return nil, err
		}
		version := payloadMsg.ProtoVersion
		if version == "" {
			version = proto.ProtoVersion
		}
		suite := payloadMsg.Suite
		if suite == "" {
			suite = proto.Suite
		}
		msgType := payloadMsg.Type
		if msgType == "" {
			msgType = proto.MsgTypePeerExchangeReq
		}
		sig := sigFromBytes(version, suite, msgType, fromID, payload, self.PrivKey)
		m.SigFrom = hex.EncodeToString(sig)
		return proto.EncodePeerExchangeReq(m)
	case proto.MsgTypePeerExchangeResp:
		m, err := proto.DecodePeerExchangeResp(data)
		if err != nil {
			return nil, err
		}
		if m.SigFrom != "" && m.FromNodeID != "" {
			return data, nil
		}
		fromID := self.ID
		m.FromNodeID = hex.EncodeToString(fromID[:])
		payloadMsg := m
		payloadMsg.SigFrom = ""
		payload, err := proto.EncodePeerExchangeResp(payloadMsg)
		if err != nil {
			return nil, err
		}
		version := payloadMsg.ProtoVersion
		if version == "" {
			version = proto.ProtoVersion
		}
		suite := payloadMsg.Suite
		if suite == "" {
			suite = proto.Suite
		}
		msgType := payloadMsg.Type
		if msgType == "" {
			msgType = proto.MsgTypePeerExchangeResp
		}
		sig := sigFromBytes(version, suite, msgType, fromID, payload, self.PrivKey)
		m.SigFrom = hex.EncodeToString(sig)
		return proto.EncodePeerExchangeResp(m)
	case proto.MsgTypeGossipPush:
		m, err := proto.DecodeGossipPushMsg(data)
		if err != nil {
			return nil, err
		}
		if m.SigFrom != "" && m.FromNodeID != "" {
			return data, nil
		}
		fromID := self.ID
		m.FromNodeID = hex.EncodeToString(fromID[:])
		payloadMsg := m
		payloadMsg.SigFrom = ""
		payload, err := proto.EncodeGossipPushMsg(payloadMsg)
		if err != nil {
			return nil, err
		}
		version := payloadMsg.ProtoVersion
		if version == "" {
			version = proto.ProtoVersion
		}
		suite := payloadMsg.Suite
		if suite == "" {
			suite = proto.Suite
		}
		msgType := payloadMsg.Type
		if msgType == "" {
			msgType = proto.MsgTypeGossipPush
		}
		sig := sigFromBytes(version, suite, msgType, fromID, payload, self.PrivKey)
		m.SigFrom = hex.EncodeToString(sig)
		return proto.EncodeGossipPushMsg(m)
	default:
		return data, nil
	}
}
func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: web4 <keygen|open|list|close|ack|recv|quic-listen|quic-send|node|gossip>")
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
		if err != nil || len(to) != crypto.PubLen {
			die("invalid --to pubkey", fmt.Errorf("need %d bytes hex", crypto.PubLen))
		}

		iou := proto.IOU{Creditor: to, Debtor: pub, Amount: *amount, Nonce: *nonce}
		cid := proto.ContractID(iou)
		credHex := hex.EncodeToString(to)
		debtHex := hex.EncodeToString(pub)
		payload, err := proto.EncodeOpenPayload(credHex, debtHex, *amount, *nonce)
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
		ackPayload, err := proto.EncodeAckPayload(*idHex, ack.Decision, ack.Close)
		if err != nil {
			die("encode ack payload failed", err)
		}
		ackEph, ackSealed, err := e2eSeal(proto.MsgTypeAck, cid, *reqNonce, c.IOU.Debtor, ackPayload)
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
		self, err := node.NewNode(root, node.Options{})
		if err != nil {
			die("load keys failed", err)
		}
		data, err := os.ReadFile(*inPath)
		if err != nil {
			die("read message failed", err)
		}
		payload, err := proto.ReadFrameWithTypeCap(bytes.NewReader(data), proto.SoftMaxFrameSize, proto.MaxSizeForType)
		if err == nil {
			if err := recvData(payload, st, self, checker); err != nil {
				if os.Getenv("WEB4_DEBUG") == "1" {
					fmt.Fprintf(os.Stderr, "recv error: %v\n", err)
				}
				dieMsg(invalidMessage)
			}
			return
		}
		if err := recvData(data, st, self, checker); err != nil {
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
		self, err := node.NewNode(root, node.Options{})
		if err != nil {
			die("load keys failed", err)
		}
		if err := network.ListenAndServeWithResponderFrom(*addr, nil, *devTLS, func(senderAddr string, data []byte) ([]byte, error) {
			resp, _, err := recvDataWithResponse(data, st, self, checker, senderAddr)
			if err != nil {
				if os.Getenv("WEB4_DEBUG") == "1" {
					fmt.Fprintf(os.Stderr, "recv error: %v\n", err)
				}
				return nil, err
			}
			return resp, nil
		}); err != nil {
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

	case "node":
		if len(os.Args) < 3 {
			dieMsg("usage: web4 node <id|list|members|join|add|hello|exchange>")
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
			_ = fs.Parse(os.Args[3:])
			if *nodeIDHex == "" && *addr == "" {
				die("missing --node-id", fmt.Errorf("node id or addr required"))
			}
			self, err := node.NewNode(root, node.Options{})
			if err != nil {
				die("load node failed", err)
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
			outPath := fs.String("out", "", "write NodeHelloMsg to file and exit")
			advertiseAddr := fs.String("advertise-addr", "", "advertised addr (host:port)")
			devTLS := fs.Bool("devtls", false, "allow deterministic dev TLS certs (unsafe)")
			devTLSCA := fs.String("devtls-ca", "", "dev TLS CA PEM path")
			_ = fs.Parse(os.Args[3:])
			if *addr == "" && *outPath == "" {
				die("missing --addr", fmt.Errorf("address required"))
			}
			if *outPath != "" && *advertiseAddr == "" {
				die("missing --advertise-addr", fmt.Errorf("advertise addr required for --out"))
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
				dieMsg(invalidMessage)
			}

			self, err := node.NewNode(root, node.Options{})
			if err != nil {
				fail("load node failed", err)
			}
			var nonceBytes [8]byte
			if _, err := rand.Read(nonceBytes[:]); err != nil {
				fail("nonce generation failed", err)
			}
			nonce := binary.BigEndian.Uint64(nonceBytes[:])
			msg, err := self.Hello(nonce, *advertiseAddr)
			if err != nil {
				fail("node hello failed", err)
			}
			data, err := proto.EncodeNodeHelloMsg(msg)
			if err != nil {
				fail("encode node hello failed", err)
			}
			if err := enforceTypeMax(proto.MsgTypeNodeHello, len(data)); err != nil {
				fail("node hello too large", err)
			}
			if *outPath != "" {
				if err := writeMsg(*outPath, data); err != nil {
					fail("write node hello failed", err)
				}
				fmt.Println("OK node hello written")
				return
			}
			if err := network.Send(*addr, data, false, *devTLS, *devTLSCA); err != nil {
				fail("node hello send failed", err)
			}
			self.Candidates.Add(*addr)
			fmt.Println("OK node hello sent")
		case "exchange":
			fs := flag.NewFlagSet("node exchange", flag.ExitOnError)
			addr := fs.String("addr", "", "target addr (host:port)")
			k := fs.Int("k", defaultPeerExchangeK, "max peers to request")
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
				if os.Getenv("WEB4_DEBUG") == "1" {
					die(msg, err)
				}
				dieMsg(invalidMessage)
			}

			self, err := node.NewNode(root, node.Options{})
			if err != nil {
				fail("load node failed", err)
			}
			var nonceBytes [8]byte
			if _, err := rand.Read(nonceBytes[:]); err != nil {
				fail("nonce generation failed", err)
			}
			nonce := binary.BigEndian.Uint64(nonceBytes[:])
			hello, err := self.Hello(nonce, "")
			if err != nil {
				fail("node hello failed", err)
			}
			helloData, err := proto.EncodeNodeHelloMsg(hello)
			if err != nil {
				fail("encode node hello failed", err)
			}
			if err := enforceTypeMax(proto.MsgTypeNodeHello, len(helloData)); err != nil {
				fail("node hello too large", err)
			}
			if err := network.Send(*addr, helloData, false, *devTLS, *devTLSCA); err != nil {
				fail("node hello send failed", err)
			}
			self.Candidates.Add(*addr)
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
			fromID := self.ID
			req.FromNodeID = hex.EncodeToString(fromID[:])
			payloadReq := req
			payloadReq.SigFrom = ""
			payload, err := proto.EncodePeerExchangeReq(payloadReq)
			if err != nil {
				fail("encode peer exchange req failed", err)
			}
			sig := sigFromBytes(req.ProtoVersion, req.Suite, req.Type, fromID, payload, self.PrivKey)
			req.SigFrom = hex.EncodeToString(sig)
			data, err := proto.EncodePeerExchangeReq(req)
			if err != nil {
				fail("encode peer exchange req failed", err)
			}
			if err := enforceTypeMax(proto.MsgTypePeerExchangeReq, len(data)); err != nil {
				fail("peer exchange req too large", err)
			}
			respData, err := network.Exchange(*addr, data, false, *devTLS, *devTLSCA)
			if err != nil {
				fail("peer exchange failed", err)
			}
			if err := enforceTypeMax(proto.MsgTypePeerExchangeResp, len(respData)); err != nil {
				fail("peer exchange resp too large", err)
			}
			resp, err := proto.DecodePeerExchangeResp(respData)
			if err != nil {
				fail("decode peer exchange resp failed", err)
			}
			if err := verifySignedMessage(respData, proto.MsgTypePeerExchangeResp, self); err != nil {
				fail("peer exchange resp verify failed", err)
			}
			added, err := applyPeerExchangeResp(self, resp)
			if err != nil {
				fail("apply peer exchange resp failed", err)
			}
			fmt.Printf("OK node exchange (%d added)\n", added)
		default:
			dieMsg("usage: web4 node <id|list|add|hello|exchange>")
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
			if err := network.Send(*addr, out, false, *devTLS, *devTLSCA); err != nil {
				fail("gossip push failed", err)
			}
			fmt.Println("OK gossip push sent")
		default:
			dieMsg("usage: web4 gossip <push>")
		}

	default:
		fmt.Println("unknown command")
		os.Exit(1)
	}
}
