package daemon

import (
	"bytes"
	"container/list"
	"context"
	stdsha256 "crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"web4mvp/internal/math4"
	"web4mvp/internal/metrics"
	"web4mvp/internal/network"
	"web4mvp/internal/node"
	"web4mvp/internal/peer"
	"web4mvp/internal/proto"
	"web4mvp/internal/state"
	"web4mvp/internal/store"
	"web4mvp/internal/zk/linear"
	"web4mvp/internal/zk/pedersen"
)

type Runner struct {
	Root       string
	Store      *store.Store
	Checker    math4.LocalChecker
	Self       *node.Node
	Metrics    *metrics.Metrics
	Mode       string
	listenMu   sync.RWMutex
	listenAddr string
	snapPath   string
	fieldPath  string
	stopSnap   chan struct{}
}

type Options struct {
	Store    *store.Store
	Checker  math4.LocalChecker
	Metrics  *metrics.Metrics
	SnapPath string
}

func NewRunner(root string, opts Options) (*Runner, error) {
	if root == "" {
		return nil, fmt.Errorf("missing root")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	if err := ensureKeypair(root); err != nil {
		return nil, err
	}
	mode := nodeMode()
	applyNodeModeDefaults(mode)
	self, err := node.NewNode(root, node.Options{})
	if err != nil {
		return nil, err
	}
	st := opts.Store
	if st == nil {
		st = store.New(
			filepath.Join(root, "contracts.jsonl"),
			filepath.Join(root, "acks.jsonl"),
			filepath.Join(root, "repayreqs.jsonl"),
		)
	}
	checker := opts.Checker
	if checker == nil {
		checker = math4.NewLocalChecker(math4.Options{})
	}
	m := opts.Metrics
	if m == nil {
		m = metrics.New()
	}
	runtimeMetrics = m
	snapPath := opts.SnapPath
	if snapPath == "" {
		snapPath = filepath.Join(root, "metrics.json")
	}
	return &Runner{
		Root:      root,
		Store:     st,
		Checker:   checker,
		Self:      self,
		Metrics:   m,
		Mode:      mode,
		snapPath:  snapPath,
		fieldPath: filepath.Join(root, "field.json"),
		stopSnap:  make(chan struct{}),
	}, nil
}

func (r *Runner) StartSnapshotWriter(interval time.Duration) {
	if r == nil || r.Metrics == nil || r.snapPath == "" {
		return
	}
	if interval <= 0 {
		interval = time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if r.Metrics != nil {
					r.Metrics.SetCurrentConns(network.CurrentConns())
					r.Metrics.SetCurrentStreams(network.CurrentStreams())
					if r.Self != nil && r.Self.Peers != nil {
						r.Metrics.SetPeerTableSize(uint64(len(r.Self.Peers.List())))
					}
				}
				_ = r.Metrics.WriteSnapshot(r.snapPath)
			case <-r.stopSnap:
				return
			}
		}
	}()
}

func (r *Runner) StopSnapshotWriter() {
	if r == nil {
		return
	}
	select {
	case r.stopSnap <- struct{}{}:
	default:
	}
}

func (r *Runner) writeFieldSnapshot(members [][32]byte) {
	if r == nil || r.Self == nil || r.Self.Field == nil || r.fieldPath == "" {
		return
	}
	b, phi := r.Self.Field.Snapshot(members)
	type fieldEntry struct {
		NodeID string  `json:"node_id"`
		B      int64   `json:"b"`
		Phi    float64 `json:"phi"`
	}
	out := make([]fieldEntry, 0, len(members))
	for _, id := range members {
		out = append(out, fieldEntry{
			NodeID: hex.EncodeToString(id[:]),
			B:      b[id],
			Phi:    phi[id],
		})
	}
	payload := struct {
		GeneratedAt time.Time    `json:"generated_at"`
		Entries     []fieldEntry `json:"entries"`
	}{
		GeneratedAt: time.Now().UTC(),
		Entries:     out,
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(r.fieldPath, data, 0600)
}

func (r *Runner) HandleRaw(data []byte) error {
	_, _, err := r.recvDataWithResponse(data, "")
	if err != nil {
		return err
	}
	return nil
}

func (r *Runner) Run(addr string, devTLS bool) error {
	return r.RunWithContext(context.Background(), addr, devTLS, nil)
}

func (r *Runner) RunWithContext(ctx context.Context, addr string, devTLS bool, ready chan<- string) error {
	if r == nil {
		return fmt.Errorf("missing runner")
	}
	r.StartSnapshotWriter(time.Second)
	internalReady := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- network.ListenAndServeWithResponderFromContext(ctx, addr, internalReady, devTLS, func(senderAddr string, data []byte) ([]byte, error) {
			resp, _, err := r.recvDataWithResponse(data, senderAddr)
			if err != nil {
				if os.Getenv("WEB4_DEBUG") == "1" {
					fmt.Fprintf(os.Stderr, "recv error: %v\n", err)
				}
				return nil, err
			}
			return resp, nil
		})
	}()
	select {
	case actual := <-internalReady:
		r.setListenAddr(actual)
		if ready != nil {
			select {
			case ready <- actual:
			default:
			}
		}
		if devTLS {
			if err := waitDevTLSCA(ctx, r.Root, 3*time.Second); err != nil {
				r.StopSnapshotWriter()
				return err
			}
		}
		startConnManAfterReady(ctx, r, devTLS)
	case err := <-errCh:
		r.StopSnapshotWriter()
		return err
	case <-ctx.Done():
		r.StopSnapshotWriter()
		return ctx.Err()
	}
	err := <-errCh
	r.StopSnapshotWriter()
	return err
}

func (r *Runner) setListenAddr(addr string) {
	if r == nil {
		return
	}
	r.listenMu.Lock()
	r.listenAddr = addr
	r.listenMu.Unlock()
}

func (r *Runner) getListenAddr() string {
	if r == nil {
		return ""
	}
	r.listenMu.RLock()
	addr := r.listenAddr
	r.listenMu.RUnlock()
	return addr
}

func startConnManAfterReady(ctx context.Context, r *Runner, devTLS bool) {
	ready := make(chan struct{})
	close(ready)
	startConnManWithReady(ctx, r, devTLS, ready)
}

func startConnManWithReady(ctx context.Context, r *Runner, devTLS bool, ready <-chan struct{}) {
	if r == nil || r.Self == nil || r.Self.Peers == nil {
		return
	}
	go func() {
		select {
		case <-ready:
		case <-ctx.Done():
			return
		}
		startConnMan(ctx, r, devTLS)
	}()
}

func waitDevTLSCA(ctx context.Context, root string, timeout time.Duration) error {
	if root == "" {
		return fmt.Errorf("missing root for devtls ca")
	}
	path := filepath.Join(root, "devtls_ca.pem")
	deadline := time.Now().Add(timeout)
	for {
		if fi, err := os.Stat(path); err == nil && fi.Size() > 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("devtls ca not ready")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

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

func enforceTypeMax(t string, n int) error {
	limit := proto.MaxSizeForType(t)
	if n > limit {
		return fmt.Errorf("message too large")
	}
	return nil
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

func SealSecureEnvelope(self *node.Node, peerID [32]byte, msgType string, channelID string, payload []byte) ([]byte, error) {
	return sealSecureEnvelope(self, peerID, msgType, channelID, payload)
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

type recvError struct {
	msg string
	err error
}

func (e *recvError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%s: %v", e.msg, e.err)
}

func (r *Runner) recvDataWithResponse(data []byte, senderAddr string) ([]byte, bool, *recvError) {
	debugRecv := func(format string, args ...any) {
		if os.Getenv("WEB4_DEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "recv: "+format+"\n", args...)
		}
	}
	reject := func(msg string, err error) *recvError {
		if os.Getenv("WEB4_DEBUG") == "1" {
			if shouldLogReject(msg) {
				fmt.Fprintf(os.Stderr, "recv reject: %s: %v\n", msg, err)
			}
		}
		debugCount.incDrop(classifyDropReason(msg, err))
		return &recvError{msg: msg, err: err}
	}

	var hdr struct {
		Type string `json:"type"`
	}
	if len(data) == 0 || len(data) > proto.MaxFrameSize {
		return nil, false, reject("message too large", fmt.Errorf("frame size %d", len(data)))
	}
	if err := json.Unmarshal(data, &hdr); err != nil {
		return nil, false, reject("decode message type failed", err)
	}
	debugRecv("recv top-level type=%s sender=%s", hdr.Type, senderAddr)
	if err := enforceTypeMax(hdr.Type, len(data)); err != nil {
		return nil, false, reject("message too large", err)
	}
	if r == nil || r.Self == nil {
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
		if toID != r.Self.ID {
			return nil, false, reject("open secure envelope failed", fmt.Errorf("to_id mismatch"))
		}
		if r.Self.Peers == nil {
			return nil, false, reject("node unavailable", fmt.Errorf("peer store unavailable"))
		}
		if senderAddr != "" {
			if mapped, ok := findPeerByAddr(r.Self.Peers.List(), senderAddr); ok && mapped.NodeID != fromID {
				return nil, false, reject("addr conflict", fmt.Errorf("addr maps to different node_id"))
			}
		}
		if !hasPeerID(r.Self.Peers.List(), fromID) {
			return nil, false, reject("unknown peer", fmt.Errorf("missing peer"))
		}
		if r.Self.Sessions == nil || !r.Self.Sessions.Has(fromID) {
			return nil, false, reject("unknown sender", fmt.Errorf("missing session"))
		}
		if !recvNodeLimiter.Allow(hex.EncodeToString(fromID[:])) {
			return nil, false, reject("rate_limit_node", errors.New("rate limited"))
		}
		msgType, plain, fromID, err := openSecureEnvelope(r.Self, env)
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
		if senderAddr != "" && r.Self.Peers != nil {
			if p, ok := findPeerByNodeID(r.Self.Peers.List(), fromID); ok && len(p.PubKey) > 0 {
				if changed, err := r.Self.Peers.ObserveAddr(peer.Peer{NodeID: fromID, PubKey: p.PubKey}, senderAddr, "", false, true); err != nil {
					return nil, false, reject("addr observe failed", err)
				} else if changed {
					debugCount.incAddrChange("observe")
				}
			}
		}
	}
	if !wasSecure && hdr.Type != proto.MsgTypeHello1 && hdr.Type != proto.MsgTypeHello2 && hdr.Type != proto.MsgTypeGossipPush {
		if hdr.Type != proto.MsgTypeInviteCert && hdr.Type != proto.MsgTypeInviteBundle && hdr.Type != proto.MsgTypeRevoke &&
			hdr.Type != proto.MsgTypePeerExchangeReq && hdr.Type != proto.MsgTypePeerExchangeResp {
			return nil, false, reject("handshake required", fmt.Errorf("missing secure envelope"))
		}
	}
	if !wasSecure {
		debugCount.incRecv(hdr.Type)
	}

	if wasSecure {
		if nodeMode() != nodeModeBootstrap || !isBootstrapDiscoveryType(hdr.Type) {
			if scope, ok := requiredMemberScope(hdr.Type); ok {
				if r.Self.Members == nil || !r.Self.Members.HasScope(secureFromID, scope) {
					if os.Getenv("WEB4_DEBUG") == "1" {
						fmt.Fprintf(os.Stderr, "recv drop: membership_gate type=%s sender=%x scope=%d\n", hdr.Type, secureFromID[:], scope)
					}
					return nil, false, reject("membership_gate", fmt.Errorf("sender not member"))
				}
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
		if fromID == r.Self.ID {
			return nil, false, reject("invalid hello1", errors.New("hello1 from_id self"))
		}
		if toID != r.Self.ID {
			return nil, false, reject("invalid hello1", errors.New("hello1 to_id mismatch"))
		}
		prevAddr := ""
		if senderAddr != "" {
			if existing, ok := findPeerByNodeID(r.Self.Peers.List(), fromID); ok {
				prevAddr = existing.Addr
			}
		}
		resp, err := r.Self.HandleHello1From(m, senderAddr)
		if err != nil {
			debugCount.incVerify("hello1")
			return nil, false, reject("invalid hello1", err)
		}
		if senderAddr != "" && prevAddr != "" && prevAddr != senderAddr {
			debugCount.incAddrChange("hello1")
		}
		out, err := proto.EncodeHello2Msg(resp)
		if err != nil {
			return nil, false, reject("encode hello2 failed", err)
		}
		return out, true, nil

	case proto.MsgTypeHello2:
		m, err := proto.DecodeHello2Msg(data)
		if err != nil {
			return nil, false, reject("decode hello2 failed", err)
		}
		fromID, toID, _, _, _, _, err := proto.DecodeHello2Fields(m)
		if err != nil {
			return nil, false, reject("decode hello2 failed", err)
		}
		if os.Getenv("WEB4_DEBUG") == "1" {
			via := "direct"
			if wasSecure || senderAddr == "" {
				via = "gossip"
			}
			fmt.Fprintf(os.Stderr, "hello2 recv from=%x to=%x via=%s\n", fromID[:], toID[:], via)
		}
		if fromID == r.Self.ID {
			return nil, false, reject("invalid hello2", errors.New("hello2 from_id self"))
		}
		if toID != r.Self.ID {
			return nil, false, reject("invalid hello2", errors.New("hello2 to_id mismatch"))
		}
		prevAddr := ""
		if senderAddr != "" {
			if existing, ok := findPeerByNodeID(r.Self.Peers.List(), fromID); ok {
				prevAddr = existing.Addr
			}
		}
		if err := r.Self.HandleHello2From(m, senderAddr); err != nil {
			debugCount.incVerify("hello2")
			return nil, false, reject("invalid hello2", err)
		}
		if senderAddr != "" && prevAddr != "" && prevAddr != senderAddr {
			debugCount.incAddrChange("hello2")
		}
		return nil, true, nil

	case proto.MsgTypeGossipPush:
		return handleGossipPush(data, r.Store, r.Self, r.Checker, senderAddr)

	case proto.MsgTypePeerExchangeReq:
		req, err := proto.DecodePeerExchangeReq(data)
		if err != nil {
			return nil, false, reject("decode peer exchange req failed", err)
		}
		if senderAddr != "" && r.Self != nil && r.Self.Peers != nil {
			var fromID [32]byte
			if req.FromNodeID != "" {
				if id, err := decodeNodeIDHex(req.FromNodeID); err == nil {
					fromID = id
				}
			}
			if req.PubKey != "" {
				pub, err := hex.DecodeString(req.PubKey)
				if err == nil && len(pub) > 0 && isValidAddr(senderAddr) {
					if isZeroNodeID(fromID) {
						fromID = node.DeriveNodeID(pub)
					}
					if !isZeroNodeID(fromID) {
						p := peer.Peer{NodeID: fromID, PubKey: pub, Source: "pex", SubnetKey: peer.SubnetKeyForAddr(senderAddr)}
						_, _ = r.Self.Peers.SetAddrUnverified(p, senderAddr, true)
						r.Self.Peers.PeerSeen(fromID, senderAddr)
						p.Addr = ""
						_ = r.Self.Peers.Upsert(p, true)
						if r.Self.Candidates != nil {
							r.Self.Candidates.Add(senderAddr)
						}
					}
				} else if os.Getenv("WEB4_DEBUG") == "1" && err != nil {
					fmt.Fprintf(os.Stderr, "peer_exchange_req invalid pubkey: %v\n", err)
				}
			} else if nodeMode() == nodeModeBootstrap && !isZeroNodeID(fromID) && isValidAddr(senderAddr) {
				p := peer.Peer{NodeID: fromID, Addr: senderAddr, Source: "pex", SubnetKey: peer.SubnetKeyForAddr(senderAddr)}
				_ = r.Self.Peers.UpsertUnverified(p)
				if r.Self.Candidates != nil {
					r.Self.Candidates.Add(senderAddr)
				}
			}
		}
		resp, err := buildPeerExchangeResp(r.Self, req.K, r.getListenAddr())
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
			respData, err = sealSecureEnvelope(r.Self, secureFromID, proto.MsgTypePeerExchangeResp, "", respData)
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
		added, err := applyPeerExchangeResp(r.Self, resp)
		if err != nil {
			return nil, false, reject("apply peer exchange resp failed", err)
		}
		fmt.Println("RECV PEER EXCHANGE", added)
		return nil, false, nil

	case proto.MsgTypeInviteCert:
		msg, err := proto.DecodeInviteCertMsg(data)
		if err != nil {
			return nil, false, reject("decode invite cert failed", err)
		}
		if r.Self.Members == nil {
			return nil, false, reject("member store unavailable", fmt.Errorf("missing member store"))
		}
		if r.Self.Invites == nil {
			return nil, false, reject("invite store unavailable", fmt.Errorf("missing invite store"))
		}
		cert, err := proto.InviteCertFromMsg(msg)
		if err != nil {
			return nil, false, reject("invalid invite cert", err)
		}
		inviterID, inviteeID, err := validateInviteCert(cert, r.Self.Invites, time.Now())
		if err != nil {
			debugCount.incVerify("invite_cert")
			return nil, false, reject("invalid invite cert", err)
		}
		if r.Self.Peers != nil {
			_ = r.Self.Peers.Upsert(peer.Peer{NodeID: inviteeID, PubKey: cert.InviteePub}, true)
			_ = r.Self.Peers.Upsert(peer.Peer{NodeID: inviterID, PubKey: cert.InviterPub}, true)
		}
		if err := r.Self.Members.AddWithScope(inviterID, proto.InviteScopeAll, true); err != nil {
			return nil, false, reject("store member failed", err)
		}
		if err := r.Self.Members.AddInvitedWithScope(inviteeID, cert.Scope, inviterID, true); err != nil {
			return nil, false, reject("store member failed", err)
		}
		if err := r.Self.Invites.Mark(inviterID, cert.InviteID, cert.ExpiresAt, true); err != nil {
			return nil, false, reject("store invite failed", err)
		}
		fmt.Fprintf(os.Stderr, "RECV INVITE OK invitee=%x inviter=%x scope=%d\n", inviteeID[:], inviterID[:], cert.Scope)
		return nil, true, nil

	case proto.MsgTypeInviteBundle:
		msg, err := proto.DecodeInviteBundleMsg(data)
		if err != nil {
			return nil, false, reject("decode invite bundle failed", err)
		}
		if r.Self.Invites == nil {
			return nil, false, reject("invite store unavailable", fmt.Errorf("missing invite store"))
		}
		if r.Self.Members == nil {
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
			if !r.Self.Members.HasScope(approverID, 0) {
				return nil, false, reject("invalid invite bundle", fmt.Errorf("approver not member"))
			}
			sig, err := decodeSigHex(approval.Sig)
			if err != nil || len(sig) == 0 {
				return nil, false, reject("invalid invite bundle", fmt.Errorf("bad approval signature"))
			}
			pub := []byte(nil)
			if approverID == r.Self.ID {
				pub = r.Self.PubKey
			} else if r.Self.Peers != nil {
				if p, ok := findPeerByNodeID(r.Self.Peers.List(), approverID); ok && len(p.PubKey) > 0 {
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
		if r.Self.Invites.Seen(inviteeID, inviteID) {
			return nil, false, reject("invalid invite bundle", fmt.Errorf("invite replay"))
		}
		if r.Self.Peers != nil {
			_ = r.Self.Peers.Upsert(peer.Peer{NodeID: inviteeID, PubKey: inviteePub}, true)
		}
		if inviterSet {
			if err := r.Self.Members.AddInvitedWithScope(inviteeID, msg.Scope, inviterID, true); err != nil {
				return nil, false, reject("store member failed", err)
			}
		} else {
			if err := r.Self.Members.AddWithScope(inviteeID, msg.Scope, true); err != nil {
				return nil, false, reject("store member failed", err)
			}
		}
		if err := r.Self.Invites.Mark(inviterID, inviteID, msg.ExpiresAt, true); err != nil {
			return nil, false, reject("store invite failed", err)
		}
		fmt.Fprintf(os.Stderr, "RECV INVITE BUNDLE OK invitee=%x approvals=%d scope=%d\n", inviteeID[:], approvals, msg.Scope)
		return nil, true, nil

	case proto.MsgTypeRevoke:
		msg, err := proto.DecodeRevokeMsg(data)
		if err != nil {
			return nil, false, reject("decode revoke failed", err)
		}
		if r.Self.Members == nil {
			return nil, false, reject("member store unavailable", fmt.Errorf("missing member store"))
		}
		if r.Self.Revokes == nil {
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
		if !r.Self.Members.HasScope(revokerID, 0) {
			if os.Getenv("WEB4_DEBUG") == "1" {
				fmt.Fprintf(os.Stderr, "recv drop: membership_gate type=%s sender=%x scope=0\n", hdr.Type, revokerID[:])
			}
			return nil, false, reject("membership_gate", fmt.Errorf("revoker not member"))
		}
		if inviterID, ok := r.Self.Members.InviterFor(targetID); !ok || inviterID != revokerID {
			return nil, false, reject("invalid revoke", fmt.Errorf("revoker not inviter"))
		}
		pub := []byte(nil)
		if revokerID == r.Self.ID {
			pub = r.Self.PubKey
		} else if r.Self.Peers != nil {
			if p, ok := findPeerByNodeID(r.Self.Peers.List(), revokerID); ok && len(p.PubKey) > 0 {
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
		if r.Self.Revokes.Seen(revokerID, revokeID) {
			return nil, false, reject("invalid revoke", fmt.Errorf("revoke replay"))
		}
		if err := r.Self.Members.SetScope(targetID, 0, true); err != nil {
			return nil, false, reject("store member failed", err)
		}
		if err := r.Self.Revokes.Mark(revokerID, revokeID, targetID, msg.IssuedAt, true); err != nil {
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
		plain, err := e2eOpen(proto.MsgTypeContractOpen, id, 0, r.Self.PrivKey, c.EphemeralPub, c.Sealed)
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
		if existing, _ := findContractByID(r.Store, id); existing != nil {
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
		if err := r.Checker.Check(update); err != nil {
			return nil, false, reject("local constraint rejected", err)
		}
		if err := r.Store.AddContract(c); err != nil {
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
		c, err := findContractByID(r.Store, cid)
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
		plain, err := e2eOpen(proto.MsgTypeRepayReq, cid, req.ReqNonce, r.Self.PrivKey, ephPub, sealed)
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
		if exists, err := r.Store.HasRepayReq(m.ContractID, m.ReqNonce); err == nil && exists {
			fmt.Println("RECV REPAY-REQ duplicate", m.ContractID)
			return nil, false, nil
		}
		if maxNonce, ok, err := r.Store.MaxRepayReqNonce(m.ContractID); err != nil {
			return nil, false, reject("repay request scan failed", err)
		} else if ok && req.ReqNonce <= maxNonce {
			return nil, false, reject("repay req nonce out of order", fmt.Errorf("non-monotonic reqnonce"))
		}
		if err := r.Store.AddRepayReqIfNew(m); err != nil {
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
		c, err := findContractByID(r.Store, a.ContractID)
		if err != nil {
			return nil, false, reject("contract lookup failed", err)
		}
		if c == nil {
			return nil, false, reject("unknown contract", fmt.Errorf("missing contract for ack"))
		}
		if c.Status == "CLOSED" {
			return nil, false, reject("contract already closed", fmt.Errorf("reject ack"))
		}
		maxNonce, ok, err := r.Store.MaxRepayReqNonce(m.ContractID)
		if err != nil {
			return nil, false, reject("repay req scan failed", err)
		}
		if !ok {
			return nil, false, reject("missing repay request", fmt.Errorf("ack without repay request"))
		}
		reqMsg, err := r.Store.FindRepayReq(m.ContractID, maxNonce)
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
		plain, err := e2eOpen(proto.MsgTypeAck, a.ContractID, maxNonce, r.Self.PrivKey, a.EphemeralPub, a.Sealed)
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
		if exists, err := r.Store.HasAck(m.ContractID, maxNonce); err == nil && exists {
			fmt.Println("RECV ACK duplicate", m.ContractID)
			return nil, false, nil
		}
		if a.Decision == 1 {
			update, err := updateFromParties(c.IOU.Creditor, c.IOU.Debtor, c.IOU.Amount)
			if err != nil {
				return nil, false, reject("invalid update", err)
			}
			if err := r.Checker.Check(update); err != nil {
				return nil, false, reject("local constraint rejected", err)
			}
		}
		if err := r.Store.AddAckIfNew(a, sigA); err != nil {
			return nil, false, reject("store ack failed", err)
		}
		if a.Decision == 1 {
			if err := r.Store.MarkClosed(a.ContractID, false); err != nil {
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
			if r.Metrics != nil {
				r.Metrics.IncDeltaDropDuplicate()
			}
			if os.Getenv("WEB4_DEBUG") == "1" && shouldLogReject("duplicate delta_b") {
				fmt.Fprintf(os.Stderr, "drop deltab duplicate id=%x\n", deltaID[:])
			}
			return nil, false, reject("duplicate delta_b", fmt.Errorf("duplicate delta_id"))
		}
		deltas, members, viewID, scopeHash, err := verifyDeltaBBasic(canonMsg, r.Self)
		if err != nil {
			if r.Metrics != nil && strings.Contains(err.Error(), "node_id not member") {
				r.Metrics.IncDeltaDropNonMember()
			}
			if os.Getenv("WEB4_DEBUG") == "1" && shouldLogReject("invalid delta_b") {
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
			if r.Metrics != nil {
				r.Metrics.IncDeltaDropRate()
			}
			if os.Getenv("WEB4_DEBUG") == "1" && shouldLogReject("rate_limited") {
				fmt.Fprintf(os.Stderr, "drop deltab rate_limited key=%s\n", rateKey)
			}
			return nil, false, reject("rate_limited", fmt.Errorf("delta_b rate limited"))
		}
		zkStatus := "missing"
		if zkMode() {
			if err := verifyDeltaBZK(canonMsgZK, viewID); err != nil {
				if r.Metrics != nil {
					r.Metrics.IncDeltaDropZKFail()
				}
				if os.Getenv("WEB4_DEBUG") == "1" && shouldLogReject("invalid delta_b zk") {
					fmt.Fprintf(os.Stderr, "recv drop: delta_b zk invalid err=%v\n", err)
					if strings.Contains(err.Error(), "zk cap") {
						fmt.Fprintf(os.Stderr, "zk cap\n")
					}
				}
				return nil, false, reject("invalid delta_b zk", err)
			}
			zkStatus = "ok"
		}
		if r.Self.Field == nil {
			r.Self.Field = state.NewField()
		}
		if err := r.Self.Field.ApplyDelta(members, deltas, deltaRelaxIters()); err != nil {
			return nil, false, reject("apply delta_b failed", err)
		}
		r.writeFieldSnapshot(members)
		deltabSeen.Add(deltaID)
		if r.Metrics != nil {
			r.Metrics.IncDeltaVerified()
			if r.Metrics.Recent() != nil {
				viewHex := hex.EncodeToString(viewID[:])
				r.Metrics.Recent().Add(metrics.DeltaHeader{
					ScopeHash: scopeHex,
					ViewID:    viewHex,
					Entries:   len(m.Entries),
					Conserved: true,
					ZK:        zkStatus,
				})
			}
		}
		if os.Getenv("WEB4_DEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "RECV DELTA_B entries=%d\n", len(m.Entries))
		}
		return nil, true, nil

	default:
		return nil, false, reject("unknown message type", fmt.Errorf("%s", hdr.Type))
	}
}

func recvDataWithResponse(data []byte, st *store.Store, self *node.Node, checker math4.LocalChecker, senderAddr string) ([]byte, bool, *recvError) {
	r := &Runner{
		Store:   st,
		Checker: checker,
		Self:    self,
		Metrics: runtimeMetrics,
	}
	return r.recvDataWithResponse(data, senderAddr)
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
var runtimeMetrics *metrics.Metrics

const (
	nodeModePeer      = "peer"
	nodeModeBootstrap = "bootstrap"

	defaultMaxConnsPeer      = 512
	defaultMaxConnsBootstrap = 128

	defaultMaxStreamsPerConnPeer      = 64
	defaultMaxStreamsPerConnBootstrap = 8

	defaultPeerExchangeMaxPeer      = 64
	defaultPeerExchangeMaxBootstrap = 32
)

func nodeMode() string {
	mode := strings.TrimSpace(strings.ToLower(os.Getenv("WEB4_NODE_MODE")))
	if mode == "" {
		return nodeModePeer
	}
	if mode != nodeModeBootstrap {
		return nodeModePeer
	}
	return mode
}

func applyNodeModeDefaults(mode string) {
	if mode != nodeModeBootstrap {
		mode = nodeModePeer
	}
	setDefaultEnv := func(key string, value int) {
		if os.Getenv(key) != "" {
			return
		}
		_ = os.Setenv(key, strconv.Itoa(value))
	}
	switch mode {
	case nodeModeBootstrap:
		setDefaultEnv("WEB4_MAX_CONNS", defaultMaxConnsBootstrap)
		setDefaultEnv("WEB4_MAX_STREAMS_PER_CONN", defaultMaxStreamsPerConnBootstrap)
		setDefaultEnv("WEB4_PEER_EXCHANGE_MAX", defaultPeerExchangeMaxBootstrap)
	default:
		setDefaultEnv("WEB4_MAX_CONNS", defaultMaxConnsPeer)
		setDefaultEnv("WEB4_MAX_STREAMS_PER_CONN", defaultMaxStreamsPerConnPeer)
		setDefaultEnv("WEB4_PEER_EXCHANGE_MAX", defaultPeerExchangeMaxPeer)
	}
}

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

func msgIDFor(data []byte) string {
	sha := sha256Hex(data)
	if sha == "" {
		return ""
	}
	if len(sha) < 12 {
		return sha
	}
	return sha[:12]
}

func check6Enabled() bool {
	return os.Getenv("WEB4_CHECK6") == "1"
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
	fmt.Fprintf(os.Stderr, "DROP msg_id=%s reason=%s details=%s\n", msgID, reason, details)
}

func handleGossipPush(data []byte, st *store.Store, self *node.Node, checker math4.LocalChecker, senderAddr string) ([]byte, bool, *recvError) {
	msgID := msgIDFor(data)
	check6Phase("PHASE recv_push msg_id=%s", msgID)
	drop := func(reason string, t string, err error) {
		msg := ""
		if err != nil {
			msg = err.Error()
		}
		if os.Getenv("WEB4_DEBUG") == "1" && shouldLogReject(reason) {
			fmt.Fprintf(os.Stderr, "DROP reason=%s from=%s type=%s err=%s\n", reason, senderAddr, t, msg)
		}
		debugCount.incDrop(classifyDropReason(reason, err))
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
		newState, innerErr = handleGossipHello1Payload(envelope, self, senderAddr)
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
			if runtimeMetrics != nil {
				runtimeMetrics.IncGossipRelayed()
				if innerType == proto.MsgTypeDeltaB {
					runtimeMetrics.IncDeltaRelayed()
				}
			}
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
		if runtimeMetrics != nil {
			runtimeMetrics.IncGossipRelayed()
			if innerType == proto.MsgTypeDeltaB {
				runtimeMetrics.IncDeltaRelayed()
			}
		}
	}
}

func handleGossipHello1Payload(data []byte, self *node.Node, senderAddr string) (bool, error) {
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
	h1Bytes := proto.Hello1Bytes(fromID, toID, ea, na)
	h1TranscriptHash := crypto.SHA3_256(h1Bytes)
	sessionID, err := decodeSessionIDHex(m.SessionID)
	if err != nil {
		if !allowLegacyHelloSig() {
			return false, err
		}
	}
	expectedSID := sessionIDForHandshake(fromID, toID, ea, zero32(), h1TranscriptHash)
	if len(sessionID) > 0 && !bytesEqual(sessionID, expectedSID) {
		return false, errors.New("hello1 session_id mismatch")
	}
	sigInput := hello1SigInput(fromID, toID, ea, na, sessionID)
	if len(sessionID) == 0 {
		sigInput = hello1SigInputLegacy(fromID, toID, ea, na)
	}
	if !crypto.VerifyDigest(fromPub, crypto.SHA3_256(sigInput), sig) {
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

func BuildGossipPushForPeer(p peer.Peer, envelope []byte, self *node.Node) ([]byte, error) {
	return buildGossipPushForPeer(p, envelope, gossipHops(), self)
}

func validateInviteCertCert(cert proto.InviteCert, invites *peer.InviteStore, now time.Time) error {
	_, _, err := validateInviteCert(cert, invites, now)
	return err
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

func requiredMemberScope(msgType string) (uint32, bool) {
	switch msgType {
	case proto.MsgTypeContractOpen, proto.MsgTypeRepayReq, proto.MsgTypeAck, proto.MsgTypeDeltaB:
		return proto.InviteScopeContract, true
	default:
		return 0, false
	}
}

func isBootstrapDiscoveryType(msgType string) bool {
	switch msgType {
	case proto.MsgTypeHello1, proto.MsgTypeHello2, proto.MsgTypePeerExchangeReq, proto.MsgTypePeerExchangeResp:
		return true
	default:
		return false
	}
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

func DeltaBContext(msg proto.DeltaBMsg, viewID [32]byte) ([]byte, error) {
	return deltaBContext(msg, viewID)
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

func DeltaBScopeHash(entries []proto.DeltaBEntry) ([32]byte, error) {
	return deltaBScopeHash(entries)
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
	scalars, err := linear.ScalarsFromInt64(values)
	if err != nil {
		return nil, err
	}
	ctx, err := deltaBContext(msg, viewID)
	if err != nil {
		return nil, fmt.Errorf("zk context failed")
	}
	C, r, err := pedersen.CommitVector(scalars, ctx)
	if err != nil {
		return nil, err
	}
	L := [][]int64{make([]int64, len(values))}
	for i := range values {
		L[0][i] = 1
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

func VerifyDeltaBZK(msg proto.DeltaBMsg, viewID [32]byte) error {
	return verifyDeltaBZK(msg, viewID)
}

func membersViewID(members [][32]byte) [32]byte {
	if len(members) == 0 {
		return [32]byte{}
	}
	out := make([][32]byte, len(members))
	copy(out, members)
	sort.Slice(out, func(i, j int) bool {
		return lessNodeID(out[i], out[j])
	})
	buf := make([]byte, 0, len(out)*32+8)
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

func MembersViewID(members [][32]byte) [32]byte {
	return membersViewID(members)
}

func decodeNodeIDHex(s string) ([32]byte, error) {
	var id [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return id, fmt.Errorf("invalid node id")
	}
	copy(id[:], b)
	return id, nil
}

func decodeSigHex(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("missing sig")
	}
	return hex.DecodeString(s)
}

func sigFromBytes(version, suite, msgType string, fromID [32]byte, payload []byte, priv []byte) []byte {
	_ = version
	_ = suite
	_ = msgType
	_ = fromID
	return crypto.Sign(priv, crypto.SHA3_256(payload))
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

func findPeerByAddr(peers []peer.Peer, addr string) (peer.Peer, bool) {
	for _, p := range peers {
		if p.Addr == addr {
			return p, true
		}
	}
	return peer.Peer{}, false
}

func findPeerByNodeID(peers []peer.Peer, id [32]byte) (peer.Peer, bool) {
	for _, p := range peers {
		if p.NodeID == id {
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
	if addr == "" {
		return false
	}
	_, _, err := net.SplitHostPort(addr)
	return err == nil
}

func lessNodeID(a, b [32]byte) bool {
	for i := 0; i < len(a); i++ {
		if a[i] == b[i] {
			continue
		}
		return a[i] < b[i]
	}
	return false
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

func findContractByID(st *store.Store, cid [32]byte) (*proto.Contract, error) {
	if st == nil {
		return nil, fmt.Errorf("store unavailable")
	}
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

const (
	defaultPeerExchangeK = 16
	maxPeerExchangeK     = 64
	defaultGossipFanout  = 2
	maxGossipFanout      = 8
	defaultGossipHops    = 8
	gossipCacheCap       = 2048
	gossipCacheTTL       = 2 * time.Minute
)

func peerExchangeCap() int {
	cap := defaultPeerExchangeMaxPeer
	if v, ok := envInt("WEB4_PEER_EXCHANGE_MAX"); ok && v > 0 {
		cap = v
	}
	if cap > maxPeerExchangeK {
		return maxPeerExchangeK
	}
	return cap
}

func peerExchangeRand() *mrand.Rand {
	seed := time.Now().UnixNano()
	if raw := os.Getenv("WEB4_PEER_EXCHANGE_SEED"); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil {
			seed = v
		}
	}
	return mrand.New(mrand.NewSource(seed))
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
		if v > defaultGossipHops {
			return defaultGossipHops
		}
		return v
	}
	return defaultGossipHops
}

func envInt(key string) (int, bool) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return 0, false
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}
	return n, true
}

type gossipCache struct {
	mu      sync.Mutex
	cap     int
	ttl     time.Duration
	entries map[[32]byte]*list.Element
	order   *list.List
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
		cap:     capacity,
		ttl:     ttl,
		entries: make(map[[32]byte]*list.Element),
		order:   list.New(),
	}
}

func (c *gossipCache) Seen(hash [32]byte) bool {
	if c == nil || c.cap <= 0 {
		return false
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	if el, ok := c.entries[hash]; ok {
		ent := el.Value.(*gossipEntry)
		if ent.expires.After(now) {
			c.order.MoveToFront(el)
			return true
		}
		delete(c.entries, hash)
		c.order.Remove(el)
	}
	return false
}

func (c *gossipCache) Add(hash [32]byte) {
	if c == nil || c.cap <= 0 {
		return
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	if el, ok := c.entries[hash]; ok {
		ent := el.Value.(*gossipEntry)
		ent.expires = now.Add(c.ttl)
		c.order.MoveToFront(el)
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

type deltabCache struct {
	mu       sync.Mutex
	capacity int
	ttl      time.Duration
	order    *list.List
	entries  map[[32]byte]*list.Element
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
	return &deltabCache{
		capacity: capacity,
		ttl:      ttl,
		order:    list.New(),
		entries:  make(map[[32]byte]*list.Element),
	}
}

func (c *deltabCache) Seen(hash [32]byte) bool {
	if c == nil || c.capacity <= 0 {
		return false
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	if el, ok := c.entries[hash]; ok {
		ent := el.Value.(*deltabEntry)
		if ent.expires.After(now) {
			c.order.MoveToFront(el)
			return true
		}
		delete(c.entries, hash)
		c.order.Remove(el)
	}
	return false
}

func (c *deltabCache) Add(hash [32]byte) {
	if c == nil || c.capacity <= 0 {
		return
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	if el, ok := c.entries[hash]; ok {
		ent := el.Value.(*deltabEntry)
		ent.expires = now.Add(c.ttl)
		c.order.MoveToFront(el)
		return
	}
	ent := &deltabEntry{hash: hash, expires: now.Add(c.ttl)}
	el := c.order.PushFront(ent)
	c.entries[hash] = el
	for c.capacity > 0 && len(c.entries) > c.capacity {
		back := c.order.Back()
		if back == nil {
			break
		}
		old := back.Value.(*deltabEntry)
		delete(c.entries, old.hash)
		c.order.Remove(back)
	}
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
	mu     sync.Mutex
	rate   float64
	burst  float64
	ttl    time.Duration
	bucket map[string]*tokenBucket
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

func newDeltabRateLimiter(rate float64, burst float64, ttl time.Duration) *deltabRateLimiter {
	if rate < 0 {
		rate = 0
	}
	if burst < rate {
		burst = rate
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &deltabRateLimiter{
		rate:   rate,
		burst:  burst,
		ttl:    ttl,
		bucket: make(map[string]*tokenBucket),
	}
}

func (l *deltabRateLimiter) Allow(key string) bool {
	if l == nil || key == "" || l.rate <= 0 {
		return true
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.bucket[key]
	if !ok || now.Sub(b.last) > l.ttl {
		l.bucket[key] = &tokenBucket{tokens: l.burst - 1, last: now}
		return true
	}
	delta := now.Sub(b.last).Seconds()
	b.tokens += delta * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens -= 1
	return true
}

type debugCounters struct {
	mu          sync.Mutex
	recvByType  map[string]uint64
	dropReason  map[string]uint64
	verifyFail  map[string]uint64
	decryptFail map[string]uint64
	sendFail    map[string]uint64
	addrChange  map[string]uint64
}

func newDebugCounters() *debugCounters {
	return &debugCounters{
		recvByType:  make(map[string]uint64),
		dropReason:  make(map[string]uint64),
		verifyFail:  make(map[string]uint64),
		decryptFail: make(map[string]uint64),
		sendFail:    make(map[string]uint64),
		addrChange:  make(map[string]uint64),
	}
}

func (c *debugCounters) incRecv(msgType string) {
	c.inc(c.recvByType, "recv_by_type", msgType)
}

func (c *debugCounters) incDrop(reason string) {
	c.inc(c.dropReason, "drop_reason", reason)
}

func (c *debugCounters) incVerify(reason string) {
	c.inc(c.verifyFail, "verify_fail", reason)
}

func (c *debugCounters) incDecrypt(reason string) {
	c.inc(c.decryptFail, "decrypt_fail", reason)
}

func (c *debugCounters) incSend(reason string) {
	c.inc(c.sendFail, "send_fail", reason)
}

func (c *debugCounters) incAddrChange(reason string) {
	c.inc(c.addrChange, "addr_change", reason)
}

func (c *debugCounters) inc(m map[string]uint64, kind, key string) {
	if c == nil || key == "" {
		return
	}
	c.mu.Lock()
	m[key]++
	count := m[key]
	c.mu.Unlock()
	if runtimeMetrics != nil {
		switch kind {
		case "recv_by_type":
			runtimeMetrics.IncRecvByType(key)
		case "drop_reason":
			runtimeMetrics.IncDropByReason(key)
		}
	}
	if os.Getenv("WEB4_DEBUG") == "1" {
		fmt.Fprintf(os.Stderr, "counter kind=%s key=%s count=%d\n", kind, key, count)
	}
}

var debugCount = newDebugCounters()

var recvHostLimiter = newRateLimiter(defaultHostRateLimit, defaultRateWindow)
var recvNodeLimiter = newRateLimiter(defaultNodeRateLimit, defaultRateWindow)
var rejectLogLimiter = newLogLimiter(1 * time.Second)

const (
	defaultHostRateLimit = 50
	defaultNodeRateLimit = 20
	defaultRateWindow    = time.Second
)

type logLimiter struct {
	mu     sync.Mutex
	window time.Duration
	bucket map[string]*logBucket
}

type logBucket struct {
	last  time.Time
	count int
}

func newLogLimiter(window time.Duration) *logLimiter {
	if window <= 0 {
		window = time.Second
	}
	return &logLimiter{
		window: window,
		bucket: make(map[string]*logBucket),
	}
}

func (l *logLimiter) Allow(key string) bool {
	if l == nil || key == "" {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, ok := l.bucket[key]
	if !ok || now.Sub(b.last) > l.window {
		l.bucket[key] = &logBucket{last: now, count: 1}
		return true
	}
	b.count++
	b.last = now
	if b.count == 1 || b.count%10 == 0 {
		return true
	}
	return false
}

func shouldLogReject(reason string) bool {
	mode := nodeMode()
	if mode != nodeModeBootstrap {
		return true
	}
	return rejectLogLimiter.Allow(reason)
}

func classifyDropReason(reason string, err error) string {
	low := strings.ToLower(reason)
	switch {
	case strings.Contains(low, "decode"):
		return "decode"
	case strings.Contains(low, "message too large"), strings.Contains(low, "too large"), strings.Contains(low, "size"):
		return "size"
	case strings.Contains(low, "rate"):
		return "rate"
	case strings.Contains(low, "duplicate"), strings.Contains(low, "already_seen"):
		return "dedupe"
	case strings.Contains(low, "membership"), strings.Contains(low, "non_member"), strings.Contains(low, "scope"):
		return "scope"
	case strings.Contains(low, "sig"):
		return "sig"
	case strings.Contains(low, "powad"):
		return "powad"
	case strings.Contains(low, "zk"):
		return "zk"
	default:
		if err != nil {
			elow := strings.ToLower(err.Error())
			switch {
			case strings.Contains(elow, "not member"), strings.Contains(elow, "member"):
				return "scope"
			case strings.Contains(elow, "zk"):
				return "zk"
			case strings.Contains(elow, "powad"):
				return "powad"
			case strings.Contains(elow, "sig"):
				return "sig"
			case strings.Contains(elow, "rate"):
				return "rate"
			}
		}
		return "other"
	}
}

type rateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	buckets map[string]*rateBucket
}

type rateBucket struct {
	count int
	reset time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	if window <= 0 {
		window = defaultRateWindow
	}
	return &rateLimiter{
		limit:   limit,
		window:  window,
		buckets: make(map[string]*rateBucket),
	}
}

func (r *rateLimiter) Allow(key string) bool {
	if r == nil || key == "" || r.limit <= 0 {
		return true
	}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.buckets[key]
	if !ok || now.After(b.reset) {
		r.buckets[key] = &rateBucket{count: 1, reset: now.Add(r.window)}
		return true
	}
	if b.count >= r.limit {
		return false
	}
	b.count++
	return true
}

func hello1SigInput(fromID, toID [32]byte, ea, na, sessionID []byte) []byte {
	buf := make([]byte, 0, len("web4:h1:v2")+32+32+len(ea)+len(na)+len(sessionID))
	buf = append(buf, []byte("web4:h1:v2")...)
	buf = append(buf, fromID[:]...)
	buf = append(buf, toID[:]...)
	buf = append(buf, ea...)
	buf = append(buf, na...)
	buf = append(buf, sessionID...)
	return buf
}

func hello1SigInputLegacy(fromID, toID [32]byte, ea, na []byte) []byte {
	buf := make([]byte, 0, len("web4:h1:v1")+32+32+len(ea)+len(na))
	buf = append(buf, []byte("web4:h1:v1")...)
	buf = append(buf, fromID[:]...)
	buf = append(buf, toID[:]...)
	buf = append(buf, ea...)
	buf = append(buf, na...)
	return buf
}

func sessionIDForHandshake(fromID, toID [32]byte, ea, eb, transcriptHash []byte) []byte {
	buf := make([]byte, 0, len("WEB4/session")+len(proto.ProtoVersion)+32+32+len(ea)+len(eb)+len(transcriptHash))
	buf = append(buf, []byte("WEB4/session")...)
	buf = append(buf, []byte(proto.ProtoVersion)...)
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

func parseInviteScope(s string) (uint32, error) {
	parts := strings.Split(s, ",")
	var scope uint32
	for _, p := range parts {
		p = strings.TrimSpace(p)
		switch p {
		case "gossip":
			scope |= proto.InviteScopeGossip
		case "contract":
			scope |= proto.InviteScopeContract
		case "all":
			scope |= proto.InviteScopeAll
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

func deltaVectorFromEntries(entries []proto.DeltaBEntry) ([]pedersen.Scalar, [][]int64, error) {
	if len(entries) == 0 {
		return nil, nil, fmt.Errorf("empty entries")
	}
	values := make([]int64, len(entries))
	row := make([]int64, len(entries))
	for i, e := range entries {
		values[i] = e.Delta
		row[i] = 1
	}
	x, err := linear.ScalarsFromInt64(values)
	if err != nil {
		return nil, nil, err
	}
	return x, [][]int64{row}, nil
}

func buildDeltaZK(entries []proto.DeltaBEntry, ctx []byte) (*proto.ZKLinearProof, error) {
	x, L, err := deltaVectorFromEntries(entries)
	if err != nil {
		return nil, err
	}
	C, r, err := pedersen.CommitVector(x, ctx)
	if err != nil {
		return nil, err
	}
	proof, err := linear.ProveLinearNullspace(L, C, r, ctx)
	if err != nil {
		return nil, err
	}
	return linear.EncodeLinearProof(C, proof)
}

func BuildDeltaBZK(entries []proto.DeltaBEntry, ctx []byte) (*proto.ZKLinearProof, error) {
	return buildDeltaZK(entries, ctx)
}

func buildPeerExchangeResp(self *node.Node, k int, listenAddr string) (proto.PeerExchangeRespMsg, error) {
	if self == nil || self.Peers == nil {
		return proto.PeerExchangeRespMsg{}, fmt.Errorf("peer store unavailable")
	}
	if k <= 0 {
		k = defaultPeerExchangeK
	}
	cap := peerExchangeCap()
	if k > cap {
		k = cap
	}
	peers := self.Peers.List()
	bootstrapMode := nodeMode() == nodeModeBootstrap
	if bootstrapMode {
		rng := peerExchangeRand()
		rng.Shuffle(len(peers), func(i, j int) { peers[i], peers[j] = peers[j], peers[i] })
	}
	respPeers := make([]proto.PeerExchangePeer, 0, k)
	for _, p := range peers {
		if len(respPeers) >= k {
			break
		}
		if p.Addr == "" {
			continue
		}
		if len(p.PubKey) == 0 && !bootstrapMode {
			continue
		}
		id := p.NodeID
		if isZeroNodeID(id) {
			if len(p.PubKey) == 0 {
				continue
			}
			id = node.DeriveNodeID(p.PubKey)
		}
		peerMsg := proto.PeerExchangePeer{
			Addr:   p.Addr,
			NodeID: hex.EncodeToString(id[:]),
		}
		if len(p.PubKey) > 0 {
			peerMsg.PubKey = hex.EncodeToString(p.PubKey)
		}
		respPeers = append(respPeers, peerMsg)
	}
	if listenAddr != "" && len(self.PubKey) > 0 && len(respPeers) < k && isValidAddr(listenAddr) {
		selfIDHex := hex.EncodeToString(self.ID[:])
		dup := false
		for _, p := range respPeers {
			if p.NodeID == selfIDHex || p.Addr == listenAddr {
				dup = true
				break
			}
		}
		if !dup {
			respPeers = append(respPeers, proto.PeerExchangePeer{
				Addr:   listenAddr,
				NodeID: selfIDHex,
				PubKey: hex.EncodeToString(self.PubKey),
			})
		}
	}
	if os.Getenv("WEB4_DEBUG") == "1" {
		selfIncluded := false
		selfIDHex := hex.EncodeToString(self.ID[:])
		for _, p := range respPeers {
			if p.NodeID == selfIDHex {
				selfIncluded = true
				break
			}
		}
		fmt.Fprintf(os.Stderr, "peer_exchange_resp peers=%d self_included=%t addr=%s\n", len(respPeers), selfIncluded, listenAddr)
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
	limit := pexInsertCap()
	for i := 0; i < len(resp.Peers); i++ {
		if limit > 0 && added >= limit {
			logPexDrop("cap")
			break
		}
		p, err := decodePeerExchangePeer(resp.Peers[i])
		if err != nil {
			logPexDrop("decode_peer")
			continue
		}
		if !isValidAddr(p.Addr) {
			logPexDrop("invalid_addr")
			continue
		}
		p.Source = "pex"
		p.SubnetKey = peer.SubnetKeyForAddr(p.Addr)
		if p.Addr != "" && self.Candidates != nil {
			self.Candidates.Add(p.Addr)
		}
		if len(p.PubKey) == 0 {
			if err := self.Peers.UpsertUnverified(p); err != nil {
				logPexDrop("upsert_unverified")
				continue
			}
		} else {
			if p.Addr != "" && self.Peers != nil {
				if _, err := self.Peers.SetAddrUnverified(p, p.Addr, true); err != nil {
					logPexDrop("addr_conflict")
				}
				self.Peers.PeerSeen(p.NodeID, p.Addr)
			}
			p.Addr = ""
			if err := self.Peers.Upsert(p, true); err != nil {
				logPexDrop("upsert")
				continue
			}
		}
		added++
	}
	if os.Getenv("WEB4_DEBUG") == "1" {
		fmt.Fprintf(os.Stderr, "peer_exchange_apply peers=%d added=%d\n", len(resp.Peers), added)
	}
	return added, nil
}

var (
	pexDropLogMu  sync.Mutex
	pexDropLog    = make(map[string]time.Time)
	pexDropLogTTL = 30 * time.Second
)

func logPexDrop(reason string) {
	if os.Getenv("WEB4_DEBUG") != "1" || reason == "" {
		return
	}
	now := time.Now()
	pexDropLogMu.Lock()
	last := pexDropLog[reason]
	if now.Sub(last) >= pexDropLogTTL {
		pexDropLog[reason] = now
		pexDropLogMu.Unlock()
		fmt.Fprintf(os.Stderr, "peer_exchange_drop reason=%s\n", reason)
		return
	}
	pexDropLogMu.Unlock()
}

func pexInsertCap() int {
	cap := 64
	if v, ok := envInt("WEB4_PEX_INSERT_MAX"); ok && v > 0 {
		cap = v
	}
	if cap > maxPeerExchangeK {
		return maxPeerExchangeK
	}
	return cap
}

func isValidAddr(addr string) bool {
	if addr == "" {
		return false
	}
	_, _, err := net.SplitHostPort(addr)
	return err == nil
}

func decodePeerExchangePeer(w proto.PeerExchangePeer) (peer.Peer, error) {
	id, err := decodeNodeIDHex(w.NodeID)
	if err != nil {
		return peer.Peer{}, err
	}
	var pub []byte
	if w.PubKey != "" {
		pub, err = hex.DecodeString(w.PubKey)
		if err != nil {
			return peer.Peer{}, fmt.Errorf("bad pubkey")
		}
	}
	p := peer.Peer{
		NodeID: id,
		PubKey: pub,
		Addr:   w.Addr,
	}
	if len(pub) > 0 {
		derived := node.DeriveNodeID(pub)
		if derived != id {
			return peer.Peer{}, fmt.Errorf("node_id mismatch")
		}
	}
	return p, nil
}

func decodeSigFromBytes(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("missing sig")
	}
	return hex.DecodeString(s)
}

func decodeNodeIDHexLower(s string) ([32]byte, error) {
	return decodeNodeIDHex(strings.ToLower(s))
}

func isZeroNodeID(id [32]byte) bool {
	for _, b := range id {
		if b != 0 {
			return false
		}
	}
	return true
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
