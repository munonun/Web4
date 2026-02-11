package daemon

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"web4mvp/internal/crypto"
	"web4mvp/internal/metrics"
	"web4mvp/internal/network"
	"web4mvp/internal/node"
	"web4mvp/internal/peer"
	"web4mvp/internal/proto"
)

const (
	defaultOutboundTarget  = 12
	defaultOutboundExplore = 2
	defaultMaxBackoffSec   = 300
	defaultPexIntervalSec  = 20
	defaultPeertableMax    = 2048
	defaultSubnetMax       = 32
	outboundSuccessWindow  = 60 * time.Second
	backoffBase            = 2 * time.Second
	backoffJitter          = 1 * time.Second
)

var connManTick = 5 * time.Second

type connMan struct {
	self      *node.Node
	metrics   *metrics.Metrics
	devTLS    bool
	devTLSCA  string
	root      string
	mu        sync.Mutex
	nextTry   map[[32]byte]time.Time
	outbound  map[[32]byte]time.Time
	rng       *rand.Rand
	bootstrap []string
	bootPeers []bootstrapPeer
	dialLog   map[[32]byte]time.Time
	addrLog   map[string]time.Time
}

func startConnMan(ctx context.Context, r *Runner, devTLS bool) {
	if r == nil || r.Self == nil || r.Self.Peers == nil {
		return
	}
	cm := newConnMan(r, devTLS)
	go cm.run(ctx)
	go cm.runPex(ctx)
}

func newConnMan(r *Runner, devTLS bool) *connMan {
	devTLSCA := ""
	if devTLS {
		path := filepath.Join(r.Root, "devtls_ca.pem")
		if envPath := os.Getenv("WEB4_DEVTLS_CA_PATH"); envPath != "" {
			path = envPath
		}
		if fi, err := os.Stat(path); err == nil {
			devTLSCA = path
			if os.Getenv("WEB4_DEBUG") == "1" {
				fmt.Fprintf(os.Stderr, "connman tls devtls_ca_path=%s exists=true size=%d\n", path, fi.Size())
			}
		} else if os.Getenv("WEB4_DEBUG") == "1" {
			fmt.Fprintf(os.Stderr, "connman tls devtls_ca_path=%s exists=false size=0\n", path)
		}
	}
	return &connMan{
		self:      r.Self,
		metrics:   r.Metrics,
		devTLS:    devTLS,
		devTLSCA:  devTLSCA,
		root:      r.Root,
		nextTry:   make(map[[32]byte]time.Time),
		outbound:  make(map[[32]byte]time.Time),
		rng:       rand.New(rand.NewSource(time.Now().UnixNano())),
		bootstrap: bootstrapAddrs(),
		bootPeers: bootstrapPeers(),
		dialLog:   make(map[[32]byte]time.Time),
		addrLog:   make(map[string]time.Time),
	}
}

func (c *connMan) run(ctx context.Context) {
	c.seedBootstrap()
	c.tickSeeds(ctx)
	ticker := time.NewTicker(connManTickDuration())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.tickOutbound(ctx)
			c.tickSeeds(ctx)
		}
	}
}

func (c *connMan) runPex(ctx context.Context) {
	interval := pexInterval()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.tickPex(ctx)
		}
	}
}

func (c *connMan) seedBootstrap() {
	if c.self == nil || c.self.Candidates == nil {
		return
	}
	for _, addr := range c.bootstrap {
		if !isValidAddr(addr) {
			continue
		}
		c.self.Candidates.Add(addr)
		if c.self.Peers != nil {
			p := peer.Peer{
				NodeID:    bootstrapSeedNodeID(addr),
				Addr:      addr,
				Source:    "seed",
				SubnetKey: peer.SubnetKeyForAddr(addr),
			}
			_ = c.self.Peers.UpsertUnverified(p)
		}
	}
	if c.self.Peers != nil {
		for _, bp := range c.bootPeers {
			if bp.addr == "" || isZeroNodeID(bp.id) || !isValidAddr(bp.addr) {
				continue
			}
			p := peer.Peer{
				NodeID:    bp.id,
				Addr:      bp.addr,
				Source:    "seed",
				SubnetKey: peer.SubnetKeyForAddr(bp.addr),
			}
			_ = c.self.Peers.UpsertUnverified(p)
		}
	}
}

func (c *connMan) tickOutbound(ctx context.Context) {
	if c.self == nil || c.self.Peers == nil {
		return
	}
	now := time.Now()
	c.pruneOutbound(now)

	target := outboundTarget()
	explore := outboundExplore()
	need := target - c.outboundCount()
	if need < 0 {
		need = 0
	}
	filter := peer.PeerFilter{AllowNoAddr: false}
	peers := c.self.Peers.ListPeersRanked(0, filter)
	c.pickAndConnect(ctx, peers, need, false)
	if explore > 0 {
		c.pickAndConnect(ctx, peers, explore, true)
	}
	c.enforcePeertableMax()
	c.updateMetrics(now)
}

func (c *connMan) tickPex(ctx context.Context) {
	if c.self == nil || c.self.Peers == nil {
		return
	}
	peers := c.self.Peers.ListPeersRanked(64, peer.PeerFilter{AllowNoAddr: false})
	if c.self.Sessions != nil {
		connected := make([]peer.Peer, 0, len(peers))
		for _, p := range peers {
			if c.self.Sessions.Has(p.NodeID) {
				connected = append(connected, p)
			}
		}
		if len(connected) > 0 {
			peers = connected
		}
	}
	if len(peers) == 0 && len(c.bootstrap) == 0 {
		return
	}
	if len(peers) > 0 {
		target := peers[0]
		if len(peers) > 1 && c.rng.Intn(4) == 0 {
			target = peers[c.rng.Intn(len(peers))]
		}
		_ = c.sendPeerExchange(ctx, target)
	} else {
		c.sendPeerExchangePlain(ctx, c.bootstrap)
	}
	c.enforcePeertableMax()
}

func (c *connMan) tickSeeds(ctx context.Context) {
	if c.self == nil || len(c.bootstrap) == 0 {
		return
	}
	if c.self.Peers == nil {
		return
	}
	if len(c.self.Peers.ListPeersRanked(1, peer.PeerFilter{AllowNoAddr: false, Source: "pex"})) > 0 {
		return
	}
	if len(c.self.Peers.ListPeersRanked(1, peer.PeerFilter{AllowNoAddr: false, Source: "manual"})) > 0 {
		return
	}
	c.sendPeerExchangePlain(ctx, c.bootstrap)
}

func (c *connMan) pickAndConnect(ctx context.Context, peers []peer.Peer, count int, explore bool) {
	if count <= 0 {
		return
	}
	now := time.Now()
	candidates := peers
	if explore && len(peers) > 2 {
		candidates = peers[len(peers)/2:]
	}
	for i := 0; i < len(candidates) && count > 0; i++ {
		p := candidates[i]
		if p.Addr == "" || isZeroNodeID(p.NodeID) {
			continue
		}
		if !c.shouldTry(p.NodeID, now) {
			continue
		}
		if c.isOutboundConnected(p.NodeID) {
			continue
		}
		if err := c.handshake(ctx, p.NodeID, p.Addr); err != nil {
			c.logDialError(p.NodeID, err)
			c.markFailure(p.NodeID)
			continue
		}
		c.markSuccess(p.NodeID)
		count--
	}
}

func (c *connMan) handshake(ctx context.Context, peerID [32]byte, addr string) error {
	if c.self == nil {
		return fmt.Errorf("missing node")
	}
	if c.metrics != nil {
		c.metrics.IncDialAttemptsTotal()
	}
	if connManDialHook != nil {
		connManDialHook()
	}
	hello1, err := c.self.BuildHello1(peerID)
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
	ctx, cancel := context.WithTimeout(ctx, dialTimeout())
	defer cancel()
	respData, err := network.ExchangeOnceWithContext(ctx, addr, data, false, c.devTLS, c.devTLSCA)
	if err != nil {
		return err
	}
	if c.metrics != nil {
		c.metrics.IncDialSuccessTotal()
	}
	resp, err := proto.DecodeHello2Msg(respData)
	if err != nil {
		return err
	}
	if err := c.self.HandleHello2(resp); err != nil {
		return err
	}
	return nil
}

func (c *connMan) sendPeerExchange(ctx context.Context, p peer.Peer) error {
	if p.Addr == "" || isZeroNodeID(p.NodeID) {
		return fmt.Errorf("missing peer addr")
	}
	if c.self == nil {
		return fmt.Errorf("missing node")
	}
	c.ensurePubKey()
	if !c.self.Sessions.Has(p.NodeID) {
		if err := c.handshake(ctx, p.NodeID, p.Addr); err != nil {
			c.markFailure(p.NodeID)
			return err
		}
		c.markSuccess(p.NodeID)
	}
	if c.metrics != nil {
		c.metrics.IncPexRequestsTotal()
		c.metrics.IncPexReqSentTotal()
	}
	reqK := defaultPeerExchangeK
	if cap := peerExchangeCap(); reqK > cap {
		reqK = cap
	}
	req := proto.PeerExchangeReqMsg{
		Type:         proto.MsgTypePeerExchangeReq,
		ProtoVersion: proto.ProtoVersion,
		Suite:        proto.Suite,
		K:            reqK,
	}
	req.FromNodeID = hex.EncodeToString(c.self.ID[:])
	req.PubKey = hex.EncodeToString(c.self.PubKey)
	if req.PubKey == "" {
		return fmt.Errorf("missing pubkey")
	}
	data, err := proto.EncodePeerExchangeReq(req)
	if err != nil {
		return err
	}
	if err := enforceTypeMax(proto.MsgTypePeerExchangeReq, len(data)); err != nil {
		return err
	}
	secureReq, err := sealSecureEnvelope(c.self, p.NodeID, proto.MsgTypePeerExchangeReq, "", data)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, dialTimeout())
	defer cancel()
	respData, err := network.ExchangeOnceWithContext(ctx, p.Addr, secureReq, false, c.devTLS, c.devTLSCA)
	if err != nil {
		c.markFailure(p.NodeID)
		return err
	}
	env, err := proto.DecodeSecureEnvelope(respData)
	if err != nil {
		return err
	}
	msgType, plain, _, err := openSecureEnvelope(c.self, env)
	if err != nil {
		return err
	}
	if msgType != proto.MsgTypePeerExchangeResp {
		return fmt.Errorf("unexpected peer exchange resp: %s", msgType)
	}
	resp, err := proto.DecodePeerExchangeResp(plain)
	if err != nil {
		return err
	}
	if c.metrics != nil {
		c.metrics.IncPexResponsesTotal()
		c.metrics.IncPexRespRecvTotal()
	}
	if _, err := applyPeerExchangeResp(c.self, resp); err != nil {
		return err
	}
	c.promoteSeed(resp, p.Addr)
	return nil
}

func (c *connMan) sendPeerExchangePlain(ctx context.Context, addrs []string) {
	if c.self == nil {
		return
	}
	c.ensurePubKey()
	for _, addr := range addrs {
		if !isValidAddr(addr) {
			continue
		}
		if c.metrics != nil {
			c.metrics.IncPexRequestsTotal()
			c.metrics.IncPexReqSentTotal()
			c.metrics.IncDialAttemptsTotal()
		}
		reqK := defaultPeerExchangeK
		if cap := peerExchangeCap(); reqK > cap {
			reqK = cap
		}
		req := proto.PeerExchangeReqMsg{
			Type:         proto.MsgTypePeerExchangeReq,
			ProtoVersion: proto.ProtoVersion,
			Suite:        proto.Suite,
			K:            reqK,
		}
		req.FromNodeID = hex.EncodeToString(c.self.ID[:])
		req.PubKey = hex.EncodeToString(c.self.PubKey)
		data, err := proto.EncodePeerExchangeReq(req)
		if err != nil {
			continue
		}
		if err := enforceTypeMax(proto.MsgTypePeerExchangeReq, len(data)); err != nil {
			continue
		}
		reqCtx, cancel := context.WithTimeout(ctx, dialTimeout())
		respData, err := network.ExchangeOnceWithContext(reqCtx, addr, data, false, c.devTLS, c.devTLSCA)
		cancel()
		if err != nil {
			c.logPexError(addr, err)
			continue
		}
		if c.metrics != nil {
			c.metrics.IncDialSuccessTotal()
		}
		resp, err := proto.DecodePeerExchangeResp(respData)
		if err != nil {
			c.logPexError(addr, err)
			continue
		}
		if c.metrics != nil {
			c.metrics.IncPexResponsesTotal()
			c.metrics.IncPexRespRecvTotal()
		}
		if _, err := applyPeerExchangeResp(c.self, resp); err != nil {
			continue
		}
		c.promoteSeed(resp, addr)
	}
}

func (c *connMan) ensurePubKey() {
	if c.self == nil || len(c.self.PubKey) > 0 || c.root == "" {
		return
	}
	pub, _, err := crypto.LoadKeypair(c.root)
	if err != nil || len(pub) == 0 {
		return
	}
	c.self.PubKey = pub
}

func (c *connMan) promoteSeed(resp proto.PeerExchangeRespMsg, seedAddr string) {
	if seedAddr == "" || c.self == nil || c.self.Peers == nil {
		return
	}
	for _, msg := range resp.Peers {
		if msg.Addr != seedAddr {
			continue
		}
		p, err := decodePeerExchangePeer(msg)
		if err != nil {
			continue
		}
		p.Source = "seed"
		p.SubnetKey = peer.SubnetKeyForAddr(p.Addr)
		_, _ = c.self.Peers.SetAddrUnverified(p, p.Addr, true)
		_ = c.self.Peers.Upsert(p, true)
		return
	}
}

func (c *connMan) enforcePeertableMax() {
	if c.self == nil || c.self.Peers == nil {
		return
	}
	limit := peertableMax()
	subnetMax := subnetMax()
	evicted := c.self.Peers.EvictToMax(limit, subnetMax)
	if evicted > 0 && c.metrics != nil {
		c.metrics.IncEvictionCountTotal()
	}
}

func (c *connMan) updateMetrics(now time.Time) {
	if c.metrics == nil {
		return
	}
	count := c.outboundCount()
	c.metrics.SetOutboundConnected(uint64(count))
	total := network.CurrentConns()
	inbound := uint64(0)
	if total > uint64(count) {
		inbound = total - uint64(count)
	}
	c.metrics.SetInboundConnected(inbound)
	if c.self != nil && c.self.Peers != nil {
		c.metrics.SetPeerTableSize(uint64(len(c.self.Peers.List())))
	}
}

func (c *connMan) pruneOutbound(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, ts := range c.outbound {
		if now.Sub(ts) > outboundSuccessWindow {
			delete(c.outbound, id)
		}
	}
}

func (c *connMan) outboundCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.outbound)
}

func (c *connMan) isOutboundConnected(id [32]byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.outbound[id]
	return ok
}

func (c *connMan) markSuccess(id [32]byte) {
	if c.self != nil && c.self.Peers != nil {
		c.self.Peers.PeerSuccess(id, 0)
	}
	now := time.Now()
	c.mu.Lock()
	delete(c.nextTry, id)
	c.outbound[id] = now
	c.mu.Unlock()
}

func (c *connMan) markFailure(id [32]byte) {
	if c.self != nil && c.self.Peers != nil {
		c.self.Peers.PeerFail(id)
	}
	now := time.Now()
	backoff := nextBackoffDuration(c.self, id, c.rng)
	c.mu.Lock()
	c.nextTry[id] = now.Add(backoff)
	c.mu.Unlock()
}

func (c *connMan) shouldTry(id [32]byte, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	next, ok := c.nextTry[id]
	if !ok {
		return true
	}
	return now.After(next)
}

func nextBackoffDuration(self *node.Node, id [32]byte, rng *rand.Rand) time.Duration {
	failCount := 0
	if self != nil && self.Peers != nil {
		if p, ok := self.Peers.Get(id); ok {
			failCount = p.FailCount
		}
	}
	if failCount < 0 {
		failCount = 0
	}
	shift := failCount
	if shift > 30 {
		shift = 30
	}
	backoff := backoffBase * time.Duration(1<<shift)
	jitter := time.Duration(rng.Int63n(int64(backoffJitter)))
	raw := backoff + jitter
	if raw > maxBackoff() {
		return maxBackoff()
	}
	return raw
}

func outboundTarget() int {
	if v, ok := envInt("WEB4_OUTBOUND_TARGET"); ok && v > 0 {
		return v
	}
	return defaultOutboundTarget
}

func outboundExplore() int {
	if v, ok := envInt("WEB4_OUTBOUND_EXPLORE"); ok && v > 0 {
		return v
	}
	return defaultOutboundExplore
}

func maxBackoff() time.Duration {
	if v, ok := envInt("WEB4_OUTBOUND_MAX_BACKOFF_SEC"); ok && v > 0 {
		return time.Duration(v) * time.Second
	}
	return time.Duration(defaultMaxBackoffSec) * time.Second
}

var connManDialHook func()

const dialLogTTL = 30 * time.Second

func (c *connMan) logDialError(id [32]byte, err error) {
	if os.Getenv("WEB4_DEBUG") != "1" || err == nil {
		return
	}
	now := time.Now()
	c.mu.Lock()
	last := c.dialLog[id]
	if now.Sub(last) < dialLogTTL {
		c.mu.Unlock()
		return
	}
	c.dialLog[id] = now
	c.mu.Unlock()
	fmt.Fprintf(os.Stderr, "connman dial failed node=%x err=%v\n", id[:], err)
}

func (c *connMan) logAddrError(addr string, err error) {
	if os.Getenv("WEB4_DEBUG") != "1" || err == nil || addr == "" {
		return
	}
	now := time.Now()
	c.mu.Lock()
	last := c.addrLog[addr]
	if now.Sub(last) < dialLogTTL {
		c.mu.Unlock()
		return
	}
	c.addrLog[addr] = now
	c.mu.Unlock()
	fmt.Fprintf(os.Stderr, "connman dial failed addr=%s err=%v\n", addr, err)
}

func (c *connMan) logPexError(addr string, err error) {
	if err == nil || addr == "" {
		return
	}
	now := time.Now()
	c.mu.Lock()
	last := c.addrLog[addr]
	if now.Sub(last) < dialLogTTL {
		c.mu.Unlock()
		return
	}
	c.addrLog[addr] = now
	c.mu.Unlock()
	fmt.Fprintf(os.Stderr, "pex dial failed addr=%s err=%v\n", addr, err)
}

func pexInterval() time.Duration {
	if v, ok := envInt("WEB4_PEX_INTERVAL_MS"); ok && v > 0 {
		return time.Duration(v) * time.Millisecond
	}
	if v, ok := envInt("WEB4_PEX_INTERVAL_SEC"); ok && v > 0 {
		return time.Duration(v) * time.Second
	}
	return time.Duration(defaultPexIntervalSec) * time.Second
}

func connManTickDuration() time.Duration {
	if v, ok := envInt("WEB4_CONNMAN_TICK_MS"); ok && v > 0 {
		return time.Duration(v) * time.Millisecond
	}
	return connManTick
}

func dialTimeout() time.Duration {
	if v, ok := envInt("WEB4_DIAL_TIMEOUT_MS"); ok && v > 0 {
		return time.Duration(v) * time.Millisecond
	}
	return 8 * time.Second
}

func peertableMax() int {
	if v, ok := envInt("WEB4_PEERTABLE_MAX"); ok && v > 0 {
		return v
	}
	return defaultPeertableMax
}

func subnetMax() int {
	if v, ok := envInt("WEB4_SUBNET_MAX"); ok && v > 0 {
		return v
	}
	return defaultSubnetMax
}

func bootstrapAddrs() []string {
	raw := strings.TrimSpace(os.Getenv("WEB4_BOOTSTRAP_ADDRS"))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		addr := strings.TrimSpace(part)
		if addr == "" {
			continue
		}
		if !isValidAddr(addr) {
			continue
		}
		out = append(out, addr)
	}
	return out
}

type bootstrapPeer struct {
	addr string
	id   [32]byte
}

func bootstrapPeers() []bootstrapPeer {
	rawAddrs := strings.TrimSpace(os.Getenv("WEB4_BOOTSTRAP_ADDRS"))
	rawIDs := strings.TrimSpace(os.Getenv("WEB4_BOOTSTRAP_IDS"))
	if rawAddrs == "" || rawIDs == "" {
		return nil
	}
	addrs := strings.Split(rawAddrs, ",")
	ids := strings.Split(rawIDs, ",")
	if len(addrs) != len(ids) {
		return nil
	}
	out := make([]bootstrapPeer, 0, len(addrs))
	for i := range addrs {
		addr := strings.TrimSpace(addrs[i])
		idHex := strings.TrimSpace(ids[i])
		if addr == "" || idHex == "" || !isValidAddr(addr) {
			continue
		}
		raw, err := hex.DecodeString(idHex)
		if err != nil || len(raw) != 32 {
			continue
		}
		var id [32]byte
		copy(id[:], raw)
		out = append(out, bootstrapPeer{addr: addr, id: id})
	}
	return out
}

func bootstrapSeedNodeID(addr string) [32]byte {
	sum := crypto.SHA3_256([]byte("web4:bootstrap:" + addr))
	var id [32]byte
	copy(id[:], sum)
	return id
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
