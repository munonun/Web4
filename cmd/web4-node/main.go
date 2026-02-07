package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/chzyer/readline"
	"github.com/fatih/color"

	"crypto/rsa"
	"crypto/x509"

	"web4mvp/internal/crypto"
	"web4mvp/internal/daemon"
	"web4mvp/internal/metrics"
	"web4mvp/internal/network"
	"web4mvp/internal/node"
	"web4mvp/internal/peer"
	"web4mvp/internal/proto"
	"web4mvp/internal/wallet"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if !isInteractive() {
		color.NoColor = true
	}
	if len(args) == 0 {
		return runInteractive(stdout, stderr)
	}
	if args[0] == "--help" || args[0] == "-h" {
		printUsage(stdout)
		return 0
	}
	switch args[0] {
	case "run":
		return runNode(args[1:], stdout, stderr)
	case "status":
		return runStatus(args[1:], stdout, stderr)
	case "peers":
		return runPeers(args[1:], stdout, stderr)
	case "members":
		return runMembers(args[1:], stdout, stderr)
	case "delta":
		return runDelta(args[1:], stdout, stderr)
	case "field":
		return runField(args[1:], stdout, stderr)
	case "pay":
		return runPay(args[1:], stdout, stderr)
	case "wallet":
		return runWallet(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n", args[0])
		printUsage(stderr)
		return 1
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: web4-node [run|status|peers|members|delta|field|pay|wallet] [args]")
	fmt.Fprintln(w, "  (no args) starts interactive peer mode")
	fmt.Fprintln(w, "  run    --addr <ip:port> [--devtls] [--debug] [--bootstrap] (interactive if TTY)")
	fmt.Fprintln(w, "  status")
	fmt.Fprintln(w, "  peers")
	fmt.Fprintln(w, "  members")
	fmt.Fprintln(w, "  delta recent [--n 20]")
	fmt.Fprintln(w, "  field show")
	fmt.Fprintln(w, "  pay --to <nodeid> --amount <v> [--scope <s>] [--send] [--devtls] [--devtls-ca <path>]")
	fmt.Fprintln(w, "  wallet show")
	fmt.Fprintln(w, "  wallet list")
	fmt.Fprintln(w, "  wallet new --force")
	fmt.Fprintln(w, "  wallet export --out <file>")
	fmt.Fprintln(w, "  wallet import --in <file> [--force]")
}

func homeDir() string {
	if h := strings.TrimSpace(os.Getenv("HOME")); h != "" {
		return filepath.Join(h, ".web4mvp")
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".web4mvp")
}

func runNode(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "", "listen addr (host:port)")
	devTLS := fs.Bool("devtls", false, "allow deterministic dev TLS certs (unsafe)")
	debug := fs.Bool("debug", false, "enable debug logging")
	bootstrap := fs.Bool("bootstrap", false, "run in bootstrap mode (stricter limits)")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *bootstrap && os.Getenv("WEB4_NODE_MODE") == "" {
		_ = os.Setenv("WEB4_NODE_MODE", "bootstrap")
	}
	if *addr == "" {
		fmt.Fprintln(stderr, "missing --addr")
		return 1
	}
	if *debug {
		_ = os.Setenv("WEB4_DEBUG", "1")
	}
	if !*devTLS {
		color.New(color.FgYellow).Fprintln(stderr, "dev TLS disabled by default; pass --devtls to enable")
		return 1
	}
	color.New(color.FgYellow).Fprintln(stderr, "WARNING: using deterministic dev TLS certificates")
	if isInteractive() {
		return runInteractiveWithAddr(stdout, stderr, *addr, *devTLS)
	}
	runner, readyAddr, errCh, err := startRunner(context.Background(), *addr, *devTLS)
	if err != nil {
		fmt.Fprintf(stderr, "load node failed: %v\n", err)
		return 1
	}
	runner.StartSnapshotWriter(time.Second)
	defer runner.StopSnapshotWriter()
	printWalletLine(stdout, runner.Self)
	printModeSummary(stderr, runner.Mode)
	fmt.Fprintf(stdout, "READY addr=%s node_id=%s\n", readyAddr, hex.EncodeToString(runner.Self.ID[:]))
	startBootstrapConnections(context.Background(), runner.Self, *devTLS)
	if err := <-errCh; err != nil {
		fmt.Fprintf(stderr, "run failed: %v\n", err)
		return 1
	}
	return 0
}

func runStatus(args []string, stdout, _ io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 1
	}
	root := homeDir()
	self, err := loadNode(root)
	if err != nil {
		color.New(color.FgRed).Fprintf(stdout, "status: node unavailable: %v\n", err)
		return 1
	}
	peers := self.Peers.List()
	connected := 0
	for _, p := range peers {
		if p.Addr != "" {
			connected++
		}
	}
	peerTotal := len(peers)
	outboundTarget := envIntDefault("WEB4_OUTBOUND_TARGET", 12)
	exploreSlots := envIntDefault("WEB4_OUTBOUND_EXPLORE", 2)
	pexInterval := envIntDefault("WEB4_PEX_INTERVAL_SEC", 20)
	if v := envIntDefault("WEB4_PEX_INTERVAL_MS", 0); v > 0 {
		pexInterval = v / 1000
		if pexInterval == 0 {
			pexInterval = 1
		}
	}
	peertableMax := envIntDefault("WEB4_PEERTABLE_MAX", 2048)
	subnetMax := envIntDefault("WEB4_SUBNET_MAX", 32)
	members := self.Members.List()
	scopeCounts := countScopes(self.Members, members)
	snap := readMetricsSnapshot(filepath.Join(root, "metrics.json"))
	viewCount := countViews(snap.Recent)
	color.New(color.FgGreen).Fprintln(stdout, "Local observation summary (not consensus):")
	color.New(color.FgHiBlack).Fprintf(stdout, "  peers: %d total, %d connected\n", peerTotal, connected)
	color.New(color.FgHiBlack).Fprintf(stdout, "  outbound target: %d explore: %d pex interval: %ds\n", outboundTarget, exploreSlots, pexInterval)
	color.New(color.FgHiBlack).Fprintf(stdout, "  peertable max: %d subnet max: %d\n", peertableMax, subnetMax)
	color.New(color.FgHiBlack).Fprintf(stdout, "  current conns: %d streams: %d\n", snap.CurrentConns, snap.CurrentStreams)
	if snap.PeerTableSize > 0 || snap.OutboundConnected > 0 || snap.InboundConnected > 0 {
		color.New(color.FgHiBlack).Fprintf(stdout, "  observed peertable: %d outbound: %d inbound: %d\n", snap.PeerTableSize, snap.OutboundConnected, snap.InboundConnected)
	}
	if snap.DialAttemptsTotal > 0 || snap.DialSuccessTotal > 0 || snap.PexReqSentTotal > 0 || snap.PexRespRecvTotal > 0 {
		color.New(color.FgHiBlack).Fprintf(stdout, "  dial attempts: %d success: %d pex sent: %d recv: %d\n",
			snap.DialAttemptsTotal, snap.DialSuccessTotal, snap.PexReqSentTotal, snap.PexRespRecvTotal)
	}
	color.New(color.FgHiBlack).Fprintf(stdout, "  members: %d (gossip=%d contract=%d admin=%d)\n", len(members), scopeCounts.gossip, scopeCounts.contract, scopeCounts.admin)
	color.New(color.FgHiBlack).Fprintf(stdout, "  Δ verified: %d\n", snap.Delta.Verified)
	color.New(color.FgHiBlack).Fprintf(stdout, "  Δ relayed: %d\n", snap.Delta.Relayed)
	color.New(color.FgHiBlack).Fprintf(stdout, "  Δ dropped: duplicate=%d rate_limited=%d non_member=%d zk_failed=%d\n",
		snap.Delta.DropDuplicate, snap.Delta.DropRate, snap.Delta.DropNonMember, snap.Delta.DropZKFail)
	if len(snap.DropByReason) > 0 {
		color.New(color.FgHiBlack).Fprintln(stdout, "  drops by reason:")
		keys := make([]string, 0, len(snap.DropByReason))
		for k := range snap.DropByReason {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			color.New(color.FgHiBlack).Fprintf(stdout, "    %s: %d\n", k, snap.DropByReason[k])
		}
	}
	if len(snap.RecvByType) > 0 {
		color.New(color.FgHiBlack).Fprintln(stdout, "  recv by type:")
		keys := make([]string, 0, len(snap.RecvByType))
		for k := range snap.RecvByType {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			color.New(color.FgHiBlack).Fprintf(stdout, "    %s: %d\n", k, snap.RecvByType[k])
		}
	}
	color.New(color.FgHiBlack).Fprintf(stdout, "  local views: %d\n", viewCount)
	return 0
}

func runPeers(args []string, stdout, _ io.Writer) int {
	fs := flag.NewFlagSet("peers", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 1
	}
	root := homeDir()
	self, err := loadNode(root)
	if err != nil {
		color.New(color.FgRed).Fprintf(stdout, "peers: node unavailable: %v\n", err)
		return 1
	}
	for _, p := range self.Peers.List() {
		id := hex.EncodeToString(p.NodeID[:])
		if p.Addr == "" {
			fmt.Fprintf(stdout, "%s addr=unknown\n", id)
			continue
		}
		fmt.Fprintf(stdout, "%s addr=%s\n", id, p.Addr)
	}
	return 0
}

func runMembers(args []string, stdout, _ io.Writer) int {
	fs := flag.NewFlagSet("members", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 1
	}
	root := homeDir()
	self, err := loadNode(root)
	if err != nil {
		color.New(color.FgRed).Fprintf(stdout, "members: node unavailable: %v\n", err)
		return 1
	}
	ids := self.Members.List()
	for _, id := range ids {
		scope, _ := self.Members.Scope(id)
		fmt.Fprintf(stdout, "%s scope=%d\n", hex.EncodeToString(id[:]), scope)
	}
	return 0
}

func runDelta(args []string, stdout, _ io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(stdout, "usage: web4-node delta recent [--n 20]")
		return 0
	}
	switch args[0] {
	case "recent":
		fs := flag.NewFlagSet("delta recent", flag.ContinueOnError)
		n := fs.Int("n", 20, "max entries")
		if err := fs.Parse(args[1:]); err != nil {
			return 1
		}
		root := homeDir()
		snap := readMetricsSnapshot(filepath.Join(root, "metrics.json"))
		recent := snap.Recent
		if *n > 0 && len(recent) > *n {
			recent = recent[len(recent)-*n:]
		}
		for _, h := range recent {
			view := h.ViewID
			if len(view) > 8 {
				view = view[:8]
			}
			zk := colorZKStatus(h.ZK)
			fmt.Fprintf(stdout, "scope=%s view=%s entries=%d conserved=%v zk=%s\n",
				h.ScopeHash, view, h.Entries, h.Conserved, zk)
		}
		return 0
	default:
		color.New(color.FgRed).Fprintf(stdout, "unknown delta subcommand: %s\n", args[0])
		return 1
	}
}

func runField(args []string, stdout, _ io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(stdout, "usage: web4-node field show")
		return 0
	}
	switch args[0] {
	case "show":
		root := homeDir()
		path := filepath.Join(root, "field.json")
		data, err := os.ReadFile(path)
		if err != nil {
			color.New(color.FgYellow).Fprintln(stdout, "field: no local snapshot")
			return 0
		}
		color.New(color.FgHiBlack).Fprintln(stdout, "Local field φ (not consensus; not transmitted)")
		stdout.Write(data)
		if !bytes.HasSuffix(data, []byte("\n")) {
			fmt.Fprintln(stdout)
		}
		return 0
	default:
		color.New(color.FgRed).Fprintf(stdout, "unknown field subcommand: %s\n", args[0])
		return 1
	}
}

func claimStorePath(root string) string {
	return filepath.Join(root, "claims.jsonl")
}

type walletExport struct {
	Algo          string `json:"algo"`
	NodeIDHex     string `json:"node_id_hex"`
	PrivateKeyPEM string `json:"private_key_pem"`
	PublicKeyPEM  string `json:"public_key_pem,omitempty"`
}

func loadNode(root string) (*node.Node, error) {
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, fmt.Errorf("home not writable: %w", err)
	}
	self, err := node.NewNode(root, node.Options{})
	if err != nil {
		return nil, err
	}
	if err := ensureWalletFiles(root, self); err != nil {
		return nil, err
	}
	return self, nil
}

func ensureWalletFiles(root string, self *node.Node) error {
	if self == nil {
		return fmt.Errorf("missing node")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return fmt.Errorf("home not writable: %w", err)
	}
	nodeIDHex := hex.EncodeToString(self.ID[:])
	if err := os.WriteFile(filepath.Join(root, "node_id.hex"), []byte(nodeIDHex), 0600); err != nil {
		return fmt.Errorf("write node_id.hex: %w", err)
	}
	if len(self.PrivKey) > 0 {
		privHex := hex.EncodeToString(self.PrivKey)
		if err := os.WriteFile(filepath.Join(root, "id_key"), []byte(privHex), 0600); err != nil {
			return fmt.Errorf("write id_key: %w", err)
		}
	}
	return nil
}

func exportWallet(root, out string) error {
	pub, priv, err := crypto.LoadKeypair(root)
	if err != nil {
		return err
	}
	privKey, err := crypto.ParseRSAPrivateKey(priv)
	if err != nil {
		return err
	}
	pubKey, err := crypto.ParseRSAPublicKey(pub)
	if err != nil {
		return err
	}
	privDER := x509.MarshalPKCS1PrivateKey(privKey)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER})
	pubDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	id := node.DeriveNodeID(pub)
	payload := walletExport{
		Algo:          "rsa",
		NodeIDHex:     hex.EncodeToString(id[:]),
		PrivateKeyPEM: string(privPEM),
		PublicKeyPEM:  string(pubPEM),
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(out, data, 0600)
}

func importWallet(root, in string, force bool) error {
	if err := os.MkdirAll(root, 0700); err != nil {
		return fmt.Errorf("home not writable: %w", err)
	}
	if !force {
		if _, err := os.Stat(filepath.Join(root, "priv.hex")); err == nil {
			return fmt.Errorf("existing wallet found; use --force to overwrite")
		}
	}
	data, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	var payload walletExport
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}
	if payload.Algo != "" && payload.Algo != "rsa" {
		return fmt.Errorf("unsupported algo")
	}
	privKey, pubKey, err := parseWalletKeys(payload)
	if err != nil {
		return err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return err
	}
	id := node.DeriveNodeID(pubDER)
	if payload.NodeIDHex != "" && payload.NodeIDHex != hex.EncodeToString(id[:]) {
		if os.Getenv("WEB4_DEBUG") == "1" {
			return fmt.Errorf("node_id mismatch file=%s computed=%s", payload.NodeIDHex, hex.EncodeToString(id[:]))
		}
		return fmt.Errorf("node_id mismatch")
	}
	if err := crypto.SaveKeypair(root, pubDER, privDER); err != nil {
		return err
	}
	if err := ensureWalletFiles(root, &node.Node{ID: id, PubKey: pubDER, PrivKey: privDER}); err != nil {
		return err
	}
	return nil
}

func shortFingerprint(pub []byte) string {
	sum := crypto.SHA3_256(pub)
	return hex.EncodeToString(sum[:4])
}

func parseWalletKeys(payload walletExport) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	if strings.TrimSpace(payload.PrivateKeyPEM) == "" {
		return nil, nil, fmt.Errorf("missing private_key_pem")
	}
	block, _ := pem.Decode([]byte(payload.PrivateKeyPEM))
	if block == nil {
		return nil, nil, fmt.Errorf("invalid private_key_pem")
	}
	var privKey *rsa.PrivateKey
	if block.Type == "RSA PRIVATE KEY" {
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("bad private_key_pem")
		}
		privKey = k
	} else {
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("bad private_key_pem")
		}
		rsaKey, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("bad private_key_pem")
		}
		privKey = rsaKey
	}
	var pubKey *rsa.PublicKey
	if strings.TrimSpace(payload.PublicKeyPEM) == "" {
		pubKey = &privKey.PublicKey
	} else {
		pb, _ := pem.Decode([]byte(payload.PublicKeyPEM))
		if pb == nil {
			return nil, nil, fmt.Errorf("invalid public_key_pem")
		}
		k, err := x509.ParsePKIXPublicKey(pb.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("bad public_key_pem")
		}
		rsaKey, ok := k.(*rsa.PublicKey)
		if !ok {
			return nil, nil, fmt.Errorf("bad public_key_pem")
		}
		pubKey = rsaKey
	}
	return privKey, pubKey, nil
}

func rotateWallet(root string) (string, string, []string, error) {
	self, err := loadNode(root)
	if err != nil {
		return "", "", nil, err
	}
	oldID := hex.EncodeToString(self.ID[:])
	pub, priv, err := crypto.GenKeypair()
	if err != nil {
		return "", "", nil, err
	}
	if err := crypto.SaveKeypair(root, pub, priv); err != nil {
		return "", "", nil, err
	}
	cleared, err := clearIdentityStores(root)
	if err != nil {
		return "", "", nil, err
	}
	newSelf, err := loadNode(root)
	if err != nil {
		return "", "", nil, err
	}
	newID := hex.EncodeToString(newSelf.ID[:])
	return oldID, newID, cleared, nil
}

func clearIdentityStores(root string) ([]string, error) {
	paths := []string{
		filepath.Join(root, "peers.jsonl"),
		filepath.Join(root, "members.jsonl"),
		filepath.Join(root, "invites.jsonl"),
		filepath.Join(root, "revokes.jsonl"),
		filepath.Join(root, "claims.jsonl"),
		filepath.Join(root, "field.json"),
		filepath.Join(root, "metrics.json"),
	}
	var cleared []string
	for _, base := range paths {
		matches, err := filepath.Glob(base + "*")
		if err != nil {
			return cleared, err
		}
		for _, p := range matches {
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				return cleared, err
			}
			cleared = append(cleared, p)
		}
	}
	return cleared, nil
}

func resolveRecipient(self *node.Node, raw string) ([32]byte, string, error) {
	var toID [32]byte
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return toID, "", fmt.Errorf("missing recipient")
	}
	if self != nil && self.Peers != nil {
		_ = self.Peers.Refresh()
	}
	if decoded, err := hex.DecodeString(raw); err == nil && len(decoded) == 32 {
		copy(toID[:], decoded)
		if p, ok := findPeerByNodeID(self.Peers.List(), toID); ok {
			return toID, p.Addr, nil
		}
		return toID, "", nil
	}
	if p, ok := findPeerByAddr(self.Peers.List(), raw); ok {
		return p.NodeID, p.Addr, nil
	}
	return toID, "", fmt.Errorf("unknown recipient")
}

func parseNodeIDHex(raw string) ([32]byte, error) {
	var id [32]byte
	raw = strings.TrimSpace(raw)
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != 32 {
		return id, fmt.Errorf("bad node_id")
	}
	copy(id[:], decoded)
	return id, nil
}

func canonicalDeltaBForPay(msg proto.DeltaBMsg) (proto.DeltaBMsg, []byte, [32]byte, [32]byte, error) {
	canonEntries, err := proto.CanonicalizeDeltaBEntries(msg.Entries)
	if err != nil {
		return proto.DeltaBMsg{}, nil, [32]byte{}, [32]byte{}, err
	}
	msg.Entries = canonEntries
	msg.Type = proto.MsgTypeDeltaB
	data, err := proto.EncodeDeltaBMsg(msg)
	if err != nil {
		return proto.DeltaBMsg{}, nil, [32]byte{}, [32]byte{}, err
	}
	var deltaID [32]byte
	copy(deltaID[:], crypto.SHA3_256(data))
	scopeHash, err := daemon.DeltaBScopeHash(canonEntries)
	if err != nil {
		return proto.DeltaBMsg{}, nil, [32]byte{}, [32]byte{}, err
	}
	return msg, data, deltaID, scopeHash, nil
}

func preparePayDelta(self *node.Node, toID [32]byte, amount int64) (wallet.Claim, proto.DeltaBMsg, []byte, [32]byte, [32]byte, [32]byte, error) {
	var zero [32]byte
	if self == nil {
		return wallet.Claim{}, proto.DeltaBMsg{}, nil, zero, zero, zero, fmt.Errorf("node unavailable")
	}
	if self.Members != nil {
		_ = self.Members.Refresh()
	}
	if amount <= 0 {
		return wallet.Claim{}, proto.DeltaBMsg{}, nil, zero, zero, zero, fmt.Errorf("amount must be positive")
	}
	viewID := daemon.MembersViewID(self.Members.List())
	viewHex := hex.EncodeToString(viewID[:])
	claim, err := wallet.NewClaim(hex.EncodeToString(self.ID[:]), hex.EncodeToString(toID[:]), amount)
	if err != nil {
		return wallet.Claim{}, proto.DeltaBMsg{}, nil, zero, zero, zero, fmt.Errorf("claim failed: %w", err)
	}
	msg := proto.DeltaBMsg{
		Type:         proto.MsgTypeDeltaB,
		ProtoVersion: proto.ProtoVersion,
		Suite:        proto.Suite,
		ViewID:       viewHex,
		CtxTag:       "web4/wallet/pay/v0",
		ClaimID:      claim.ID,
		Entries: []proto.DeltaBEntry{
			{NodeID: hex.EncodeToString(self.ID[:]), Delta: -1 * amount},
			{NodeID: hex.EncodeToString(toID[:]), Delta: amount},
		},
	}
	canonMsg, canonBytes, deltaID, scopeHash, err := canonicalDeltaBForPay(msg)
	if err != nil {
		return wallet.Claim{}, proto.DeltaBMsg{}, nil, zero, zero, zero, fmt.Errorf("invalid delta_b: %w", err)
	}
	claim.ViewID = viewHex
	claim.ScopeHash = hex.EncodeToString(scopeHash[:])
	claim.DeltaID = hex.EncodeToString(deltaID[:])
	if os.Getenv("WEB4_ZK_MODE") == "1" {
		ctx, err := daemon.DeltaBContext(canonMsg, viewID)
		if err != nil {
			return wallet.Claim{}, proto.DeltaBMsg{}, nil, zero, zero, zero, fmt.Errorf("zk ctx failed: %w", err)
		}
		zk, err := daemon.BuildDeltaBZK(canonMsg.Entries, ctx)
		if err != nil {
			return wallet.Claim{}, proto.DeltaBMsg{}, nil, zero, zero, zero, fmt.Errorf("zk proof failed: %w", err)
		}
		canonMsg.ZK = zk
		canonBytes, err = proto.EncodeDeltaBMsg(canonMsg)
		if err != nil {
			return wallet.Claim{}, proto.DeltaBMsg{}, nil, zero, zero, zero, fmt.Errorf("encode delta_b failed: %w", err)
		}
		copy(deltaID[:], crypto.SHA3_256(canonBytes))
		claim.DeltaID = hex.EncodeToString(deltaID[:])
	}
	return claim, canonMsg, canonBytes, deltaID, scopeHash, viewID, nil
}

func sendDeltaBToPeers(self *node.Node, toID [32]byte, toAddr string, payload []byte, devTLS bool, devTLSCA string) error {
	if self == nil || self.Peers == nil {
		return fmt.Errorf("peer store unavailable")
	}
	_ = self.Peers.Refresh()
	peers := self.Peers.List()
	var targets []peer.Peer
	if toAddr != "" {
		if p, ok := findPeerByAddr(peers, toAddr); ok {
			targets = []peer.Peer{p}
		}
	}
	if len(targets) == 0 && !isZeroNodeID(toID) {
		if p, ok := findPeerByNodeID(peers, toID); ok {
			targets = []peer.Peer{p}
		}
	}
	if len(targets) == 0 {
		for _, p := range peers {
			if p.Addr != "" && len(p.PubKey) > 0 {
				targets = append(targets, p)
			}
		}
	}
	if len(targets) == 0 {
		return fmt.Errorf("no peers to send")
	}
	devTLSCAPath := devTLSCA
	if devTLSCAPath == "" {
		devTLSCAPath = filepath.Join(homeDir(), "devtls_ca.pem")
	}
	for _, p := range targets {
		if p.Addr == "" {
			continue
		}
		if !self.Sessions.Has(p.NodeID) {
			if err := handshakeWithPeer(context.Background(), self, p.NodeID, p.Addr, devTLS, devTLSCAPath); err != nil {
				return err
			}
		}
		out, err := daemon.SealSecureEnvelope(self, p.NodeID, proto.MsgTypeDeltaB, "", payload)
		if err != nil {
			return err
		}
		if err := network.Send(p.Addr, out, false, devTLS, devTLSCAPath); err != nil {
			return err
		}
	}
	return nil
}

func sendPeerExchangeToPeers(self *node.Node, toID [32]byte, toAddr string, devTLS bool, devTLSCA string) error {
	if self == nil || self.Peers == nil {
		return fmt.Errorf("peer store unavailable")
	}
	_ = self.Peers.Refresh()
	peers := self.Peers.List()
	var targets []peer.Peer
	if toAddr != "" {
		if p, ok := findPeerByAddr(peers, toAddr); ok {
			targets = []peer.Peer{p}
		}
	}
	if len(targets) == 0 && !isZeroNodeID(toID) {
		if p, ok := findPeerByNodeID(peers, toID); ok {
			targets = []peer.Peer{p}
		}
	}
	if len(targets) == 0 {
		for _, p := range peers {
			if p.Addr != "" && len(p.PubKey) > 0 {
				targets = append(targets, p)
			}
		}
	}
	if len(targets) == 0 {
		return fmt.Errorf("no peers to exchange")
	}
	devTLSCAPath := devTLSCA
	if devTLSCAPath == "" {
		devTLSCAPath = filepath.Join(homeDir(), "devtls_ca.pem")
	}
	for _, p := range targets {
		if p.Addr == "" {
			continue
		}
		if !self.Sessions.Has(p.NodeID) {
			if err := handshakeWithPeer(context.Background(), self, p.NodeID, p.Addr, devTLS, devTLSCAPath); err != nil {
				return err
			}
		}
		req := proto.PeerExchangeReqMsg{
			Type:         proto.MsgTypePeerExchangeReq,
			ProtoVersion: proto.ProtoVersion,
			Suite:        proto.Suite,
			K:            8,
			FromNodeID:   hex.EncodeToString(self.ID[:]),
		}
		data, err := proto.EncodePeerExchangeReq(req)
		if err != nil {
			return err
		}
		secureReq, err := daemon.SealSecureEnvelope(self, p.NodeID, proto.MsgTypePeerExchangeReq, "", data)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err = network.ExchangeWithContext(ctx, p.Addr, secureReq, false, devTLS, devTLSCAPath)
		cancel()
		if err != nil {
			return err
		}
	}
	return nil
}

func isZeroNodeID(id [32]byte) bool {
	var zero [32]byte
	return id == zero
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

func runPay(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	to := fs.String("to", "", "recipient node id hex")
	amount := fs.Int64("amount", 0, "amount to transfer")
	scope := fs.String("scope", "", "optional scope hint (unused in v0)")
	send := fs.Bool("send", false, "gossip delta to peers")
	devTLS := fs.Bool("devtls", false, "allow deterministic dev TLS certs (unsafe)")
	devTLSCA := fs.String("devtls-ca", "", "dev TLS CA PEM path")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *to == "" || *amount <= 0 {
		fmt.Fprintln(stderr, "missing --to or --amount")
		return 1
	}
	if *scope != "" {
		color.New(color.FgYellow).Fprintln(stderr, "warning: --scope is ignored in v0; derived from entries")
	}
	root := homeDir()
	self, err := loadNode(root)
	if err != nil {
		color.New(color.FgRed).Fprintf(stderr, "pay: node unavailable: %v\n", err)
		return 1
	}
	toID, err := parseNodeIDHex(*to)
	if err != nil {
		color.New(color.FgRed).Fprintf(stderr, "pay: %v\n", err)
		return 1
	}
	toAddr := ""
	if p, ok := findPeerByNodeID(self.Peers.List(), toID); ok {
		toAddr = p.Addr
	}
	color.New(color.FgHiBlack).Fprintf(stdout, "Sender: %s\n", hex.EncodeToString(self.ID[:]))
	claim, _, canonBytes, _, _, _, err := preparePayDelta(self, toID, *amount)
	if err != nil {
		color.New(color.FgRed).Fprintf(stderr, "pay: %v\n", err)
		return 1
	}
	store, err := wallet.NewStore(claimStorePath(root))
	if err != nil {
		color.New(color.FgRed).Fprintf(stderr, "pay: claim store failed: %v\n", err)
		return 1
	}
	if err := store.Add(claim); err != nil {
		color.New(color.FgRed).Fprintf(stderr, "pay: store claim failed: %v\n", err)
		return 1
	}
	color.New(color.FgGreen).Fprintf(stdout, "OK claim stored id=%s delta_id=%s\n", claim.ID, claim.DeltaID)
	if *send {
		if !*devTLS {
			color.New(color.FgYellow).Fprintln(stderr, "dev TLS disabled by default; pass --devtls to enable")
			return 1
		}
		if toAddr == "" {
			color.New(color.FgRed).Fprintln(stderr, "pay: recipient addr unknown (not in peers list)")
			return 1
		}
		if err := sendDeltaBToPeers(self, toID, toAddr, canonBytes, *devTLS, *devTLSCA); err != nil {
			color.New(color.FgRed).Fprintf(stderr, "pay: send failed: %v\n", err)
			return 1
		}
		if err := sendPeerExchangeToPeers(self, toID, toAddr, *devTLS, *devTLSCA); err != nil && os.Getenv("WEB4_DEBUG") == "1" {
			color.New(color.FgYellow).Fprintf(stderr, "pay: peer exchange skipped: %v\n", err)
		}
		color.New(color.FgGreen).Fprintln(stdout, "OK delta_b sent (local observation)")
	}
	return 0
}

func runWallet(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: wallet [show|list|new|export|import]")
		return 1
	}
	switch args[0] {
	case "show":
		root := homeDir()
		self, err := loadNode(root)
		if err != nil {
			color.New(color.FgRed).Fprintf(stderr, "wallet: %v\n", err)
			return 1
		}
		members := self.Members.List()
		scopeCounts := countScopes(self.Members, members)
		mode := strings.TrimSpace(os.Getenv("WEB4_NODE_MODE"))
		if mode == "" {
			mode = "peer"
		}
		fmt.Fprintf(stdout, "wallet: %s\n", hex.EncodeToString(self.ID[:]))
		fmt.Fprintf(stdout, "pubkey_fingerprint: %s\n", shortFingerprint(self.PubKey))
		fmt.Fprintf(stdout, "mode: %s\n", mode)
		fmt.Fprintf(stdout, "members: %d (gossip=%d contract=%d admin=%d)\n", len(members), scopeCounts.gossip, scopeCounts.contract, scopeCounts.admin)
		return 0
	case "list":
		fs := flag.NewFlagSet("wallet list", flag.ContinueOnError)
		limit := fs.Int("n", 20, "max items")
		if err := fs.Parse(args[1:]); err != nil {
			return 1
		}
		root := homeDir()
		store, err := wallet.NewStore(claimStorePath(root))
		if err != nil {
			color.New(color.FgRed).Fprintf(stderr, "wallet: %v\n", err)
			return 1
		}
		claims, err := store.List(*limit)
		if err != nil {
			color.New(color.FgRed).Fprintf(stderr, "wallet: %v\n", err)
			return 1
		}
		for _, c := range claims {
			fmt.Fprintf(stdout, "%s from=%s to=%s amount=%d view=%s delta=%s\n",
				c.ID, c.FromNode, c.ToNode, c.Amount, c.ViewID, c.DeltaID)
		}
		return 0
	case "new":
		fs := flag.NewFlagSet("wallet new", flag.ContinueOnError)
		force := fs.Bool("force", false, "confirm rotation")
		if err := fs.Parse(args[1:]); err != nil {
			return 1
		}
		if !*force {
			color.New(color.FgRed).Fprintln(stderr, "wallet new requires --force")
			return 1
		}
		root := homeDir()
		oldID, newID, cleared, err := rotateWallet(root)
		if err != nil {
			color.New(color.FgRed).Fprintf(stderr, "wallet: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "wallet rotated -> node reset (old=%s new=%s)\n", oldID, newID)
		if len(cleared) > 0 {
			fmt.Fprintln(stdout, "cleared:")
			for _, p := range cleared {
				fmt.Fprintf(stdout, "  %s\n", p)
			}
		}
		return 0
	case "export":
		fs := flag.NewFlagSet("wallet export", flag.ContinueOnError)
		out := fs.String("out", "", "output file path")
		if err := fs.Parse(args[1:]); err != nil {
			return 1
		}
		if *out == "" {
			color.New(color.FgRed).Fprintln(stderr, "wallet export requires --out")
			return 1
		}
		root := homeDir()
		if err := exportWallet(root, *out); err != nil {
			color.New(color.FgRed).Fprintf(stderr, "wallet: %v\n", err)
			return 1
		}
		color.New(color.FgGreen).Fprintln(stdout, "wallet exported")
		return 0
	case "import":
		fs := flag.NewFlagSet("wallet import", flag.ContinueOnError)
		in := fs.String("in", "", "input file path")
		force := fs.Bool("force", false, "overwrite existing keys")
		if err := fs.Parse(args[1:]); err != nil {
			return 1
		}
		if *in == "" {
			color.New(color.FgRed).Fprintln(stderr, "wallet import requires --in")
			return 1
		}
		root := homeDir()
		if err := importWallet(root, *in, *force); err != nil {
			color.New(color.FgRed).Fprintf(stderr, "wallet: %v\n", err)
			return 1
		}
		color.New(color.FgGreen).Fprintln(stdout, "wallet imported")
		return 0
	default:
		fmt.Fprintln(stderr, "usage: wallet [show|list|new|export|import]")
		return 1
	}
}

func runInteractive(stdout, stderr io.Writer) int {
	addr := strings.TrimSpace(os.Getenv("WEB4_ADDR"))
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	return runInteractiveWithAddr(stdout, stderr, addr, true)
}

func runInteractiveWithAddr(stdout, stderr io.Writer, addr string, devTLS bool) int {
	if os.Getenv("WEB4_DEBUG") == "1" {
		_ = os.Setenv("WEB4_DEBUG", "1")
	}
	color.New(color.FgYellow).Fprintln(stderr, "WARNING: using deterministic dev TLS certificates")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runner, _, errCh, err := startRunner(ctx, addr, devTLS)
	if err != nil {
		fmt.Fprintf(stderr, "load node failed: %v\n", err)
		return 1
	}
	runner.StartSnapshotWriter(time.Second)
	defer runner.StopSnapshotWriter()
	banner(stdout, homeDir(), runner.Mode, runner.Self)
	startBootstrapConnections(ctx, runner.Self, devTLS)
	handlers := replHandlers{
		help: func(w io.Writer) {
			color.New(color.FgHiBlack).Fprintln(w, "Commands:")
			fmt.Fprintln(w, "  help")
			fmt.Fprintln(w, "  status")
			fmt.Fprintln(w, "  peers")
			fmt.Fprintln(w, "  members")
			fmt.Fprintln(w, "  delta recent [--n N]")
			fmt.Fprintln(w, "  field show")
			fmt.Fprintln(w, "  wallet show|list|new --force|export --out <file>|import --in <file> [--force]")
			fmt.Fprintln(w, "  pay --to <nodeid> --amount <n> [--send]")
			fmt.Fprintln(w, "  quit | exit")
		},
		status: func() {
			_ = runStatus(nil, stdout, stderr)
		},
		peers: func() {
			_ = runPeers(nil, stdout, stderr)
		},
		members: func() {
			_ = runMembers(nil, stdout, stderr)
		},
		deltaRecent: func(n int) {
			args := []string{"recent", "--n", strconv.Itoa(n)}
			_ = runDelta(args, stdout, stderr)
		},
		fieldShow: func() {
			_ = runField([]string{"show"}, stdout, stderr)
		},
		wallet: func(args []string) {
			_ = runWallet(args, stdout, stderr)
		},
		pay: func(args []string) {
			_ = runPay(args, stdout, stderr)
		},
		unknown: func(w io.Writer) {
			color.New(color.FgRed).Fprintln(w, "unknown command; type 'help'")
		},
	}
	if err := runRepl(stdout, handlers); err != nil {
		color.New(color.FgRed).Fprintf(stderr, "repl error: %v\n", err)
	}
	cancel()
	if err := <-errCh; err != nil && ctx.Err() == nil {
		color.New(color.FgRed).Fprintf(stderr, "run failed: %v\n", err)
		return 1
	}
	return 0
}

func startRunner(ctx context.Context, addr string, devTLS bool) (*daemon.Runner, string, <-chan error, error) {
	root := homeDir()
	_ = os.Setenv("WEB4_SUPPRESS_READY", "1")
	runner, err := daemon.NewRunner(root, daemon.Options{Metrics: metrics.New()})
	if err != nil {
		return nil, "", nil, err
	}
	if err := ensureWalletFiles(root, runner.Self); err != nil {
		return nil, "", nil, err
	}
	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- runner.RunWithContext(ctx, addr, devTLS, ready)
	}()
	readyAddr := addr
	select {
	case readyAddr = <-ready:
	case <-time.After(2 * time.Second):
	}
	return runner, readyAddr, errCh, nil
}

func banner(w io.Writer, root string, mode string, self *node.Node) {
	peers, scopes := bannerCounts(root)
	color.New(color.FgGreen).Fprintln(w, "Web4 Node running.")
	printWalletLine(w, self)
	printModeSummary(w, mode)
	color.New(color.FgHiBlack).Fprintf(w, "Peers: %d\n", peers)
	color.New(color.FgHiBlack).Fprintf(w, "Scopes: %d\n", scopes)
	color.New(color.FgHiBlack).Fprintln(w, "Type 'help' for commands.")
}

func printModeSummary(w io.Writer, mode string) {
	role := mode
	if role == "" {
		role = "peer"
	}
	maxConns := getenvInt("WEB4_MAX_CONNS", 0)
	maxStreams := getenvInt("WEB4_MAX_STREAMS_PER_CONN", 0)
	peerCap := getenvInt("WEB4_PEER_EXCHANGE_MAX", 0)
	color.New(color.FgHiBlack).Fprintf(w, "Mode: %s\n", role)
	color.New(color.FgHiBlack).Fprintf(w, "Role: %s\n", roleForMode(role))
	color.New(color.FgHiBlack).Fprintf(w, "Limits: max_conns=%d streams/conn=%d peer_exchange_max=%d\n", maxConns, maxStreams, peerCap)
}

func printWalletLine(w io.Writer, self *node.Node) {
	if self == nil {
		return
	}
	color.New(color.FgHiBlack).Fprintf(w, "Wallet: %s\n", hex.EncodeToString(self.ID[:]))
}

func getenvInt(key string, def int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return v
}

func roleForMode(mode string) string {
	switch mode {
	case "bootstrap":
		return "bootstrap (peer discovery / exchange only)"
	default:
		return "peer (relay + verifier)"
	}
}

func isInteractive() bool {
	inInfo, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	outInfo, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (inInfo.Mode()&os.ModeCharDevice) != 0 && (outInfo.Mode()&os.ModeCharDevice) != 0
}

func bannerCounts(root string) (int, int) {
	self, err := node.NewNode(root, node.Options{})
	if err != nil {
		return 0, 0
	}
	peers := 0
	for _, p := range self.Peers.List() {
		if p.Addr != "" {
			peers++
		}
	}
	scopes := len(self.Members.List())
	return peers, scopes
}

type bootstrapPeer struct {
	addr string
	id   [32]byte
}

func parseBootstrapPeers() []bootstrapPeer {
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
		if addr == "" || idHex == "" {
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

func startBootstrapConnections(ctx context.Context, self *node.Node, devTLS bool) {
	peers := parseBootstrapPeers()
	if len(peers) == 0 || self == nil {
		return
	}
	go func() {
		for _, p := range peers {
			if ctx.Err() != nil {
				return
			}
			if err := handshakeWithPeer(ctx, self, p.id, p.addr, devTLS, ""); err != nil {
				if os.Getenv("WEB4_DEBUG") == "1" {
					color.New(color.FgYellow).Fprintf(os.Stderr, "bootstrap connect failed addr=%s err=%v\n", p.addr, err)
				}
			}
		}
	}()
}

func handshakeWithPeer(ctx context.Context, self *node.Node, peerID [32]byte, addr string, devTLS bool, devTLSCAPath string) error {
	if self == nil {
		return fmt.Errorf("missing node")
	}
	hello1, err := self.BuildHello1(peerID)
	if err != nil {
		return err
	}
	data, err := proto.EncodeHello1Msg(hello1)
	if err != nil {
		return err
	}
	if devTLSCAPath == "" {
		devTLSCAPath = filepath.Join(homeDir(), "devtls_ca.pem")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	respData, err := network.ExchangeWithContext(ctx, addr, data, false, devTLS, devTLSCAPath)
	if err != nil {
		return err
	}
	hello2, err := proto.DecodeHello2Msg(respData)
	if err != nil {
		return err
	}
	return self.HandleHello2(hello2)
}

type replHandlers struct {
	help        func(io.Writer)
	status      func()
	peers       func()
	members     func()
	deltaRecent func(int)
	fieldShow   func()
	wallet      func([]string)
	pay         func([]string)
	unknown     func(io.Writer)
}

func runRepl(w io.Writer, handlers replHandlers) error {
	home, _ := os.UserHomeDir()
	historyPath := filepath.Join(home, ".web4", "node_history")
	_ = os.MkdirAll(filepath.Dir(historyPath), 0700)
	rl, err := readline.NewEx(&readline.Config{
		Prompt:                 "web4> ",
		HistoryFile:            historyPath,
		AutoComplete:           replCompleter(),
		InterruptPrompt:        "",
		EOFPrompt:              "",
		DisableAutoSaveHistory: false,
	})
	if err != nil {
		return err
	}
	defer rl.Close()

	for {
		line, err := rl.Readline()
		if err == readline.ErrInterrupt {
			color.New(color.FgYellow).Fprintln(w, "type 'quit' to exit")
			continue
		}
		if err == io.EOF {
			return nil
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if dispatchRepl(line, w, handlers) {
			return nil
		}
	}
}

func replCompleter() readline.AutoCompleter {
	return readline.NewPrefixCompleter(
		readline.PcItem("help"),
		readline.PcItem("status"),
		readline.PcItem("peers"),
		readline.PcItem("members"),
		readline.PcItem("delta", readline.PcItem("recent")),
		readline.PcItem("field", readline.PcItem("show")),
		readline.PcItem("wallet",
			readline.PcItem("show"),
			readline.PcItem("list"),
			readline.PcItem("new"),
			readline.PcItem("export"),
			readline.PcItem("import"),
		),
		readline.PcItem("pay"),
		readline.PcItem("exit"),
		readline.PcItem("quit"),
	)
}

func dispatchRepl(line string, w io.Writer, handlers replHandlers) bool {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false
	}
	switch fields[0] {
	case "help":
		if handlers.help != nil {
			handlers.help(w)
		}
	case "status":
		if handlers.status != nil {
			handlers.status()
		}
	case "peers":
		if handlers.peers != nil {
			handlers.peers()
		}
	case "members":
		if handlers.members != nil {
			handlers.members()
		}
	case "delta":
		if len(fields) >= 2 && fields[1] == "recent" {
			n := parseRecentN(fields[2:])
			if handlers.deltaRecent != nil {
				handlers.deltaRecent(n)
			}
		} else if handlers.unknown != nil {
			handlers.unknown(w)
		}
	case "field":
		if len(fields) >= 2 && fields[1] == "show" {
			if handlers.fieldShow != nil {
				handlers.fieldShow()
			}
		} else if handlers.unknown != nil {
			handlers.unknown(w)
		}
	case "wallet":
		if handlers.wallet != nil {
			handlers.wallet(fields[1:])
		}
	case "pay":
		if handlers.pay != nil {
			handlers.pay(fields[1:])
		}
	case "quit", "exit":
		return true
	default:
		if handlers.unknown != nil {
			handlers.unknown(w)
		}
	}
	return false
}

func parseRecentN(args []string) int {
	n := 20
	if len(args) == 0 {
		return n
	}
	if len(args) >= 2 && args[0] == "--n" {
		if v, err := strconv.Atoi(args[1]); err == nil && v > 0 {
			return v
		}
		return n
	}
	if v, err := strconv.Atoi(args[0]); err == nil && v > 0 {
		return v
	}
	return n
}

func colorZKStatus(status string) string {
	switch status {
	case "ok":
		return color.New(color.FgGreen).Sprint(status)
	case "missing":
		return color.New(color.FgYellow).Sprint(status)
	case "fail":
		return color.New(color.FgRed).Sprint(status)
	default:
		return status
	}
}

type scopeSummary struct {
	gossip   int
	contract int
	admin    int
}

func countScopes(members *peer.MemberStore, ids [][32]byte) scopeSummary {
	var out scopeSummary
	for _, id := range ids {
		scope, _ := members.Scope(id)
		if scope&proto.InviteScopeGossip != 0 {
			out.gossip++
		}
		if scope&proto.InviteScopeContract != 0 {
			out.contract++
		}
		if scope&proto.InviteScopeAdmin != 0 {
			out.admin++
		}
	}
	return out
}

func readMetricsSnapshot(path string) metrics.Snapshot {
	data, err := os.ReadFile(path)
	if err != nil {
		return metrics.Snapshot{}
	}
	var snap metrics.Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return metrics.Snapshot{}
	}
	return snap
}

func countViews(recent []metrics.DeltaHeader) int {
	if len(recent) == 0 {
		return 0
	}
	seen := make(map[string]struct{}, len(recent))
	for _, h := range recent {
		key := strings.ToLower(h.ViewID)
		if key == "" {
			continue
		}
		seen[key] = struct{}{}
	}
	return len(seen)
}

func envIntDefault(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func sortPeersByID(peers []peer.Peer) {
	sort.Slice(peers, func(i, j int) bool {
		return bytes.Compare(peers[i].NodeID[:], peers[j].NodeID[:]) < 0
	})
}
