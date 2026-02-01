package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"web4mvp/internal/daemon"
	"web4mvp/internal/metrics"
	"web4mvp/internal/node"
	"web4mvp/internal/peer"
	"web4mvp/internal/proto"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
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
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n", args[0])
		printUsage(stderr)
		return 1
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: web4-node <run|status|peers|members|delta|field> [args]")
	fmt.Fprintln(w, "  run    --addr <ip:port> [--devtls] [--debug]")
	fmt.Fprintln(w, "  status")
	fmt.Fprintln(w, "  peers")
	fmt.Fprintln(w, "  members")
	fmt.Fprintln(w, "  delta recent [--n 20]")
	fmt.Fprintln(w, "  field show")
}

func homeDir() string {
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".web4mvp")
}

func runNode(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "", "listen addr (host:port)")
	devTLS := fs.Bool("devtls", false, "allow deterministic dev TLS certs (unsafe)")
	debug := fs.Bool("debug", false, "enable debug logging")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *addr == "" {
		fmt.Fprintln(stderr, "missing --addr")
		return 1
	}
	if *debug {
		_ = os.Setenv("WEB4_DEBUG", "1")
	}
	if !*devTLS {
		fmt.Fprintln(stderr, "dev TLS disabled by default; pass --devtls to enable")
		return 1
	}
	fmt.Fprintln(stderr, "WARNING: using deterministic dev TLS certificates")
	root := homeDir()
	_ = os.Setenv("WEB4_SUPPRESS_READY", "1")
	runner, err := daemon.NewRunner(root, daemon.Options{Metrics: metrics.New()})
	if err != nil {
		fmt.Fprintf(stderr, "load node failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "READY addr=%s node_id=%s\n", *addr, hex.EncodeToString(runner.Self.ID[:]))
	if err := runner.Run(*addr, *devTLS); err != nil {
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
	self, err := node.NewNode(root, node.Options{})
	if err != nil {
		fmt.Fprintf(stdout, "status: node unavailable: %v\n", err)
		return 1
	}
	peers := self.Peers.List()
	connected := 0
	for _, p := range peers {
		if p.Addr != "" {
			connected++
		}
	}
	members := self.Members.List()
	scopeCounts := countScopes(self.Members, members)
	snap := readMetricsSnapshot(filepath.Join(root, "metrics.json"))
	viewCount := countViews(snap.Recent)
	fmt.Fprintln(stdout, "Local observation summary (not consensus):")
	fmt.Fprintf(stdout, "  connected peers: %d\n", connected)
	fmt.Fprintf(stdout, "  members: %d (gossip=%d contract=%d admin=%d)\n", len(members), scopeCounts.gossip, scopeCounts.contract, scopeCounts.admin)
	fmt.Fprintf(stdout, "  Δ verified: %d\n", snap.Delta.Verified)
	fmt.Fprintf(stdout, "  Δ relayed: %d\n", snap.Delta.Relayed)
	fmt.Fprintf(stdout, "  Δ dropped: duplicate=%d rate_limited=%d non_member=%d zk_failed=%d\n",
		snap.Delta.DropDuplicate, snap.Delta.DropRate, snap.Delta.DropNonMember, snap.Delta.DropZKFail)
	fmt.Fprintf(stdout, "  local views: %d\n", viewCount)
	return 0
}

func runPeers(args []string, stdout, _ io.Writer) int {
	fs := flag.NewFlagSet("peers", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 1
	}
	root := homeDir()
	self, err := node.NewNode(root, node.Options{})
	if err != nil {
		fmt.Fprintf(stdout, "peers: node unavailable: %v\n", err)
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
	self, err := node.NewNode(root, node.Options{})
	if err != nil {
		fmt.Fprintf(stdout, "members: node unavailable: %v\n", err)
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
			fmt.Fprintf(stdout, "scope=%s view=%s entries=%d conserved=%v zk=%s\n",
				h.ScopeHash, view, h.Entries, h.Conserved, h.ZK)
		}
		return 0
	default:
		fmt.Fprintf(stdout, "unknown delta subcommand: %s\n", args[0])
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
			fmt.Fprintf(stdout, "field: no local snapshot\n")
			return 0
		}
		fmt.Fprintln(stdout, "Local field φ (not consensus; not transmitted)")
		stdout.Write(data)
		if !bytes.HasSuffix(data, []byte("\n")) {
			fmt.Fprintln(stdout)
		}
		return 0
	default:
		fmt.Fprintf(stdout, "unknown field subcommand: %s\n", args[0])
		return 1
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

func sortPeersByID(peers []peer.Peer) {
	sort.Slice(peers, func(i, j int) bool {
		return bytes.Compare(peers[i].NodeID[:], peers[j].NodeID[:]) < 0
	})
}
