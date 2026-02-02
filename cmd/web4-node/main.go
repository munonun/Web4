package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
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
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n", args[0])
		printUsage(stderr)
		return 1
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: web4-node [run|status|peers|members|delta|field] [args]")
	fmt.Fprintln(w, "  (no args) starts interactive peer mode")
	fmt.Fprintln(w, "  run    --addr <ip:port> [--devtls] [--debug] (interactive if TTY)")
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
	fmt.Fprintf(stdout, "READY addr=%s node_id=%s\n", readyAddr, hex.EncodeToString(runner.Self.ID[:]))
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
	self, err := node.NewNode(root, node.Options{})
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
	members := self.Members.List()
	scopeCounts := countScopes(self.Members, members)
	snap := readMetricsSnapshot(filepath.Join(root, "metrics.json"))
	viewCount := countViews(snap.Recent)
	color.New(color.FgGreen).Fprintln(stdout, "Local observation summary (not consensus):")
	color.New(color.FgHiBlack).Fprintf(stdout, "  connected peers: %d\n", connected)
	color.New(color.FgHiBlack).Fprintf(stdout, "  members: %d (gossip=%d contract=%d admin=%d)\n", len(members), scopeCounts.gossip, scopeCounts.contract, scopeCounts.admin)
	color.New(color.FgHiBlack).Fprintf(stdout, "  Δ verified: %d\n", snap.Delta.Verified)
	color.New(color.FgHiBlack).Fprintf(stdout, "  Δ relayed: %d\n", snap.Delta.Relayed)
	color.New(color.FgHiBlack).Fprintf(stdout, "  Δ dropped: duplicate=%d rate_limited=%d non_member=%d zk_failed=%d\n",
		snap.Delta.DropDuplicate, snap.Delta.DropRate, snap.Delta.DropNonMember, snap.Delta.DropZKFail)
	color.New(color.FgHiBlack).Fprintf(stdout, "  local views: %d\n", viewCount)
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
	self, err := node.NewNode(root, node.Options{})
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
	_, _, errCh, err := startRunner(ctx, addr, devTLS)
	if err != nil {
		fmt.Fprintf(stderr, "load node failed: %v\n", err)
		return 1
	}
	banner(stdout, homeDir())
	handlers := replHandlers{
		help: func(w io.Writer) {
			color.New(color.FgHiBlack).Fprintln(w, "Commands:")
			fmt.Fprintln(w, "  help")
			fmt.Fprintln(w, "  status")
			fmt.Fprintln(w, "  peers")
			fmt.Fprintln(w, "  members")
			fmt.Fprintln(w, "  delta recent [--n N]")
			fmt.Fprintln(w, "  field show")
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

func banner(w io.Writer, root string) {
	peers, scopes := bannerCounts(root)
	color.New(color.FgGreen).Fprintln(w, "Web4 Node running.")
	color.New(color.FgHiBlack).Fprintf(w, "Peers: %d\n", peers)
	color.New(color.FgHiBlack).Fprintf(w, "Scopes: %d\n", scopes)
	color.New(color.FgHiBlack).Fprintln(w, "Role: peer (relay + verifier)")
	color.New(color.FgHiBlack).Fprintln(w, "Type 'help' for commands.")
}

func isInteractive() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
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

type replHandlers struct {
	help        func(io.Writer)
	status      func()
	peers       func()
	members     func()
	deltaRecent func(int)
	fieldShow   func()
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

func sortPeersByID(peers []peer.Peer) {
	sort.Slice(peers, func(i, j int) bool {
		return bytes.Compare(peers[i].NodeID[:], peers[j].NodeID[:]) < 0
	})
}
