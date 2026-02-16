package node

import (
	"os"
	"path/filepath"
	"sync"
	"time"

	"web4mvp/internal/crypto"
	"web4mvp/internal/peer"
	"web4mvp/internal/state"
)

type Node struct {
	ID         [32]byte
	PubKey     []byte
	PrivKey    []byte
	Peers      *peer.Store
	Members    *peer.MemberStore
	Invites    *peer.InviteStore
	Revokes    *peer.RevokeStore
	Candidates *peer.CandidatePool
	Sessions   *SessionStore
	Field      *state.Field
	listenMu   sync.RWMutex
	listenAddr string
}

type Options struct {
	PeerStorePath   string
	PeerStoreCap    int
	PeerStoreTTL    time.Duration
	PeerStoreLoad   int
	MemberStorePath string
	MemberStoreCap  int
	MemberStoreTTL  time.Duration
	MemberStoreLoad int
	InviteStorePath string
	InviteStoreCap  int
	InviteStoreTTL  time.Duration
	InviteStoreLoad int
	RevokeStorePath string
	RevokeStoreCap  int
	RevokeStoreTTL  time.Duration
	RevokeStoreLoad int
	CandidateCap    int
	CandidateTTL    time.Duration
}

const defaultPeerBook = "peers.jsonl"
const defaultMemberBook = "members.jsonl"
const defaultInviteBook = "invites.jsonl"
const defaultRevokeBook = "revokes.jsonl"

func NewNode(home string, opts Options) (*Node, error) {
	if err := os.MkdirAll(home, 0700); err != nil {
		return nil, err
	}
	pub, priv, err := crypto.LoadKeypair(home)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		pub, priv, err = crypto.GenKeypair()
		if err != nil {
			return nil, err
		}
		if err := crypto.SaveKeypair(home, pub, priv); err != nil {
			return nil, err
		}
	}
	id := DeriveNodeID(pub)
	path := opts.PeerStorePath
	if path == "" {
		path = filepath.Join(home, defaultPeerBook)
	}
	peers, err := peer.NewStore(path, peer.Options{
		Cap:          opts.PeerStoreCap,
		TTL:          opts.PeerStoreTTL,
		LoadLimit:    opts.PeerStoreLoad,
		DeriveNodeID: DeriveNodeID,
	})
	if err != nil {
		return nil, err
	}
	memberPath := opts.MemberStorePath
	if memberPath == "" {
		memberPath = filepath.Join(home, defaultMemberBook)
	}
	members, err := peer.NewMemberStore(memberPath, peer.MemberOptions{
		Cap:       opts.MemberStoreCap,
		TTL:       opts.MemberStoreTTL,
		LoadLimit: opts.MemberStoreLoad,
	})
	if err != nil {
		return nil, err
	}
	if err := members.AddWithScope(id, peer.DefaultMemberScope, true); err != nil {
		return nil, err
	}
	invitePath := opts.InviteStorePath
	if invitePath == "" {
		invitePath = filepath.Join(home, defaultInviteBook)
	}
	invites, err := peer.NewInviteStore(invitePath, peer.InviteOptions{
		Cap:       opts.InviteStoreCap,
		TTL:       opts.InviteStoreTTL,
		LoadLimit: opts.InviteStoreLoad,
	})
	if err != nil {
		return nil, err
	}
	revokePath := opts.RevokeStorePath
	if revokePath == "" {
		revokePath = filepath.Join(home, defaultRevokeBook)
	}
	revokes, err := peer.NewRevokeStore(revokePath, peer.RevokeOptions{
		Cap:       opts.RevokeStoreCap,
		TTL:       opts.RevokeStoreTTL,
		LoadLimit: opts.RevokeStoreLoad,
	})
	if err != nil {
		return nil, err
	}
	candidates := peer.NewCandidatePool(opts.CandidateCap, opts.CandidateTTL)
	return &Node{
		ID:         id,
		PubKey:     pub,
		PrivKey:    priv,
		Peers:      peers,
		Members:    members,
		Invites:    invites,
		Revokes:    revokes,
		Candidates: candidates,
		Sessions:   NewSessionStore(),
		Field:      state.NewField(),
	}, nil
}

func DeriveNodeID(pub []byte) [32]byte {
	sum := crypto.SHA3_256(pub)
	var id [32]byte
	copy(id[:], sum)
	return id
}

func (n *Node) SetListenAddr(addr string) {
	if n == nil {
		return
	}
	n.listenMu.Lock()
	n.listenAddr = addr
	n.listenMu.Unlock()
}

func (n *Node) ListenAddr() string {
	if n == nil {
		return ""
	}
	n.listenMu.RLock()
	addr := n.listenAddr
	n.listenMu.RUnlock()
	return addr
}
