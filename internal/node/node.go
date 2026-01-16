package node

import (
	"os"
	"path/filepath"
	"time"

	"web4mvp/internal/crypto"
	"web4mvp/internal/peer"
)

type Node struct {
	ID         [32]byte
	PubKey     []byte
	PrivKey    []byte
	Peers      *peer.Store
	Members    *peer.MemberStore
	Candidates *peer.CandidatePool
	Sessions   *SessionStore
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
	CandidateCap    int
	CandidateTTL    time.Duration
}

const defaultPeerBook = "peers.jsonl"
const defaultMemberBook = "members.jsonl"

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
	candidates := peer.NewCandidatePool(opts.CandidateCap, opts.CandidateTTL)
	return &Node{
		ID:         id,
		PubKey:     pub,
		PrivKey:    priv,
		Peers:      peers,
		Members:    members,
		Candidates: candidates,
		Sessions:   NewSessionStore(),
	}, nil
}

func DeriveNodeID(pub []byte) [32]byte {
	buf := make([]byte, 0, len("web4:nodeid:v1")+len(pub))
	buf = append(buf, []byte("web4:nodeid:v1")...)
	buf = append(buf, pub...)
	sum := crypto.SHA3_256(buf)
	var id [32]byte
	copy(id[:], sum)
	return id
}
