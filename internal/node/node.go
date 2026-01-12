package node

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"web4mvp/internal/crypto"
	"web4mvp/internal/peer"
	"web4mvp/internal/proto"
)

type Node struct {
	ID         [32]byte
	PubKey     []byte
	PrivKey    []byte
	Peers      *peer.Store
	Members    *peer.MemberStore
	Candidates *peer.CandidatePool
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
		Cap:       opts.PeerStoreCap,
		TTL:       opts.PeerStoreTTL,
		LoadLimit: opts.PeerStoreLoad,
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
	}, nil
}

func DeriveNodeID(pub []byte) [32]byte {
	sum := crypto.SHA3_256(pub)
	var id [32]byte
	copy(id[:], sum)
	return id
}

func (n *Node) Hello(nonce uint64, advertiseAddr string) (proto.NodeHelloMsg, error) {
	if n == nil {
		return proto.NodeHelloMsg{}, fmt.Errorf("nil node")
	}
	hash := proto.NodeHelloHash(n.ID, n.PubKey, advertiseAddr, nonce)
	sig := crypto.Sign(n.PrivKey, hash[:])
	return proto.NodeHelloMsg{
		Type:   proto.MsgTypeNodeHello,
		NodeID: hex.EncodeToString(n.ID[:]),
		PubKey: hex.EncodeToString(n.PubKey),
		Addr:   advertiseAddr,
		Nonce:  nonce,
		Sig:    hex.EncodeToString(sig),
	}, nil
}

func VerifyHello(m proto.NodeHelloMsg) (peer.Peer, error) {
	if m.Type != "" && m.Type != proto.MsgTypeNodeHello {
		return peer.Peer{}, fmt.Errorf("unexpected msg type: %s", m.Type)
	}
	idBytes, err := hex.DecodeString(m.NodeID)
	if err != nil || len(idBytes) != 32 {
		return peer.Peer{}, fmt.Errorf("bad node_id")
	}
	pub, err := hex.DecodeString(m.PubKey)
	if err != nil || len(pub) != crypto.PubLen {
		return peer.Peer{}, fmt.Errorf("bad pubkey")
	}
	sig, err := hex.DecodeString(m.Sig)
	if err != nil {
		return peer.Peer{}, fmt.Errorf("bad sig")
	}
	var id [32]byte
	copy(id[:], idBytes)
	if derived := DeriveNodeID(pub); derived != id {
		return peer.Peer{}, fmt.Errorf("node_id mismatch")
	}
	hash := proto.NodeHelloHash(id, pub, m.Addr, m.Nonce)
	if !crypto.Verify(pub, hash[:], sig) {
		return peer.Peer{}, fmt.Errorf("invalid signature")
	}
	return peer.Peer{NodeID: id, PubKey: pub, Addr: m.Addr}, nil
}

func (n *Node) AcceptHello(m proto.NodeHelloMsg) (peer.Peer, error) {
	if n == nil || n.Peers == nil {
		return peer.Peer{}, fmt.Errorf("peer store unavailable")
	}
	p, err := VerifyHello(m)
	if err != nil {
		return peer.Peer{}, err
	}
	if err := n.Peers.Upsert(p, true); err != nil {
		return peer.Peer{}, err
	}
	return p, nil
}
