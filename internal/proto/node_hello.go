package proto

import (
	"crypto/sha3"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

const (
	MsgTypeNodeHello = "node_hello"
	MaxNodeHelloSize = 4 << 10
)

type NodeHelloMsg struct {
	Type   string `json:"type"`
	NodeID string `json:"node_id"`
	PubKey string `json:"pubkey"`
	Nonce  uint64 `json:"nonce"`
	Sig    string `json:"sig"`
}

func EncodeNodeHelloMsg(m NodeHelloMsg) ([]byte, error) {
	if m.Type == "" {
		m.Type = MsgTypeNodeHello
	}
	return json.Marshal(m)
}

func DecodeNodeHelloMsg(data []byte) (NodeHelloMsg, error) {
	var m NodeHelloMsg
	if err := json.Unmarshal(data, &m); err != nil {
		return NodeHelloMsg{}, err
	}
	if m.Type != "" && m.Type != MsgTypeNodeHello {
		return NodeHelloMsg{}, fmt.Errorf("unexpected msg type: %s", m.Type)
	}
	return m, nil
}

func NodeHelloHash(nodeID [32]byte, pub []byte, nonce uint64) [32]byte {
	buf := make([]byte, 0, 32+len(pub)+8)
	buf = append(buf, nodeID[:]...)
	buf = append(buf, pub...)
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], nonce)
	buf = append(buf, tmp[:]...)
	return sha3.Sum256(buf)
}
