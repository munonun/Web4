package proto

import (
	"encoding/json"
	"fmt"
)

const (
	MsgTypeGossipPush = "gossip_push"
	MsgTypeGossipAck  = "gossip_ack"
	MaxGossipPushSize = 64 << 10
	MaxGossipAckSize  = 1 << 10
)

type GossipPushMsg struct {
	Type         string `json:"type"`
	ProtoVersion string `json:"proto_version"`
	Suite        string `json:"suite"`
	EphemeralPub string `json:"ephemeral_pub"`
	Sealed       string `json:"sealed"`
	Hops         int    `json:"hops,omitempty"`
	From         string `json:"from,omitempty"`
	FromNodeID   string `json:"from_node_id,omitempty"`
	SigFrom      string `json:"sig_from,omitempty"`
}

type GossipAckMsg struct {
	Type       string `json:"type"`
	Sha256     string `json:"sha256"`
	FromNodeID string `json:"from_node_id,omitempty"`
}

func EncodeGossipPushMsg(m GossipPushMsg) ([]byte, error) {
	if m.Type == "" {
		m.Type = MsgTypeGossipPush
	}
	if m.ProtoVersion == "" {
		m.ProtoVersion = ProtoVersion
	}
	if m.Suite == "" {
		m.Suite = Suite
	}
	return json.Marshal(m)
}

func DecodeGossipPushMsg(data []byte) (GossipPushMsg, error) {
	var m GossipPushMsg
	if err := json.Unmarshal(data, &m); err != nil {
		return GossipPushMsg{}, err
	}
	if m.Type != "" && m.Type != MsgTypeGossipPush {
		return GossipPushMsg{}, fmt.Errorf("unexpected msg type: %s", m.Type)
	}
	if err := ValidateWireMeta(m.ProtoVersion, m.Suite); err != nil {
		return GossipPushMsg{}, err
	}
	return m, nil
}

func EncodeGossipAckMsg(m GossipAckMsg) ([]byte, error) {
	if m.Type == "" {
		m.Type = MsgTypeGossipAck
	}
	return json.Marshal(m)
}

func DecodeGossipAckMsg(data []byte) (GossipAckMsg, error) {
	var m GossipAckMsg
	if err := json.Unmarshal(data, &m); err != nil {
		return GossipAckMsg{}, err
	}
	if m.Type != "" && m.Type != MsgTypeGossipAck {
		return GossipAckMsg{}, fmt.Errorf("unexpected msg type: %s", m.Type)
	}
	return m, nil
}
