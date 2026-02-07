package proto

import (
	"encoding/json"
	"fmt"
)

const (
	MsgTypePeerExchangeReq  = "peer_exchange_req"
	MsgTypePeerExchangeResp = "peer_exchange_resp"

	MaxPeerExchangeReqSize  = 2 << 10
	MaxPeerExchangeRespSize = 16 << 10
)

type PeerExchangeReqMsg struct {
	Type         string `json:"type"`
	ProtoVersion string `json:"proto_version"`
	Suite        string `json:"suite"`
	K            int    `json:"k"`
	FromNodeID   string `json:"from_node_id,omitempty"`
	PubKey       string `json:"pubkey,omitempty"`
	SigFrom      string `json:"sig_from,omitempty"`
}

type PeerExchangePeer struct {
	NodeID string `json:"node_id,omitempty"`
	PubKey string `json:"pubkey,omitempty"`
	Addr   string `json:"addr,omitempty"`
}

type PeerExchangeRespMsg struct {
	Type         string             `json:"type"`
	ProtoVersion string             `json:"proto_version"`
	Suite        string             `json:"suite"`
	Peers        []PeerExchangePeer `json:"peers"`
	FromNodeID   string             `json:"from_node_id,omitempty"`
	SigFrom      string             `json:"sig_from,omitempty"`
}

func EncodePeerExchangeReq(m PeerExchangeReqMsg) ([]byte, error) {
	if m.Type == "" {
		m.Type = MsgTypePeerExchangeReq
	}
	if m.ProtoVersion == "" {
		m.ProtoVersion = ProtoVersion
	}
	if m.Suite == "" {
		m.Suite = Suite
	}
	return json.Marshal(m)
}

func DecodePeerExchangeReq(data []byte) (PeerExchangeReqMsg, error) {
	var m PeerExchangeReqMsg
	if err := json.Unmarshal(data, &m); err != nil {
		return PeerExchangeReqMsg{}, err
	}
	if m.Type != "" && m.Type != MsgTypePeerExchangeReq {
		return PeerExchangeReqMsg{}, fmt.Errorf("unexpected msg type: %s", m.Type)
	}
	if err := ValidateWireMeta(m.ProtoVersion, m.Suite); err != nil {
		return PeerExchangeReqMsg{}, err
	}
	return m, nil
}

func EncodePeerExchangeResp(m PeerExchangeRespMsg) ([]byte, error) {
	if m.Type == "" {
		m.Type = MsgTypePeerExchangeResp
	}
	if m.ProtoVersion == "" {
		m.ProtoVersion = ProtoVersion
	}
	if m.Suite == "" {
		m.Suite = Suite
	}
	return json.Marshal(m)
}

func DecodePeerExchangeResp(data []byte) (PeerExchangeRespMsg, error) {
	var m PeerExchangeRespMsg
	if err := json.Unmarshal(data, &m); err != nil {
		return PeerExchangeRespMsg{}, err
	}
	if m.Type != "" && m.Type != MsgTypePeerExchangeResp {
		return PeerExchangeRespMsg{}, fmt.Errorf("unexpected msg type: %s", m.Type)
	}
	if err := ValidateWireMeta(m.ProtoVersion, m.Suite); err != nil {
		return PeerExchangeRespMsg{}, err
	}
	return m, nil
}
