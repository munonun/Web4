package proto

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const (
	MsgTypeSecureEnvelope = "secure"
	MaxSecureEnvelopeSize = 64 << 10
)

type SecureEnvelope struct {
	Type       string `json:"type"`
	MsgType    string `json:"msg_type"`
	FromNodeID string `json:"from_node_id"`
	ToNodeID   string `json:"to_node_id"`
	ChannelID  string `json:"channel_id,omitempty"`
	Seq        uint64 `json:"seq"`
	Sealed     string `json:"sealed"`
}

func EncodeSecureEnvelope(m SecureEnvelope) ([]byte, error) {
	if m.Type == "" {
		m.Type = MsgTypeSecureEnvelope
	}
	return json.Marshal(m)
}

func DecodeSecureEnvelope(data []byte) (SecureEnvelope, error) {
	var m SecureEnvelope
	if err := json.Unmarshal(data, &m); err != nil {
		return SecureEnvelope{}, err
	}
	if m.Type != "" && m.Type != MsgTypeSecureEnvelope {
		return SecureEnvelope{}, fmt.Errorf("unexpected msg type: %s", m.Type)
	}
	return m, nil
}

func EncodeSealedPayload(payload []byte) string {
	return base64.StdEncoding.EncodeToString(payload)
}

func DecodeSealedPayload(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func DecodeNodeIDHex(s string) ([32]byte, error) {
	var id [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return id, fmt.Errorf("bad node id")
	}
	copy(id[:], b)
	return id, nil
}
