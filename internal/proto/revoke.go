package proto

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const (
	MsgTypeRevoke   = "revoke_member"
	MaxRevokeSize   = 4 << 10
	maxRevokeReason = 256
)

type RevokeMsg struct {
	Type          string `json:"type"`
	RevokerNodeID string `json:"revoker_node_id"`
	TargetNodeID  string `json:"target_node_id"`
	Reason        string `json:"reason,omitempty"`
	IssuedAt      uint64 `json:"issued_at"`
	RevokeID      string `json:"revoke_id"`
	Sig           string `json:"sig"`
}

func EncodeRevokeMsg(m RevokeMsg) ([]byte, error) {
	if m.Type == "" {
		m.Type = MsgTypeRevoke
	}
	return json.Marshal(m)
}

func DecodeRevokeMsg(data []byte) (RevokeMsg, error) {
	var m RevokeMsg
	if err := json.Unmarshal(data, &m); err != nil {
		return RevokeMsg{}, err
	}
	if m.Type != "" && m.Type != MsgTypeRevoke {
		return RevokeMsg{}, fmt.Errorf("unexpected msg type: %s", m.Type)
	}
	return m, nil
}

func RevokeSignBytes(revokerID, targetID [32]byte, revokeID []byte, issuedAt uint64, reason string) ([]byte, error) {
	if len(revokeID) == 0 || (len(revokeID) != 16 && len(revokeID) != 32) {
		return nil, fmt.Errorf("bad revoke_id length")
	}
	if len(reason) > maxRevokeReason {
		return nil, fmt.Errorf("reason too long")
	}
	if len(revokeID) > 0xffff || len(reason) > 0xffff {
		return nil, fmt.Errorf("field too large")
	}
	prefix := []byte("web4:v0:revoke|")
	buf := make([]byte, 0, len(prefix)+32+32+2+len(revokeID)+8+2+len(reason))
	buf = append(buf, prefix...)
	buf = append(buf, revokerID[:]...)
	buf = append(buf, targetID[:]...)
	tmp2 := make([]byte, 2)
	tmp8 := make([]byte, 8)
	binary.BigEndian.PutUint16(tmp2, uint16(len(revokeID)))
	buf = append(buf, tmp2...)
	buf = append(buf, revokeID...)
	binary.BigEndian.PutUint64(tmp8, issuedAt)
	buf = append(buf, tmp8...)
	binary.BigEndian.PutUint16(tmp2, uint16(len(reason)))
	buf = append(buf, tmp2...)
	buf = append(buf, reason...)
	return buf, nil
}

func DecodeRevokeIDHex(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("missing revoke_id")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("bad revoke_id hex")
	}
	if len(b) != 16 && len(b) != 32 {
		return nil, fmt.Errorf("bad revoke_id length")
	}
	return b, nil
}
