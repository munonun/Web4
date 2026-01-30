package proto

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const (
	MsgTypeInviteBundle = "invite_bundle"
	MaxInviteBundleSize = 16 << 10
)

type InviteApproval struct {
	ApproverNodeID string `json:"approver_node_id"`
	Sig            string `json:"sig"`
}

type InviteBundleMsg struct {
	Type          string           `json:"type"`
	InviteePub    string           `json:"invitee_pub"`
	InviteeNodeID string           `json:"invitee_node_id"`
	InviteID      string           `json:"invite_id"`
	ExpiresAt     uint64           `json:"expires_at"`
	Scope         uint32           `json:"scope"`
	Approvals     []InviteApproval `json:"approvals"`
}

func EncodeInviteBundleMsg(m InviteBundleMsg) ([]byte, error) {
	if m.Type == "" {
		m.Type = MsgTypeInviteBundle
	}
	return json.Marshal(m)
}

func DecodeInviteBundleMsg(data []byte) (InviteBundleMsg, error) {
	var m InviteBundleMsg
	if err := json.Unmarshal(data, &m); err != nil {
		return InviteBundleMsg{}, err
	}
	if m.Type != "" && m.Type != MsgTypeInviteBundle {
		return InviteBundleMsg{}, fmt.Errorf("unexpected msg type: %s", m.Type)
	}
	return m, nil
}

func InviteApproveSignBytes(inviteID []byte, inviteeID [32]byte, expiresAt uint64, scope uint32) ([]byte, error) {
	if len(inviteID) == 0 || (len(inviteID) != 16 && len(inviteID) != 32) {
		return nil, fmt.Errorf("bad invite_id length")
	}
	prefix := []byte("web4:v0:invite_approve|")
	buf := make([]byte, 0, len(prefix)+len(inviteID)+32+8+4)
	buf = append(buf, prefix...)
	buf = append(buf, inviteID...)
	buf = append(buf, inviteeID[:]...)
	tmp8 := make([]byte, 8)
	tmp4 := make([]byte, 4)
	binary.BigEndian.PutUint64(tmp8, expiresAt)
	buf = append(buf, tmp8...)
	binary.BigEndian.PutUint32(tmp4, scope)
	buf = append(buf, tmp4...)
	return buf, nil
}

func DecodeInviteIDHex(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("missing invite_id")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("bad invite_id hex")
	}
	if len(b) != 16 && len(b) != 32 {
		return nil, fmt.Errorf("bad invite_id length")
	}
	return b, nil
}
