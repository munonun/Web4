package proto

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const (
	MsgTypeInviteCert   = "invite_cert"
	MsgTypeInviteAck    = "invite_ack"
	MaxInviteCertSize   = 8 << 10
	MaxInviteAckSize    = 2 << 10
	InvitePoWaDBits     = 18
	InviteScopeGossip   = uint32(1 << 0)
	InviteScopeContract = uint32(1 << 1)
	InviteScopeAdmin    = uint32(1 << 2)
	InviteScopeAll      = InviteScopeGossip | InviteScopeContract
)

type InviteCert struct {
	V          uint16
	InviterPub []byte
	InviteePub []byte
	InviteID   []byte
	IssuedAt   uint64
	ExpiresAt  uint64
	Scope      uint32
	PowBits    uint8
	PowNonce   uint64
	Sig        []byte
}

type InviteCertMsg struct {
	Type       string `json:"type"`
	V          uint16 `json:"v"`
	InviterPub string `json:"inviter_pub"`
	InviteePub string `json:"invitee_pub"`
	InviteID   string `json:"invite_id"`
	IssuedAt   uint64 `json:"issued_at"`
	ExpiresAt  uint64 `json:"expires_at"`
	Scope      uint32 `json:"scope"`
	PowBits    uint8  `json:"pow_bits"`
	PowNonce   uint64 `json:"pow_nonce"`
	Sig        string `json:"sig"`
}

type InviteAckMsg struct {
	Type          string `json:"type"`
	InviterNodeID string `json:"inviter_node_id"`
	InviteeNodeID string `json:"invitee_node_id"`
	InviteID      string `json:"invite_id"`
}

func EncodeInviteCertMsg(m InviteCertMsg) ([]byte, error) {
	if m.Type == "" {
		m.Type = MsgTypeInviteCert
	}
	return json.Marshal(m)
}

func DecodeInviteCertMsg(data []byte) (InviteCertMsg, error) {
	var m InviteCertMsg
	if err := json.Unmarshal(data, &m); err != nil {
		return InviteCertMsg{}, err
	}
	if m.Type != "" && m.Type != MsgTypeInviteCert {
		return InviteCertMsg{}, fmt.Errorf("unexpected msg type: %s", m.Type)
	}
	return m, nil
}

func EncodeInviteAckMsg(m InviteAckMsg) ([]byte, error) {
	if m.Type == "" {
		m.Type = MsgTypeInviteAck
	}
	return json.Marshal(m)
}

func DecodeInviteAckMsg(data []byte) (InviteAckMsg, error) {
	var m InviteAckMsg
	if err := json.Unmarshal(data, &m); err != nil {
		return InviteAckMsg{}, err
	}
	if m.Type != "" && m.Type != MsgTypeInviteAck {
		return InviteAckMsg{}, fmt.Errorf("unexpected msg type: %s", m.Type)
	}
	return m, nil
}

func InviteCertMsgFromCert(c InviteCert) InviteCertMsg {
	return InviteCertMsg{
		Type:       MsgTypeInviteCert,
		V:          c.V,
		InviterPub: hex.EncodeToString(c.InviterPub),
		InviteePub: hex.EncodeToString(c.InviteePub),
		InviteID:   hex.EncodeToString(c.InviteID),
		IssuedAt:   c.IssuedAt,
		ExpiresAt:  c.ExpiresAt,
		Scope:      c.Scope,
		PowBits:    c.PowBits,
		PowNonce:   c.PowNonce,
		Sig:        hex.EncodeToString(c.Sig),
	}
}

func InviteCertFromMsg(m InviteCertMsg) (InviteCert, error) {
	if m.Type != "" && m.Type != MsgTypeInviteCert {
		return InviteCert{}, fmt.Errorf("unexpected msg type: %s", m.Type)
	}
	inviterPub, err := hex.DecodeString(m.InviterPub)
	if err != nil || len(inviterPub) == 0 {
		return InviteCert{}, fmt.Errorf("bad inviter_pub hex")
	}
	inviteePub, err := hex.DecodeString(m.InviteePub)
	if err != nil || len(inviteePub) == 0 {
		return InviteCert{}, fmt.Errorf("bad invitee_pub hex")
	}
	inviteID, err := hex.DecodeString(m.InviteID)
	if err != nil || (len(inviteID) != 16 && len(inviteID) != 32) {
		return InviteCert{}, fmt.Errorf("bad invite_id hex")
	}
	sig, err := hex.DecodeString(m.Sig)
	if err != nil || len(sig) == 0 {
		return InviteCert{}, fmt.Errorf("bad sig hex")
	}
	return InviteCert{
		V:          m.V,
		InviterPub: inviterPub,
		InviteePub: inviteePub,
		InviteID:   inviteID,
		IssuedAt:   m.IssuedAt,
		ExpiresAt:  m.ExpiresAt,
		Scope:      m.Scope,
		PowBits:    m.PowBits,
		PowNonce:   m.PowNonce,
		Sig:        sig,
	}, nil
}

func EncodeInviteCertForSig(c InviteCert) ([]byte, error) {
	if len(c.InviterPub) == 0 {
		return nil, fmt.Errorf("missing inviter_pub")
	}
	if len(c.InviteePub) == 0 {
		return nil, fmt.Errorf("missing invitee_pub")
	}
	if len(c.InviteID) != 16 && len(c.InviteID) != 32 {
		return nil, fmt.Errorf("bad invite_id length")
	}
	if len(c.InviterPub) > 0xffff || len(c.InviteePub) > 0xffff || len(c.InviteID) > 0xffff {
		return nil, fmt.Errorf("field too large")
	}
	buf := make([]byte, 0, 2+2+len(c.InviterPub)+2+len(c.InviteePub)+2+len(c.InviteID)+8+8+4+1+8)
	tmp2 := make([]byte, 2)
	tmp4 := make([]byte, 4)
	tmp8 := make([]byte, 8)
	binary.BigEndian.PutUint16(tmp2, c.V)
	buf = append(buf, tmp2...)
	binary.BigEndian.PutUint16(tmp2, uint16(len(c.InviterPub)))
	buf = append(buf, tmp2...)
	buf = append(buf, c.InviterPub...)
	binary.BigEndian.PutUint16(tmp2, uint16(len(c.InviteePub)))
	buf = append(buf, tmp2...)
	buf = append(buf, c.InviteePub...)
	binary.BigEndian.PutUint16(tmp2, uint16(len(c.InviteID)))
	buf = append(buf, tmp2...)
	buf = append(buf, c.InviteID...)
	binary.BigEndian.PutUint64(tmp8, c.IssuedAt)
	buf = append(buf, tmp8...)
	binary.BigEndian.PutUint64(tmp8, c.ExpiresAt)
	buf = append(buf, tmp8...)
	binary.BigEndian.PutUint32(tmp4, c.Scope)
	buf = append(buf, tmp4...)
	buf = append(buf, c.PowBits)
	binary.BigEndian.PutUint64(tmp8, c.PowNonce)
	buf = append(buf, tmp8...)
	return buf, nil
}
