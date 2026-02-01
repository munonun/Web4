// internal/proto/proto.go
package proto

import (
	"crypto/sha3"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type IOU struct {
	Creditor []byte
	Debtor   []byte
	Amount   uint64
	Nonce    uint64
}

type Contract struct {
	IOU
	SigCred      []byte
	SigDebt      []byte
	EphemeralPub []byte
	Sealed       []byte
	Status       string // OPEN/CLOSED
}

type RepayReq struct {
	ContractID [32]byte
	ReqNonce   uint64
	Close      bool
}

type Ack struct {
	ContractID   [32]byte
	ReqNonce     uint64
	Decision     uint8 // 1 accept, 0 reject
	Close        bool
	EphemeralPub []byte
	Sealed       []byte
}

const (
	MsgTypeContractOpen = "contract_open"
	MsgTypeRepayReq     = "repay_req"
	MsgTypeAck          = "ack"
)

const (
	ProtoVersion = "0.0.2"
	Suite        = "rsa-pss+x25519+xchacha20poly1305+sha3"
)

const (
	MaxContractOpenSize = 32 << 10
	MaxRepayReqSize     = 8 << 10
	MaxAckSize          = 8 << 10
	MaxDeltaBSize       = 32 << 10
)

func MaxSizeForType(t string) int {
	switch t {
	case MsgTypeContractOpen:
		return MaxContractOpenSize
	case MsgTypeRepayReq:
		return MaxRepayReqSize
	case MsgTypeAck:
		return MaxAckSize
	case MsgTypeHello1:
		return MaxHello1Size
	case MsgTypeHello2:
		return MaxHello2Size
	case MsgTypePeerExchangeReq:
		return MaxPeerExchangeReqSize
	case MsgTypePeerExchangeResp:
		return MaxPeerExchangeRespSize
	case MsgTypeGossipPush:
		return MaxGossipPushSize
	case MsgTypeGossipAck:
		return MaxGossipAckSize
	case MsgTypeSecureEnvelope:
		return MaxSecureEnvelopeSize
	case MsgTypeInviteCert:
		return MaxInviteCertSize
	case MsgTypeInviteAck:
		return MaxInviteAckSize
	case MsgTypeInviteBundle:
		return MaxInviteBundleSize
	case MsgTypeRevoke:
		return MaxRevokeSize
	case MsgTypeDeltaB:
		return MaxDeltaBSize
	default:
		return MaxFrameSize
	}
}

type ContractOpenMsg struct {
	Type         string `json:"type"`
	ProtoVersion string `json:"proto_version"`
	Suite        string `json:"suite"`
	Creditor     string `json:"creditor"`
	Debtor       string `json:"debtor"`
	Amount       uint64 `json:"amount"`
	Nonce        uint64 `json:"nonce"`
	EphemeralPub string `json:"ephemeral_pub"`
	Sealed       string `json:"sealed"`
	SigB         string `json:"sigB"`
	SigA         string `json:"sigA,omitempty"`
	FromNodeID   string `json:"from_node_id,omitempty"`
	SigFrom      string `json:"sig_from,omitempty"`
}

type RepayReqMsg struct {
	Type         string `json:"type"`
	ProtoVersion string `json:"proto_version"`
	Suite        string `json:"suite"`
	ContractID   string `json:"contract_id"`
	ReqNonce     uint64 `json:"reqnonce"`
	Close        bool   `json:"close"`
	EphemeralPub string `json:"ephemeral_pub"`
	Sealed       string `json:"sealed"`
	SigB         string `json:"sigB"`
	FromNodeID   string `json:"from_node_id,omitempty"`
	SigFrom      string `json:"sig_from,omitempty"`
}

type AckMsg struct {
	Type         string `json:"type"`
	ProtoVersion string `json:"proto_version"`
	Suite        string `json:"suite"`
	ContractID   string `json:"contract_id"`
	Decision     uint8  `json:"decision"`
	Close        bool   `json:"close"`
	EphemeralPub string `json:"ephemeral_pub"`
	Sealed       string `json:"sealed"`
	SigA         string `json:"sigA"`
	FromNodeID   string `json:"from_node_id,omitempty"`
	SigFrom      string `json:"sig_from,omitempty"`
}

func IOUBytes(i IOU) []byte {
	b := make([]byte, 0, len(i.Creditor)+len(i.Debtor)+16)
	b = append(b, i.Creditor...)
	b = append(b, i.Debtor...)
	tmp := make([]byte, 8)
	binary.BigEndian.PutUint64(tmp, i.Amount)
	b = append(b, tmp...)
	binary.BigEndian.PutUint64(tmp, i.Nonce)
	b = append(b, tmp...)
	return b
}

func ContractID(i IOU) [32]byte {
	return sha3.Sum256(IOUBytes(i))
}

func RepayReqBytes(r RepayReq) []byte {
	b := make([]byte, 0, 32+8+1)
	b = append(b, r.ContractID[:]...)
	tmp := make([]byte, 8)
	binary.BigEndian.PutUint64(tmp, r.ReqNonce)
	b = append(b, tmp...)
	if r.Close {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	return b
}

func AckBytes(a Ack) []byte {
	b := make([]byte, 0, 32+8+1+1)
	b = append(b, a.ContractID[:]...)
	tmp := make([]byte, 8)
	binary.BigEndian.PutUint64(tmp, a.ReqNonce)
	b = append(b, tmp...)
	b = append(b, a.Decision)
	if a.Close {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	return b
}

func AckHeaderBytes(contractID [32]byte, decision uint8, close bool) []byte {
	b := make([]byte, 0, 32+1+1)
	b = append(b, contractID[:]...)
	b = append(b, decision)
	if close {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	return b
}

func EncodeContractOpenMsg(m ContractOpenMsg) ([]byte, error) {
	if m.Type == "" {
		m.Type = MsgTypeContractOpen
	}
	if m.ProtoVersion == "" {
		m.ProtoVersion = ProtoVersion
	}
	if m.Suite == "" {
		m.Suite = Suite
	}
	return json.Marshal(m)
}

func DecodeContractOpenMsg(data []byte) (ContractOpenMsg, error) {
	var m ContractOpenMsg
	if err := json.Unmarshal(data, &m); err != nil {
		return ContractOpenMsg{}, err
	}
	if err := ValidateWireMeta(m.ProtoVersion, m.Suite); err != nil {
		return ContractOpenMsg{}, err
	}
	return m, nil
}

func EncodeRepayReqMsg(m RepayReqMsg) ([]byte, error) {
	if m.Type == "" {
		m.Type = MsgTypeRepayReq
	}
	if m.ProtoVersion == "" {
		m.ProtoVersion = ProtoVersion
	}
	if m.Suite == "" {
		m.Suite = Suite
	}
	return json.Marshal(m)
}

func DecodeRepayReqMsg(data []byte) (RepayReqMsg, error) {
	var m RepayReqMsg
	if err := json.Unmarshal(data, &m); err != nil {
		return RepayReqMsg{}, err
	}
	if err := ValidateWireMeta(m.ProtoVersion, m.Suite); err != nil {
		return RepayReqMsg{}, err
	}
	return m, nil
}

func EncodeAckMsg(m AckMsg) ([]byte, error) {
	if m.Type == "" {
		m.Type = MsgTypeAck
	}
	if m.ProtoVersion == "" {
		m.ProtoVersion = ProtoVersion
	}
	if m.Suite == "" {
		m.Suite = Suite
	}
	return json.Marshal(m)
}

func DecodeAckMsg(data []byte) (AckMsg, error) {
	var m AckMsg
	if err := json.Unmarshal(data, &m); err != nil {
		return AckMsg{}, err
	}
	if err := ValidateWireMeta(m.ProtoVersion, m.Suite); err != nil {
		return AckMsg{}, err
	}
	return m, nil
}

func ContractOpenMsgFromContract(c Contract) ContractOpenMsg {
	m := ContractOpenMsg{
		Type:         MsgTypeContractOpen,
		ProtoVersion: ProtoVersion,
		Suite:        Suite,
		Creditor:     hex.EncodeToString(c.IOU.Creditor),
		Debtor:       hex.EncodeToString(c.IOU.Debtor),
		Amount:       c.IOU.Amount,
		Nonce:        c.IOU.Nonce,
		EphemeralPub: base64.StdEncoding.EncodeToString(c.EphemeralPub),
		Sealed:       base64.StdEncoding.EncodeToString(c.Sealed),
		SigB:         hex.EncodeToString(c.SigDebt),
	}
	if len(c.SigCred) != 0 {
		m.SigA = hex.EncodeToString(c.SigCred)
	}
	return m
}

func ContractFromOpenMsg(m ContractOpenMsg) (Contract, error) {
	if m.Type != "" && m.Type != MsgTypeContractOpen {
		return Contract{}, fmt.Errorf("unexpected msg type: %s", m.Type)
	}
	cred, err := hex.DecodeString(m.Creditor)
	if err != nil {
		return Contract{}, fmt.Errorf("bad creditor hex")
	}
	debt, err := hex.DecodeString(m.Debtor)
	if err != nil {
		return Contract{}, fmt.Errorf("bad debtor hex")
	}
	sigB, err := hex.DecodeString(m.SigB)
	if err != nil {
		return Contract{}, fmt.Errorf("bad sigB hex")
	}
	eph, err := base64.StdEncoding.DecodeString(m.EphemeralPub)
	if err != nil {
		return Contract{}, fmt.Errorf("bad ephemeral pub")
	}
	sealed, err := base64.StdEncoding.DecodeString(m.Sealed)
	if err != nil {
		return Contract{}, fmt.Errorf("bad sealed")
	}
	var sigA []byte
	if m.SigA != "" {
		sigA, err = hex.DecodeString(m.SigA)
		if err != nil {
			return Contract{}, fmt.Errorf("bad sigA hex")
		}
	}
	return Contract{
		IOU: IOU{
			Creditor: cred,
			Debtor:   debt,
			Amount:   m.Amount,
			Nonce:    m.Nonce,
		},
		SigCred:      sigA,
		SigDebt:      sigB,
		EphemeralPub: eph,
		Sealed:       sealed,
		Status:       "OPEN",
	}, nil
}

func RepayReqMsgFromReq(r RepayReq, sigB, ephPub, sealed []byte) RepayReqMsg {
	return RepayReqMsg{
		Type:         MsgTypeRepayReq,
		ProtoVersion: ProtoVersion,
		Suite:        Suite,
		ContractID:   hex.EncodeToString(r.ContractID[:]),
		ReqNonce:     r.ReqNonce,
		Close:        r.Close,
		EphemeralPub: base64.StdEncoding.EncodeToString(ephPub),
		Sealed:       base64.StdEncoding.EncodeToString(sealed),
		SigB:         hex.EncodeToString(sigB),
	}
}

func RepayReqFromMsg(m RepayReqMsg) (RepayReq, []byte, error) {
	if m.Type != "" && m.Type != MsgTypeRepayReq {
		return RepayReq{}, nil, fmt.Errorf("unexpected msg type: %s", m.Type)
	}
	idBytes, err := hex.DecodeString(m.ContractID)
	if err != nil || len(idBytes) != 32 {
		return RepayReq{}, nil, fmt.Errorf("bad contract_id hex")
	}
	var cid [32]byte
	copy(cid[:], idBytes)
	sigB, err := hex.DecodeString(m.SigB)
	if err != nil {
		return RepayReq{}, nil, fmt.Errorf("bad sigB hex")
	}
	return RepayReq{ContractID: cid, ReqNonce: m.ReqNonce, Close: m.Close}, sigB, nil
}

func AckMsgFromAck(a Ack, sigA []byte) AckMsg {
	return AckMsg{
		Type:         MsgTypeAck,
		ProtoVersion: ProtoVersion,
		Suite:        Suite,
		ContractID:   hex.EncodeToString(a.ContractID[:]),
		Decision:     a.Decision,
		Close:        a.Close,
		EphemeralPub: base64.StdEncoding.EncodeToString(a.EphemeralPub),
		Sealed:       base64.StdEncoding.EncodeToString(a.Sealed),
		SigA:         hex.EncodeToString(sigA),
	}
}

func AckFromMsg(m AckMsg) (Ack, []byte, error) {
	if m.Type != "" && m.Type != MsgTypeAck {
		return Ack{}, nil, fmt.Errorf("unexpected msg type: %s", m.Type)
	}
	idBytes, err := hex.DecodeString(m.ContractID)
	if err != nil || len(idBytes) != 32 {
		return Ack{}, nil, fmt.Errorf("bad contract_id hex")
	}
	var cid [32]byte
	copy(cid[:], idBytes)
	sigA, err := hex.DecodeString(m.SigA)
	if err != nil {
		return Ack{}, nil, fmt.Errorf("bad sigA hex")
	}
	eph, err := base64.StdEncoding.DecodeString(m.EphemeralPub)
	if err != nil {
		return Ack{}, nil, fmt.Errorf("bad ephemeral pub")
	}
	sealed, err := base64.StdEncoding.DecodeString(m.Sealed)
	if err != nil {
		return Ack{}, nil, fmt.Errorf("bad sealed")
	}
	return Ack{ContractID: cid, Decision: m.Decision, Close: m.Close, EphemeralPub: eph, Sealed: sealed}, sigA, nil
}

type OpenPayload struct {
	Type     string         `json:"type"`
	Creditor string         `json:"creditor"`
	Debtor   string         `json:"debtor"`
	Amount   uint64         `json:"amount"`
	Nonce    uint64         `json:"nonce"`
	ZK       *ZKLinearProof `json:"zk,omitempty"`
}

type RepayPayload struct {
	Type       string `json:"type"`
	ContractID string `json:"contract_id"`
	ReqNonce   uint64 `json:"reqnonce"`
	Close      bool   `json:"close"`
}

type AckPayload struct {
	Type       string         `json:"type"`
	ContractID string         `json:"contract_id"`
	Decision   uint8          `json:"decision"`
	Close      bool           `json:"close"`
	ZK         *ZKLinearProof `json:"zk,omitempty"`
}

func EncodeOpenPayload(credHex, debtHex string, amount, nonce uint64) ([]byte, error) {
	p := OpenPayload{
		Type:     MsgTypeContractOpen,
		Creditor: credHex,
		Debtor:   debtHex,
		Amount:   amount,
		Nonce:    nonce,
	}
	return json.Marshal(p)
}

func EncodeOpenPayloadWithZK(credHex, debtHex string, amount, nonce uint64, zk *ZKLinearProof) ([]byte, error) {
	p := OpenPayload{
		Type:     MsgTypeContractOpen,
		Creditor: credHex,
		Debtor:   debtHex,
		Amount:   amount,
		Nonce:    nonce,
		ZK:       zk,
	}
	return json.Marshal(p)
}

func EncodeRepayPayload(contractID string, reqNonce uint64, close bool) ([]byte, error) {
	p := RepayPayload{
		Type:       MsgTypeRepayReq,
		ContractID: contractID,
		ReqNonce:   reqNonce,
		Close:      close,
	}
	return json.Marshal(p)
}

func EncodeAckPayload(contractID string, decision uint8, close bool) ([]byte, error) {
	p := AckPayload{
		Type:       MsgTypeAck,
		ContractID: contractID,
		Decision:   decision,
		Close:      close,
	}
	return json.Marshal(p)
}

func EncodeAckPayloadWithZK(contractID string, decision uint8, close bool, zk *ZKLinearProof) ([]byte, error) {
	p := AckPayload{
		Type:       MsgTypeAck,
		ContractID: contractID,
		Decision:   decision,
		Close:      close,
		ZK:         zk,
	}
	return json.Marshal(p)
}

func OpenSignBytes(iou IOU, ephPub, sealed []byte) []byte {
	b := make([]byte, 0, len(iou.Creditor)+len(iou.Debtor)+16+len(ephPub)+len(sealed))
	b = append(b, IOUBytes(iou)...)
	b = append(b, ephPub...)
	b = append(b, sealed...)
	return b
}

func RepayReqSignBytes(r RepayReq, ephPub, sealed []byte) []byte {
	b := make([]byte, 0, 32+8+1+len(ephPub)+len(sealed))
	b = append(b, RepayReqBytes(r)...)
	b = append(b, ephPub...)
	b = append(b, sealed...)
	return b
}

func AckSignBytes(contractID [32]byte, decision uint8, close bool, ephPub, sealed []byte) []byte {
	b := make([]byte, 0, 32+1+1+len(ephPub)+len(sealed))
	b = append(b, AckHeaderBytes(contractID, decision, close)...)
	b = append(b, ephPub...)
	b = append(b, sealed...)
	return b
}

func DecodeSealedFields(ephB64, sealedB64 string) ([]byte, []byte, error) {
	eph, err := base64.StdEncoding.DecodeString(ephB64)
	if err != nil {
		return nil, nil, fmt.Errorf("bad ephemeral pub")
	}
	sealed, err := base64.StdEncoding.DecodeString(sealedB64)
	if err != nil {
		return nil, nil, fmt.Errorf("bad sealed")
	}
	return eph, sealed, nil
}

func ValidateWireMeta(version, suite string) error {
	if version != "" && version != ProtoVersion {
		return fmt.Errorf("proto version mismatch")
	}
	if suite != "" && suite != Suite {
		return fmt.Errorf("suite mismatch")
	}
	return nil
}
