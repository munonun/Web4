// internal/proto/proto.go
package proto

import (
	"crypto/sha3"
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
	SigCred []byte
	SigDebt []byte
	Status  string // OPEN/CLOSED
}

type RepayReq struct {
	ContractID [32]byte
	ReqNonce   uint64
	Close      bool
}

type Ack struct {
	ContractID [32]byte
	ReqNonce   uint64
	Decision   uint8 // 1 accept, 0 reject
	Close      bool
}

const (
	MsgTypeContractOpen = "contract_open"
	MsgTypeRepayReq     = "repay_req"
	MsgTypeAck          = "ack"
)

type ContractOpenMsg struct {
	Type     string `json:"type"`
	Creditor string `json:"creditor"`
	Debtor   string `json:"debtor"`
	Amount   uint64 `json:"amount"`
	Nonce    uint64 `json:"nonce"`
	SigB     string `json:"sigB"`
	SigA     string `json:"sigA,omitempty"`
}

type RepayReqMsg struct {
	Type       string `json:"type"`
	ContractID string `json:"contract_id"`
	ReqNonce   uint64 `json:"reqnonce"`
	Close      bool   `json:"close"`
	SigB       string `json:"sigB"`
}

type AckMsg struct {
	Type       string `json:"type"`
	ContractID string `json:"contract_id"`
	Decision   uint8  `json:"decision"`
	Close      bool   `json:"close"`
	SigA       string `json:"sigA"`
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

func EncodeContractOpenMsg(m ContractOpenMsg) ([]byte, error) {
	if m.Type == "" {
		m.Type = MsgTypeContractOpen
	}
	return json.Marshal(m)
}

func DecodeContractOpenMsg(data []byte) (ContractOpenMsg, error) {
	var m ContractOpenMsg
	if err := json.Unmarshal(data, &m); err != nil {
		return ContractOpenMsg{}, err
	}
	return m, nil
}

func EncodeRepayReqMsg(m RepayReqMsg) ([]byte, error) {
	if m.Type == "" {
		m.Type = MsgTypeRepayReq
	}
	return json.Marshal(m)
}

func DecodeRepayReqMsg(data []byte) (RepayReqMsg, error) {
	var m RepayReqMsg
	if err := json.Unmarshal(data, &m); err != nil {
		return RepayReqMsg{}, err
	}
	return m, nil
}

func EncodeAckMsg(m AckMsg) ([]byte, error) {
	if m.Type == "" {
		m.Type = MsgTypeAck
	}
	return json.Marshal(m)
}

func DecodeAckMsg(data []byte) (AckMsg, error) {
	var m AckMsg
	if err := json.Unmarshal(data, &m); err != nil {
		return AckMsg{}, err
	}
	return m, nil
}

func ContractOpenMsgFromContract(c Contract) ContractOpenMsg {
	m := ContractOpenMsg{
		Type:     MsgTypeContractOpen,
		Creditor: hex.EncodeToString(c.IOU.Creditor),
		Debtor:   hex.EncodeToString(c.IOU.Debtor),
		Amount:   c.IOU.Amount,
		Nonce:    c.IOU.Nonce,
		SigB:     hex.EncodeToString(c.SigDebt),
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
		SigCred: sigA,
		SigDebt: sigB,
		Status:  "OPEN",
	}, nil
}

func RepayReqMsgFromReq(r RepayReq, sigB []byte) RepayReqMsg {
	return RepayReqMsg{
		Type:       MsgTypeRepayReq,
		ContractID: hex.EncodeToString(r.ContractID[:]),
		ReqNonce:   r.ReqNonce,
		Close:      r.Close,
		SigB:       hex.EncodeToString(sigB),
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
		Type:       MsgTypeAck,
		ContractID: hex.EncodeToString(a.ContractID[:]),
		Decision:   a.Decision,
		Close:      a.Close,
		SigA:       hex.EncodeToString(sigA),
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
	return Ack{ContractID: cid, Decision: m.Decision, Close: m.Close}, sigA, nil
}
