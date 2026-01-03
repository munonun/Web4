// internal/proto/proto.go
package proto

import (
	"crypto/sha3"
	"encoding/binary"
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
