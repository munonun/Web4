package crypto

import (
	"encoding/binary"
	"errors"
)

const (
	labelKDFMaster = "web4:kdf:v1"
	labelSendKey   = "web4:send:v1"
	labelRecvKey   = "web4:recv:v1"
	labelNonceSend = "web4:ns:send:v1"
	labelNonceRecv = "web4:ns:recv:v1"
)

type SessionKeys struct {
	Master        []byte
	SendKey       []byte
	RecvKey       []byte
	NonceBaseSend []byte
	NonceBaseRecv []byte
}

func DeriveSessionKeys(ss, transcript []byte) (SessionKeys, error) {
	if len(ss) == 0 || len(transcript) == 0 {
		return SessionKeys{}, errors.New("empty key material")
	}
	master := KDF(labelKDFMaster, ss, transcript)
	send := KDF(labelSendKey, master)
	recv := KDF(labelRecvKey, master)
	nsSend := KDF(labelNonceSend, master)[:XNonceSize]
	nsRecv := KDF(labelNonceRecv, master)[:XNonceSize]
	return SessionKeys{
		Master:        master,
		SendKey:       send,
		RecvKey:       recv,
		NonceBaseSend: nsSend,
		NonceBaseRecv: nsRecv,
	}, nil
}

func NonceFromBase(base []byte, counter uint64) ([]byte, error) {
	if len(base) != XNonceSize {
		return nil, errors.New("bad nonce base size")
	}
	nonce := make([]byte, XNonceSize)
	copy(nonce, base)
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], counter)
	for i := 0; i < 8; i++ {
		nonce[XNonceSize-8+i] ^= tmp[i]
	}
	return nonce, nil
}
