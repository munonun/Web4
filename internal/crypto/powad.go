package crypto

import "encoding/binary"

const powadPrefix = "web4:v0:powad|"

func PoWaDCheck(inviteID []byte, inviteeNodeID []byte, powNonce uint64, powBits uint8) bool {
	if powBits == 0 {
		return true
	}
	if len(inviteID) == 0 || len(inviteeNodeID) != 32 {
		return false
	}
	buf := make([]byte, 0, len(powadPrefix)+len(inviteID)+len(inviteeNodeID)+8)
	buf = append(buf, []byte(powadPrefix)...)
	buf = append(buf, inviteID...)
	buf = append(buf, inviteeNodeID...)
	var nonce [8]byte
	binary.LittleEndian.PutUint64(nonce[:], powNonce)
	buf = append(buf, nonce[:]...)
	digest := SHA3_256(buf)
	full := int(powBits / 8)
	rem := int(powBits % 8)
	for i := 0; i < full; i++ {
		if digest[i] != 0 {
			return false
		}
	}
	if rem == 0 {
		return true
	}
	mask := byte(0xff << (8 - rem))
	return digest[full]&mask == 0
}

func PoWaDSolve(inviteID []byte, inviteeNodeID []byte, powBits uint8) (uint64, bool) {
	for nonce := uint64(0); nonce < ^uint64(0); nonce++ {
		if PoWaDCheck(inviteID, inviteeNodeID, nonce, powBits) {
			return nonce, true
		}
	}
	return 0, false
}
