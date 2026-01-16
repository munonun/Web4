package crypto

import (
	"encoding/binary"
)

func BuildAAD(msgType string, seq uint64, fromID, toID [32]byte, channelID string) []byte {
	msgBytes := []byte(msgType)
	chBytes := []byte(channelID)
	buf := make([]byte, 0, 2+len(msgBytes)+8+32+32+2+len(chBytes))
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], uint16(len(msgBytes)))
	buf = append(buf, tmp[:]...)
	buf = append(buf, msgBytes...)
	var seqBytes [8]byte
	binary.BigEndian.PutUint64(seqBytes[:], seq)
	buf = append(buf, seqBytes[:]...)
	buf = append(buf, fromID[:]...)
	buf = append(buf, toID[:]...)
	binary.BigEndian.PutUint16(tmp[:], uint16(len(chBytes)))
	buf = append(buf, tmp[:]...)
	buf = append(buf, chBytes...)
	return buf
}
