package proto

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const (
	MsgTypeHello1 = "hello1"
	MsgTypeHello2 = "hello2"

	// Suite 0 carries additional PQ material (ML-KEM + SLH-DSA), so
	// handshake envelopes are larger than legacy RSA/X25519 messages.
	MaxHello1Size = 32 << 10
	MaxHello2Size = 32 << 10
)

type Hello1Msg struct {
	Type            string `json:"type"`
	FromNodeID      string `json:"from_node_id"`
	FromPub         string `json:"from_pub"`
	ListenAddr      string `json:"listen_addr,omitempty"`
	FromAddr        string `json:"from_addr,omitempty"`
	ToNodeID        string `json:"to_node_id"`
	SuiteID         int    `json:"suite_id"`
	SupportedSuites string `json:"supported_suites,omitempty"`
	EA              string `json:"ea"`
	Na              string `json:"na"`
	MLKEMPub        string `json:"mlkem_pub,omitempty"`
	PQPub           string `json:"pq_pub,omitempty"`
	PQBindSig       string `json:"pq_bind_sig,omitempty"`
	SessionID       string `json:"session_id,omitempty"`
	Sig             string `json:"sig"`
}

type Hello2Msg struct {
	Type            string `json:"type"`
	FromNodeID      string `json:"from_node_id"`
	FromPub         string `json:"from_pub"`
	ListenAddr      string `json:"listen_addr,omitempty"`
	FromAddr        string `json:"from_addr,omitempty"`
	ToNodeID        string `json:"to_node_id"`
	SuiteID         int    `json:"suite_id"`
	SupportedSuites string `json:"supported_suites,omitempty"`
	EB              string `json:"eb"`
	Nb              string `json:"nb"`
	MLKEMCT         string `json:"mlkem_ct,omitempty"`
	PQPub           string `json:"pq_pub,omitempty"`
	PQBindSig       string `json:"pq_bind_sig,omitempty"`
	SessionID       string `json:"session_id,omitempty"`
	Sig             string `json:"sig"`
}

func EncodeHello1Msg(m Hello1Msg) ([]byte, error) {
	if m.Type == "" {
		m.Type = MsgTypeHello1
	}
	return json.Marshal(m)
}

func DecodeHello1Msg(data []byte) (Hello1Msg, error) {
	var m Hello1Msg
	if err := json.Unmarshal(data, &m); err != nil {
		return Hello1Msg{}, err
	}
	if m.Type != "" && m.Type != MsgTypeHello1 {
		return Hello1Msg{}, fmt.Errorf("unexpected msg type: %s", m.Type)
	}
	return m, nil
}

func EncodeHello2Msg(m Hello2Msg) ([]byte, error) {
	if m.Type == "" {
		m.Type = MsgTypeHello2
	}
	return json.Marshal(m)
}

func DecodeHello2Msg(data []byte) (Hello2Msg, error) {
	var m Hello2Msg
	if err := json.Unmarshal(data, &m); err != nil {
		return Hello2Msg{}, err
	}
	if m.Type != "" && m.Type != MsgTypeHello2 {
		return Hello2Msg{}, fmt.Errorf("unexpected msg type: %s", m.Type)
	}
	return m, nil
}

func Hello1Bytes(fromID, toID [32]byte, ea, na []byte) []byte {
	buf := make([]byte, 0, 32+32+len(ea)+len(na))
	buf = append(buf, fromID[:]...)
	buf = append(buf, toID[:]...)
	buf = append(buf, ea...)
	buf = append(buf, na...)
	return buf
}

func Hello2Bytes(fromID, toID [32]byte, eb, nb []byte) []byte {
	buf := make([]byte, 0, 32+32+len(eb)+len(nb))
	buf = append(buf, fromID[:]...)
	buf = append(buf, toID[:]...)
	buf = append(buf, eb...)
	buf = append(buf, nb...)
	return buf
}

func DecodeHello1Fields(m Hello1Msg) ([32]byte, [32]byte, []byte, []byte, []byte, []byte, error) {
	var fromID, toID [32]byte
	fromBytes, err := hex.DecodeString(m.FromNodeID)
	if err != nil || len(fromBytes) != 32 {
		return fromID, toID, nil, nil, nil, nil, fmt.Errorf("bad from_node_id")
	}
	fromPub, err := hex.DecodeString(m.FromPub)
	if err != nil || len(fromPub) == 0 {
		return fromID, toID, nil, nil, nil, nil, fmt.Errorf("bad from_pub")
	}
	toBytes, err := hex.DecodeString(m.ToNodeID)
	if err != nil || len(toBytes) != 32 {
		return fromID, toID, nil, nil, nil, nil, fmt.Errorf("bad to_node_id")
	}
	ea, err := hex.DecodeString(m.EA)
	if err != nil || len(ea) != 32 {
		return fromID, toID, nil, nil, nil, nil, fmt.Errorf("bad ea")
	}
	na, err := hex.DecodeString(m.Na)
	if err != nil || len(na) != 32 {
		return fromID, toID, nil, nil, nil, nil, fmt.Errorf("bad na")
	}
	sig, err := hex.DecodeString(m.Sig)
	if err != nil || len(sig) == 0 {
		return fromID, toID, nil, nil, nil, nil, fmt.Errorf("bad sig")
	}
	copy(fromID[:], fromBytes)
	copy(toID[:], toBytes)
	return fromID, toID, fromPub, ea, na, sig, nil
}

func DecodeHello2Fields(m Hello2Msg) ([32]byte, [32]byte, []byte, []byte, []byte, []byte, error) {
	var fromID, toID [32]byte
	fromBytes, err := hex.DecodeString(m.FromNodeID)
	if err != nil || len(fromBytes) != 32 {
		return fromID, toID, nil, nil, nil, nil, fmt.Errorf("bad from_node_id")
	}
	fromPub, err := hex.DecodeString(m.FromPub)
	if err != nil || len(fromPub) == 0 {
		return fromID, toID, nil, nil, nil, nil, fmt.Errorf("bad from_pub")
	}
	toBytes, err := hex.DecodeString(m.ToNodeID)
	if err != nil || len(toBytes) != 32 {
		return fromID, toID, nil, nil, nil, nil, fmt.Errorf("bad to_node_id")
	}
	eb, err := hex.DecodeString(m.EB)
	if err != nil || len(eb) != 32 {
		return fromID, toID, nil, nil, nil, nil, fmt.Errorf("bad eb")
	}
	nb, err := hex.DecodeString(m.Nb)
	if err != nil || len(nb) != 32 {
		return fromID, toID, nil, nil, nil, nil, fmt.Errorf("bad nb")
	}
	sig, err := hex.DecodeString(m.Sig)
	if err != nil || len(sig) == 0 {
		return fromID, toID, nil, nil, nil, nil, fmt.Errorf("bad sig")
	}
	copy(fromID[:], fromBytes)
	copy(toID[:], toBytes)
	return fromID, toID, fromPub, eb, nb, sig, nil
}
