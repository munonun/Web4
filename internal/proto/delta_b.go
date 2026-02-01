package proto

import (
	"encoding/json"
	"fmt"
	"sort"
)

const (
	MsgTypeDeltaB = "delta_b"
)

type DeltaBEntry struct {
	NodeID string `json:"node_id"`
	Delta  int64  `json:"delta"`
}

type DeltaBMsg struct {
	Type         string         `json:"type"`
	ProtoVersion string         `json:"proto_version"`
	Suite        string         `json:"suite"`
	ViewID       string         `json:"view_id"`
	Entries      []DeltaBEntry  `json:"entries"`
	ZK           *ZKLinearProof `json:"zk,omitempty"`
}

func EncodeDeltaBMsg(m DeltaBMsg) ([]byte, error) {
	m.Type = MsgTypeDeltaB
	if len(m.Entries) > 1 {
		entries := make([]DeltaBEntry, len(m.Entries))
		copy(entries, m.Entries)
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].NodeID < entries[j].NodeID
		})
		m.Entries = entries
	}
	return json.Marshal(m)
}

func DecodeDeltaBMsg(data []byte) (DeltaBMsg, error) {
	var m DeltaBMsg
	if err := json.Unmarshal(data, &m); err != nil {
		return DeltaBMsg{}, err
	}
	if m.Type != "" && m.Type != MsgTypeDeltaB {
		return DeltaBMsg{}, fmt.Errorf("unexpected msg type: %s", m.Type)
	}
	return m, nil
}
