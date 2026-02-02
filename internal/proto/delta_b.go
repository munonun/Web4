package proto

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
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
	entries, err := CanonicalizeDeltaBEntries(m.Entries)
	if err != nil {
		return nil, err
	}
	m.Entries = entries
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

func CanonicalizeDeltaBEntries(entries []DeltaBEntry) ([]DeltaBEntry, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("empty entries")
	}
	out := make([]DeltaBEntry, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		if e.Delta == 0 {
			continue
		}
		id := strings.TrimSpace(e.NodeID)
		if id == "" {
			return nil, fmt.Errorf("missing node_id")
		}
		raw, err := hex.DecodeString(id)
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("bad node_id")
		}
		key := hex.EncodeToString(raw)
		if _, ok := seen[key]; ok {
			return nil, fmt.Errorf("duplicate node_id")
		}
		seen[key] = struct{}{}
		out = append(out, DeltaBEntry{NodeID: key, Delta: e.Delta})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty entries")
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].NodeID < out[j].NodeID
	})
	return out, nil
}
