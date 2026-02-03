package wallet

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Claim struct {
	ID        string    `json:"id"`
	FromNode  string    `json:"from_node"`
	ToNode    string    `json:"to_node"`
	Amount    int64     `json:"amount"`
	CreatedAt time.Time `json:"created_at"`
	ViewID    string    `json:"view_id,omitempty"`
	ScopeHash string    `json:"scope_hash,omitempty"`
	DeltaID   string    `json:"delta_id,omitempty"`
}

type Store struct {
	path string
}

func NewStore(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("missing path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	return &Store{path: path}, nil
}

func NewClaim(fromNode, toNode string, amount int64) (Claim, error) {
	if fromNode == "" || toNode == "" {
		return Claim{}, fmt.Errorf("missing node id")
	}
	if amount == 0 {
		return Claim{}, fmt.Errorf("amount must be non-zero")
	}
	var id [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		return Claim{}, err
	}
	return Claim{
		ID:        hex.EncodeToString(id[:]),
		FromNode:  fromNode,
		ToNode:    toNode,
		Amount:    amount,
		CreatedAt: time.Now().UTC(),
	}, nil
}

func (s *Store) Add(c Claim) error {
	if s == nil || s.path == "" {
		return fmt.Errorf("missing store")
	}
	if c.ID == "" {
		return fmt.Errorf("missing claim id")
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	return enc.Encode(c)
}

func (s *Store) List(limit int) ([]Claim, error) {
	if s == nil || s.path == "" {
		return nil, fmt.Errorf("missing store")
	}
	f, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	if limit <= 0 {
		limit = 100
	}
	out := make([]Claim, 0, limit)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var c Claim
		if err := json.Unmarshal(scanner.Bytes(), &c); err != nil {
			continue
		}
		out = append(out, c)
		if len(out) >= limit {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return out, err
	}
	return out, nil
}
