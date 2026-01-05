// internal/store/store.go
package store

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"web4mvp/internal/proto"
)

type Store struct {
	contractsPath string
	acksPath      string
	repayReqsPath string
}

const maxScanSize = 2 * proto.MaxFrameSize

func New(contractsPath, acksPath, repayReqsPath string) *Store {
	_ = os.MkdirAll(filepath.Dir(contractsPath), 0700)
	return &Store{contractsPath: contractsPath, acksPath: acksPath, repayReqsPath: repayReqsPath}
}

func newScanner(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxScanSize)
	return sc
}

func syncFile(f *os.File) error {
	if f == nil {
		return nil
	}
	return f.Sync()
}

func syncDir(path string) {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return
	}
	defer dir.Close()
	_ = dir.Sync()
}

func (s *Store) AddContract(c proto.Contract) error {
	f, err := os.OpenFile(s.contractsPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(c); err != nil {
		return err
	}
	return syncFile(f)
}

func (s *Store) ListContracts() ([]proto.Contract, error) {
	f, err := os.OpenFile(s.contractsPath, os.O_CREATE|os.O_RDONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []proto.Contract
	sc := newScanner(f)
	for sc.Scan() {
		var c proto.Contract
		if err := json.Unmarshal(sc.Bytes(), &c); err == nil {
			out = append(out, c)
		}
	}
	return out, sc.Err()
}

func (s *Store) MarkClosed(cid [32]byte, forget bool) error {
	cs, err := s.ListContracts()
	if err != nil {
		return err
	}
	idHex := hex.EncodeToString(cid[:])

	// rewrite file
	tmp := s.contractsPath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(f)
	for _, c := range cs {
		id := proto.ContractID(c.IOU)
		if hex.EncodeToString(id[:]) == idHex {
			if forget {
				continue
			}
			c.Status = "CLOSED"
		}
		if err := enc.Encode(c); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := syncFile(f); err != nil {
		_ = f.Close()
		return err
	}

	// ✅ 윈도우: Rename 전에 반드시 닫기
	if err := f.Close(); err != nil {
		return err
	}

	// ✅ Rename는 딱 한 번만
	if err := os.Rename(tmp, s.contractsPath); err != nil {
		return err
	}
	syncDir(s.contractsPath)
	return nil
}

func (s *Store) AddAck(a proto.Ack, sigA []byte) error {
	type rec struct {
		Ack  proto.Ack `json:"ack"`
		SigA string    `json:"sigA"`
		Hash string    `json:"hash"`
	}
	h := sha256.Sum256(append(proto.AckBytes(a), sigA...))
	r := rec{Ack: a, SigA: hex.EncodeToString(sigA), Hash: hex.EncodeToString(h[:])}

	f, err := os.OpenFile(s.acksPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(r); err != nil {
		return err
	}
	return syncFile(f)
}

func (s *Store) AddAckIfNew(a proto.Ack, sigA []byte) error {
	exists, err := s.HasAck(hex.EncodeToString(a.ContractID[:]), a.ReqNonce)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return s.AddAck(a, sigA)
}

func (s *Store) HasAck(contractID string, reqNonce uint64) (bool, error) {
	f, err := os.OpenFile(s.acksPath, os.O_CREATE|os.O_RDONLY, 0600)
	if err != nil {
		return false, err
	}
	defer f.Close()

	type rec struct {
		Ack proto.Ack `json:"ack"`
	}
	sc := newScanner(f)
	for sc.Scan() {
		var r rec
		if err := json.Unmarshal(sc.Bytes(), &r); err == nil {
			if hex.EncodeToString(r.Ack.ContractID[:]) == contractID && r.Ack.ReqNonce == reqNonce {
				return true, nil
			}
		}
	}
	if err := sc.Err(); err != nil {
		return false, err
	}
	return false, nil
}

func (s *Store) AddRepayReq(m proto.RepayReqMsg) error {
	f, err := os.OpenFile(s.repayReqsPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(m); err != nil {
		return err
	}
	return syncFile(f)
}

func (s *Store) AddRepayReqIfNew(m proto.RepayReqMsg) error {
	exists, err := s.HasRepayReq(m.ContractID, m.ReqNonce)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return s.AddRepayReq(m)
}

func (s *Store) HasRepayReq(contractID string, reqNonce uint64) (bool, error) {
	f, err := os.OpenFile(s.repayReqsPath, os.O_CREATE|os.O_RDONLY, 0600)
	if err != nil {
		return false, err
	}
	defer f.Close()

	sc := newScanner(f)
	for sc.Scan() {
		var m proto.RepayReqMsg
		if err := json.Unmarshal(sc.Bytes(), &m); err == nil {
			if m.ContractID == contractID && m.ReqNonce == reqNonce {
				return true, nil
			}
		}
	}
	if err := sc.Err(); err != nil {
		return false, err
	}
	return false, nil
}

func (s *Store) FindRepayReq(contractID string, reqNonce uint64) (*proto.RepayReqMsg, error) {
	f, err := os.OpenFile(s.repayReqsPath, os.O_CREATE|os.O_RDONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sc := newScanner(f)
	for sc.Scan() {
		var m proto.RepayReqMsg
		if err := json.Unmarshal(sc.Bytes(), &m); err == nil {
			if m.ContractID == contractID && m.ReqNonce == reqNonce {
				return &m, nil
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, nil
}

func (s *Store) MaxRepayReqNonce(contractID string) (uint64, bool, error) {
	f, err := os.OpenFile(s.repayReqsPath, os.O_CREATE|os.O_RDONLY, 0600)
	if err != nil {
		return 0, false, err
	}
	defer f.Close()

	var max uint64
	var found bool
	sc := newScanner(f)
	for sc.Scan() {
		var m proto.RepayReqMsg
		if err := json.Unmarshal(sc.Bytes(), &m); err == nil {
			if m.ContractID == contractID {
				if !found || m.ReqNonce > max {
					max = m.ReqNonce
					found = true
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return 0, false, err
	}
	return max, found, nil
}

func (s *Store) Debug() (string, error) {
	_, err := os.Stat(s.contractsPath)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("contracts=%s acks=%s repayreqs=%s", s.contractsPath, s.acksPath, s.repayReqsPath), nil
}
