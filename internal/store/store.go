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
	"strconv"

	"web4mvp/internal/proto"
)

type Store struct {
	contractsPath string
	acksPath      string
	repayReqsPath string
}

const maxScanSize = 2 * proto.MaxFrameSize

var (
	MaxLinesPerFile = 200_000
	MaxBytesPerFile = 64 << 20
	MaxRotations    = 3
)

func init() {
	maxInt := int64(int(^uint(0) >> 1))
	if v := os.Getenv("WEB4_STORE_MAX_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 && n <= maxInt {
			MaxBytesPerFile = int(n)
		}
	}
	if v := os.Getenv("WEB4_STORE_MAX_LINES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 && n <= maxInt {
			MaxLinesPerFile = int(n)
		}
	}
}

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
	return appendJSONL(s.contractsPath, c)
}

func (s *Store) ListContracts() ([]proto.Contract, error) {
	var out []proto.Contract
	paths := scanPaths(s.contractsPath)
	for i, path := range paths {
		f, err := openRead(path, i == 0)
		if err != nil {
			return nil, err
		}
		if f == nil {
			continue
		}
		sc := newScanner(f)
		for sc.Scan() {
			var c proto.Contract
			if err := json.Unmarshal(sc.Bytes(), &c); err == nil {
				out = append(out, c)
			}
		}
		if err := sc.Err(); err != nil {
			_ = f.Close()
			return nil, err
		}
		_ = f.Close()
	}
	return out, nil
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

	return appendJSONL(s.acksPath, r)
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
	type rec struct {
		Ack proto.Ack `json:"ack"`
	}
	paths := scanPaths(s.acksPath)
	for i, path := range paths {
		f, err := openRead(path, i == 0)
		if err != nil {
			return false, err
		}
		if f == nil {
			continue
		}
		sc := newScanner(f)
		for sc.Scan() {
			var r rec
			if err := json.Unmarshal(sc.Bytes(), &r); err == nil {
				if hex.EncodeToString(r.Ack.ContractID[:]) == contractID && r.Ack.ReqNonce == reqNonce {
					_ = f.Close()
					return true, nil
				}
			}
		}
		if err := sc.Err(); err != nil {
			_ = f.Close()
			return false, err
		}
		_ = f.Close()
	}
	return false, nil
}

func (s *Store) AddRepayReq(m proto.RepayReqMsg) error {
	return appendJSONL(s.repayReqsPath, m)
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
	paths := scanPaths(s.repayReqsPath)
	for i, path := range paths {
		f, err := openRead(path, i == 0)
		if err != nil {
			return false, err
		}
		if f == nil {
			continue
		}
		sc := newScanner(f)
		for sc.Scan() {
			var m proto.RepayReqMsg
			if err := json.Unmarshal(sc.Bytes(), &m); err == nil {
				if m.ContractID == contractID && m.ReqNonce == reqNonce {
					_ = f.Close()
					return true, nil
				}
			}
		}
		if err := sc.Err(); err != nil {
			_ = f.Close()
			return false, err
		}
		_ = f.Close()
	}
	return false, nil
}

func (s *Store) FindRepayReq(contractID string, reqNonce uint64) (*proto.RepayReqMsg, error) {
	paths := scanPaths(s.repayReqsPath)
	for i, path := range paths {
		f, err := openRead(path, i == 0)
		if err != nil {
			return nil, err
		}
		if f == nil {
			continue
		}
		sc := newScanner(f)
		for sc.Scan() {
			var m proto.RepayReqMsg
			if err := json.Unmarshal(sc.Bytes(), &m); err == nil {
				if m.ContractID == contractID && m.ReqNonce == reqNonce {
					_ = f.Close()
					return &m, nil
				}
			}
		}
		if err := sc.Err(); err != nil {
			_ = f.Close()
			return nil, err
		}
		_ = f.Close()
	}
	return nil, nil
}

func (s *Store) MaxRepayReqNonce(contractID string) (uint64, bool, error) {
	var max uint64
	var found bool
	paths := scanPaths(s.repayReqsPath)
	for i, path := range paths {
		f, err := openRead(path, i == 0)
		if err != nil {
			return 0, false, err
		}
		if f == nil {
			continue
		}
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
			_ = f.Close()
			return 0, false, err
		}
		_ = f.Close()
	}
	return max, found, nil
}

func openRead(path string, create bool) (*os.File, error) {
	if create {
		return os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0600)
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return f, nil
}

func scanPaths(path string) []string {
	out := make([]string, 0, MaxRotations+1)
	out = append(out, path)
	for i := 1; i <= MaxRotations; i++ {
		out = append(out, fmt.Sprintf("%s.%d", path, i))
	}
	return out
}

func appendJSONL(path string, v any) error {
	line, err := json.Marshal(v)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	if err := rotateIfNeeded(path, len(line)); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(line); err != nil {
		return err
	}
	return syncFile(f)
}

func AppendJSONL(path string, v any) error {
	return appendJSONL(path, v)
}

func rotateIfNeeded(path string, addBytes int) error {
	if MaxLinesPerFile <= 0 && MaxBytesPerFile <= 0 {
		return nil
	}
	curBytes := int64(0)
	if info, err := os.Stat(path); err == nil {
		curBytes = info.Size()
	} else if !os.IsNotExist(err) {
		return err
	}
	curLines := 0
	if MaxLinesPerFile > 0 {
		lines, err := countLines(path)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		curLines = lines
	}
	nextBytes := curBytes + int64(addBytes)
	nextLines := curLines + 1
	if (MaxBytesPerFile > 0 && nextBytes > int64(MaxBytesPerFile)) ||
		(MaxLinesPerFile > 0 && nextLines > MaxLinesPerFile) {
		return rotateFiles(path)
	}
	return nil
}

func rotateFiles(path string) error {
	if MaxRotations <= 0 {
		return nil
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for i := MaxRotations - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", path, i)
		dst := fmt.Sprintf("%s.%d", path, i+1)
		if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := os.Rename(src, dst); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err := os.Remove(fmt.Sprintf("%s.%d", path, 1)); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(path, fmt.Sprintf("%s.%d", path, 1)); err != nil {
		return err
	}
	syncDir(path)
	return nil
}

func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := newScanner(f)
	lines := 0
	for sc.Scan() {
		if len(sc.Bytes()) != 0 {
			lines++
		}
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return lines, nil
}

func (s *Store) Debug() (string, error) {
	_, err := os.Stat(s.contractsPath)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("contracts=%s acks=%s repayreqs=%s", s.contractsPath, s.acksPath, s.repayReqsPath), nil
}
