package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"web4mvp/internal/crypto"
	"web4mvp/internal/network"
	"web4mvp/internal/proto"
	"web4mvp/internal/store"
)

func TestOpenCloseAckFlow(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()

	runOK(t, homeB, "keygen")
	runOK(t, homeA, "keygen")

	pubA := loadPub(t, homeA)
	pubB := loadPub(t, homeB)

	openMsgPath := filepath.Join(t.TempDir(), "open.json")
	runOK(t, homeB, "open",
		"--to", hex.EncodeToString(pubA),
		"--amount", "500",
		"--nonce", "1",
		"--out", openMsgPath,
	)
	runOK(t, homeA, "recv", "--in", openMsgPath)

	iou := proto.IOU{Creditor: pubA, Debtor: pubB, Amount: 500, Nonce: 1}
	cid := proto.ContractID(iou)
	cidHex := hex.EncodeToString(cid[:])

	closeMsgPath := filepath.Join(t.TempDir(), "close.json")
	runOK(t, homeB, "close",
		"--id", cidHex,
		"--reqnonce", "1",
		"--out", closeMsgPath,
	)
	runOK(t, homeA, "recv", "--in", closeMsgPath)
	runOK(t, homeB, "recv", "--in", closeMsgPath)

	ackMsgPath := filepath.Join(t.TempDir(), "ack.json")
	runOK(t, homeA, "ack",
		"--id", cidHex,
		"--reqnonce", "1",
		"--decision", "1",
		"--out", ackMsgPath,
	)
	runOK(t, homeB, "recv", "--in", ackMsgPath)

	if err := runWithHome(homeA, "close", "--id", cidHex, "--reqnonce", "2"); err == nil || !strings.Contains(err.Error(), "debtor mismatch") {
		t.Fatalf("expected debtor mismatch error, got: %v", err)
	}

	closeMsg, err := os.ReadFile(closeMsgPath)
	if err != nil {
		t.Fatalf("read close message failed: %v", err)
	}
	repayMsg, err := proto.DecodeRepayReqMsg(closeMsg)
	if err != nil {
		t.Fatalf("decode repay request failed: %v", err)
	}
	if err := runWithHome(homeB, "ack",
		"--id", cidHex,
		"--reqnonce", "1",
		"--sigb", repayMsg.SigB,
		"--decision", "1",
	); err == nil || !strings.Contains(err.Error(), "creditor mismatch") {
		t.Fatalf("expected creditor mismatch error, got: %v", err)
	}
}

func TestOpenSealedDecrypt(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()

	runOK(t, homeA, "keygen")
	runOK(t, homeB, "keygen")

	pubA, privA := loadKeypair(t, homeA)
	pubB, _ := loadKeypair(t, homeB)

	openMsgPath := filepath.Join(t.TempDir(), "open.json")
	runOK(t, homeB, "open",
		"--to", hex.EncodeToString(pubA),
		"--amount", "42",
		"--nonce", "7",
		"--out", openMsgPath,
	)

	data, err := os.ReadFile(openMsgPath)
	if err != nil {
		t.Fatalf("read open msg failed: %v", err)
	}
	msg, err := proto.DecodeContractOpenMsg(data)
	if err != nil {
		t.Fatalf("decode open msg failed: %v", err)
	}
	ephPub, err := base64.StdEncoding.DecodeString(msg.EphemeralPub)
	if err != nil {
		t.Fatalf("decode eph pub failed: %v", err)
	}
	sealed, err := base64.StdEncoding.DecodeString(msg.Sealed)
	if err != nil {
		t.Fatalf("decode sealed failed: %v", err)
	}

	privX, err := crypto.Ed25519PrivToX25519(privA)
	if err != nil {
		t.Fatalf("convert priv failed: %v", err)
	}
	shared, err := crypto.X25519Shared(privX, ephPub)
	if err != nil {
		t.Fatalf("shared failed: %v", err)
	}
	key, err := crypto.DeriveKeyE(shared, "web4:v0:e2e:contract_open", 32)
	if err != nil {
		t.Fatalf("derive key failed: %v", err)
	}

	iou := proto.IOU{Creditor: pubA, Debtor: pubB, Amount: 42, Nonce: 7}
	cid := proto.ContractID(iou)
	nonce := e2eNonceForTest(cid, 0, ephPub)
	plain, err := crypto.XOpen(key, nonce, sealed, nil)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	want, err := proto.EncodeOpenPayload(hex.EncodeToString(pubA), hex.EncodeToString(pubB), 42, 7)
	if err != nil {
		t.Fatalf("encode payload failed: %v", err)
	}
	if !bytes.Equal(plain, want) {
		t.Fatalf("payload mismatch")
	}
}

func TestRepayReqSealedTamper(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()

	runOK(t, homeA, "keygen")
	runOK(t, homeB, "keygen")

	pubA := loadPub(t, homeA)
	pubB := loadPub(t, homeB)

	openMsgPath := filepath.Join(t.TempDir(), "open.json")
	runOK(t, homeB, "open",
		"--to", hex.EncodeToString(pubA),
		"--amount", "5",
		"--nonce", "1",
		"--out", openMsgPath,
	)
	runOK(t, homeA, "recv", "--in", openMsgPath)

	iou := proto.IOU{Creditor: pubA, Debtor: pubB, Amount: 5, Nonce: 1}
	cid := proto.ContractID(iou)
	cidHex := hex.EncodeToString(cid[:])

	closeMsgPath := filepath.Join(t.TempDir(), "close.json")
	runOK(t, homeB, "close",
		"--id", cidHex,
		"--reqnonce", "1",
		"--out", closeMsgPath,
	)

	raw, err := os.ReadFile(closeMsgPath)
	if err != nil {
		t.Fatalf("read close msg failed: %v", err)
	}
	var msg proto.RepayReqMsg
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatalf("decode close msg failed: %v", err)
	}
	sealed, err := base64.StdEncoding.DecodeString(msg.Sealed)
	if err != nil {
		t.Fatalf("decode sealed failed: %v", err)
	}
	if len(sealed) == 0 {
		t.Fatalf("sealed empty")
	}
	sealed[0] ^= 0xff
	msg.Sealed = base64.StdEncoding.EncodeToString(sealed)
	tampered, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("encode tampered failed: %v", err)
	}
	tamperedPath := filepath.Join(t.TempDir(), "close-tampered.json")
	if err := os.WriteFile(tamperedPath, tampered, 0600); err != nil {
		t.Fatalf("write tampered failed: %v", err)
	}

	runOK(t, homeA, "recv", "--in", tamperedPath)
	if err := runWithHome(homeA, "ack", "--id", cidHex, "--reqnonce", "1", "--decision", "1"); err == nil || !strings.Contains(err.Error(), "invalid sigb") {
		t.Fatalf("expected invalid sigb error, got: %v", err)
	}
}

func TestQuicRecvOpen(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()

	runOK(t, homeA, "keygen")
	runOK(t, homeB, "keygen")

	pubA := loadPub(t, homeA)
	pubB := loadPub(t, homeB)

	openMsgPath := filepath.Join(t.TempDir(), "open.json")
	runOK(t, homeB, "open",
		"--to", hex.EncodeToString(pubA),
		"--amount", "10",
		"--nonce", "1",
		"--out", openMsgPath,
	)
	iou := proto.IOU{Creditor: pubA, Debtor: pubB, Amount: 10, Nonce: 1}
	cid := proto.ContractID(iou)
	cidHex := hex.EncodeToString(cid[:])

	addr := freeUDPAddr(t)
	root := filepath.Join(homeA, ".web4mvp")
	_ = os.MkdirAll(root, 0700)
	st := store.New(
		filepath.Join(root, "contracts.jsonl"),
		filepath.Join(root, "acks.jsonl"),
		filepath.Join(root, "repayreqs.jsonl"),
	)
	ready := make(chan struct{})
	done := make(chan struct{})
	go func() {
		_ = network.ListenAndServeWithReady(addr, ready, func(data []byte) {
			recvData(data, st)
			select {
			case <-done:
			default:
				close(done)
			}
		})
	}()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for quic server ready")
	}

	msgData, err := os.ReadFile(openMsgPath)
	if err != nil {
		t.Fatalf("read open msg failed: %v", err)
	}
	if err := network.Send(addr, msgData, true); err != nil {
		t.Fatalf("quic send failed: %v", err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for quic receive")
	}
	waitForContract(t, homeA, cidHex, 5*time.Second)
}

func runOK(t *testing.T, home string, args ...string) {
	t.Helper()
	if err := runWithHome(home, args...); err != nil {
		t.Fatalf("command failed: %v\nargs=%v", err, args)
	}
}

func runWithHome(home string, args ...string) error {
	if err := ensureGoCaches(); err != nil {
		return err
	}
	cmd := exec.Command("go", append([]string{"run", "."}, args...)...)
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	cmd.Dir = wd
	cmd.Env = applyEnv(os.Environ(),
		"HOME="+home,
		"GOMODCACHE="+modCacheDir,
		"GOCACHE="+goCacheDir,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func loadPub(t *testing.T, home string) []byte {
	t.Helper()
	root := filepath.Join(home, ".web4mvp")
	pub, _, err := crypto.LoadKeypair(root)
	if err != nil {
		t.Fatalf("load keypair failed: %v", err)
	}
	return pub
}

func loadKeypair(t *testing.T, home string) ([]byte, []byte) {
	t.Helper()
	root := filepath.Join(home, ".web4mvp")
	pub, priv, err := crypto.LoadKeypair(root)
	if err != nil {
		t.Fatalf("load keypair failed: %v", err)
	}
	return pub, priv
}

func waitForContract(t *testing.T, home, cidHex string, timeout time.Duration) {
	t.Helper()
	contractsPath := filepath.Join(home, ".web4mvp", "contracts.jsonl")
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(contractsPath)
		if err == nil && len(data) != 0 {
			sc := bufio.NewScanner(strings.NewReader(string(data)))
			for sc.Scan() {
				var c proto.Contract
				if err := json.Unmarshal(sc.Bytes(), &c); err == nil {
					id := proto.ContractID(c.IOU)
					if hex.EncodeToString(id[:]) == cidHex {
						return
					}
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for contract %s", cidHex)
}

func freeUDPAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp failed: %v", err)
	}
	defer pc.Close()
	return pc.LocalAddr().String()
}

var (
	cacheOnce   sync.Once
	modCacheDir string
	goCacheDir  string
	cacheErr    error
)

func ensureGoCaches() error {
	cacheOnce.Do(func() {
		modCacheDir, cacheErr = goEnvValue("GOMODCACHE")
		if cacheErr != nil {
			return
		}
		goCacheDir, cacheErr = goEnvValue("GOCACHE")
	})
	return cacheErr
}

func goEnvValue(key string) (string, error) {
	cmd := exec.Command("go", "env", key)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func e2eNonceForTest(contractID [32]byte, reqNonce uint64, ephPub []byte) []byte {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], reqNonce)
	buf := make([]byte, 0, len("web4:v0:nonce|")+32+8+len(ephPub))
	buf = append(buf, []byte("web4:v0:nonce|")...)
	buf = append(buf, contractID[:]...)
	buf = append(buf, tmp[:]...)
	buf = append(buf, ephPub...)
	sum := crypto.SHA3_256(buf)
	return sum[:crypto.XNonceSize]
}

func applyEnv(base []string, overrides ...string) []string {
	out := make([]string, 0, len(base)+len(overrides))
	overrideKeys := make(map[string]string, len(overrides))
	for _, kv := range overrides {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		overrideKeys[parts[0]] = kv
	}
	for _, kv := range base {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		if _, exists := overrideKeys[parts[0]]; exists {
			continue
		}
		out = append(out, kv)
	}
	for _, kv := range overrides {
		out = append(out, kv)
	}
	return out
}
