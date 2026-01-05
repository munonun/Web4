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
	if err := runWithHome(homeB, "recv", "--in", closeMsgPath); err == nil || !strings.Contains(err.Error(), "sealed repay request failed") {
		t.Fatalf("expected recipient decrypt failure, got: %v", err)
	}

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

	if err := runWithHome(homeA, "recv", "--in", tamperedPath); err == nil || !strings.Contains(err.Error(), "invalid sigb") {
		t.Fatalf("expected invalid sigb error, got: %v", err)
	}
}

func TestAckSigTamperRejectedOnRecv(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()

	runOK(t, homeA, "keygen")
	runOK(t, homeB, "keygen")

	pubA := loadPub(t, homeA)
	pubB := loadPub(t, homeB)

	openMsgPath := filepath.Join(t.TempDir(), "open.json")
	runOK(t, homeB, "open",
		"--to", hex.EncodeToString(pubA),
		"--amount", "3",
		"--nonce", "1",
		"--out", openMsgPath,
	)
	runOK(t, homeA, "recv", "--in", openMsgPath)

	iou := proto.IOU{Creditor: pubA, Debtor: pubB, Amount: 3, Nonce: 1}
	cid := proto.ContractID(iou)
	cidHex := hex.EncodeToString(cid[:])

	closeMsgPath := filepath.Join(t.TempDir(), "close.json")
	runOK(t, homeB, "close",
		"--id", cidHex,
		"--reqnonce", "1",
		"--out", closeMsgPath,
	)
	runOK(t, homeA, "recv", "--in", closeMsgPath)

	ackMsgPath := filepath.Join(t.TempDir(), "ack.json")
	runOK(t, homeA, "ack",
		"--id", cidHex,
		"--reqnonce", "1",
		"--decision", "1",
		"--out", ackMsgPath,
	)
	raw, err := os.ReadFile(ackMsgPath)
	if err != nil {
		t.Fatalf("read ack failed: %v", err)
	}
	var msg proto.AckMsg
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatalf("decode ack failed: %v", err)
	}
	sig, err := hex.DecodeString(msg.SigA)
	if err != nil {
		t.Fatalf("decode sigA failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatalf("sigA empty")
	}
	sig[0] ^= 0xff
	msg.SigA = hex.EncodeToString(sig)
	tampered, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("encode tampered ack failed: %v", err)
	}
	tamperedPath := filepath.Join(t.TempDir(), "ack-tampered.json")
	if err := os.WriteFile(tamperedPath, tampered, 0600); err != nil {
		t.Fatalf("write tampered ack failed: %v", err)
	}

	if err := runWithHome(homeB, "recv", "--in", tamperedPath); err == nil || !strings.Contains(err.Error(), "invalid siga") {
		t.Fatalf("expected invalid siga error, got: %v", err)
	}
}

func TestE2ESealFreshEphemeralPerCall(t *testing.T) {
	pub, _, err := crypto.GenKeypair()
	if err != nil {
		t.Fatalf("generate keypair failed: %v", err)
	}
	var cid [32]byte
	copy(cid[:], []byte("web4:e2e:seal:fresh:ephemeral"))
	payload := []byte("payload")

	ephPub1, sealed1, err := e2eSeal(proto.MsgTypeContractOpen, cid, 0, pub, payload)
	if err != nil {
		t.Fatalf("e2eSeal first call failed: %v", err)
	}
	ephPub2, sealed2, err := e2eSeal(proto.MsgTypeContractOpen, cid, 0, pub, payload)
	if err != nil {
		t.Fatalf("e2eSeal second call failed: %v", err)
	}

	if bytes.Equal(ephPub1, ephPub2) {
		t.Fatalf("expected different ephemeral public keys per call")
	}
	if bytes.Equal(sealed1, sealed2) {
		t.Fatalf("expected different sealed outputs per call")
	}
}

func TestRecvRejectsOversizeAck(t *testing.T) {
	home := t.TempDir()
	runOK(t, home, "keygen")
	data := oversizedPayload(t, proto.MsgTypeAck, maxAckSize)
	inPath := filepath.Join(t.TempDir(), "ack-oversize.json")
	if err := os.WriteFile(inPath, data, 0600); err != nil {
		t.Fatalf("write oversize ack failed: %v", err)
	}
	if err := runWithHome(home, "recv", "--in", inPath); err == nil || !strings.Contains(err.Error(), "message too large") {
		t.Fatalf("expected size rejection, got: %v", err)
	}
}

func TestRecvRejectsOversizeRepayReq(t *testing.T) {
	home := t.TempDir()
	runOK(t, home, "keygen")
	data := oversizedPayload(t, proto.MsgTypeRepayReq, maxRepayReqSize)
	inPath := filepath.Join(t.TempDir(), "repay-oversize.json")
	if err := os.WriteFile(inPath, data, 0600); err != nil {
		t.Fatalf("write oversize repay req failed: %v", err)
	}
	if err := runWithHome(home, "recv", "--in", inPath); err == nil || !strings.Contains(err.Error(), "message too large") {
		t.Fatalf("expected size rejection, got: %v", err)
	}
}

func TestRecvRejectsMismatchedOpenPayload(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()

	runOK(t, homeA, "keygen")
	runOK(t, homeB, "keygen")

	pubA, _ := loadKeypair(t, homeA)
	pubB, privB := loadKeypair(t, homeB)

	iou := proto.IOU{Creditor: pubA, Debtor: pubB, Amount: 5, Nonce: 1}
	cid := proto.ContractID(iou)
	payload, err := proto.EncodeOpenPayload(hex.EncodeToString(pubA), hex.EncodeToString(pubB), 999, 1)
	if err != nil {
		t.Fatalf("encode open payload failed: %v", err)
	}
	ephPub, sealed, err := e2eSeal(proto.MsgTypeContractOpen, cid, 0, pubA, payload)
	if err != nil {
		t.Fatalf("e2e seal failed: %v", err)
	}
	signBytes := proto.OpenSignBytes(iou, ephPub, sealed)
	sigB := crypto.Sign(privB, crypto.SHA3_256(signBytes))
	msg := proto.ContractOpenMsgFromContract(proto.Contract{
		IOU:          iou,
		SigDebt:      sigB,
		EphemeralPub: ephPub,
		Sealed:       sealed,
		Status:       "OPEN",
	})
	data, err := proto.EncodeContractOpenMsg(msg)
	if err != nil {
		t.Fatalf("encode open msg failed: %v", err)
	}
	inPath := filepath.Join(t.TempDir(), "open-mismatch.json")
	if err := os.WriteFile(inPath, data, 0600); err != nil {
		t.Fatalf("write open msg failed: %v", err)
	}
	if err := runWithHome(homeA, "recv", "--in", inPath); err == nil || !strings.Contains(err.Error(), "payload mismatch") {
		t.Fatalf("expected payload mismatch, got: %v", err)
	}
}

func TestRecvRejectsAckWithoutRepayReq(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()

	runOK(t, homeA, "keygen")
	runOK(t, homeB, "keygen")

	pubA, privA := loadKeypair(t, homeA)
	pubB, _ := loadKeypair(t, homeB)

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

	ackPayload, err := proto.EncodeAckPayload(cidHex, 1, true)
	if err != nil {
		t.Fatalf("encode ack payload failed: %v", err)
	}
	ackEph, ackSealed, err := e2eSeal(proto.MsgTypeAck, cid, 1, pubB, ackPayload)
	if err != nil {
		t.Fatalf("e2e seal ack failed: %v", err)
	}
	ack := proto.Ack{
		ContractID:   cid,
		ReqNonce:     1,
		Decision:     1,
		Close:        true,
		EphemeralPub: ackEph,
		Sealed:       ackSealed,
	}
	ackSign := proto.AckSignBytes(cid, ack.Decision, ack.Close, ackEph, ackSealed)
	sigA := crypto.Sign(privA, crypto.SHA3_256(ackSign))
	ackMsg := proto.AckMsgFromAck(ack, sigA)
	data, err := proto.EncodeAckMsg(ackMsg)
	if err != nil {
		t.Fatalf("encode ack msg failed: %v", err)
	}
	inPath := filepath.Join(t.TempDir(), "ack-no-req.json")
	if err := os.WriteFile(inPath, data, 0600); err != nil {
		t.Fatalf("write ack msg failed: %v", err)
	}
	if err := runWithHome(homeB, "recv", "--in", inPath); err == nil || !strings.Contains(err.Error(), "missing repay request") {
		t.Fatalf("expected missing repay request, got: %v", err)
	}
}

func TestRecvRejectsAfterClosed(t *testing.T) {
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
	runOK(t, homeA, "recv", "--in", openMsgPath)

	iou := proto.IOU{Creditor: pubA, Debtor: pubB, Amount: 10, Nonce: 1}
	cid := proto.ContractID(iou)
	cidHex := hex.EncodeToString(cid[:])

	closeMsgPath := filepath.Join(t.TempDir(), "close.json")
	runOK(t, homeB, "close",
		"--id", cidHex,
		"--reqnonce", "1",
		"--out", closeMsgPath,
	)
	runOK(t, homeA, "recv", "--in", closeMsgPath)

	ackMsgPath := filepath.Join(t.TempDir(), "ack.json")
	runOK(t, homeA, "ack",
		"--id", cidHex,
		"--reqnonce", "1",
		"--decision", "1",
		"--out", ackMsgPath,
	)
	runOK(t, homeB, "recv", "--in", ackMsgPath)

	closeMsgPath2 := filepath.Join(t.TempDir(), "close2.json")
	runOK(t, homeB, "close",
		"--id", cidHex,
		"--reqnonce", "2",
		"--out", closeMsgPath2,
	)
	if err := runWithHome(homeA, "recv", "--in", closeMsgPath2); err == nil || !strings.Contains(err.Error(), "contract already closed") {
		t.Fatalf("expected closed rejection, got: %v", err)
	}
}

func TestRepayReqDuplicateRecv(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()

	runOK(t, homeA, "keygen")
	runOK(t, homeB, "keygen")

	pubA := loadPub(t, homeA)

	openMsgPath := filepath.Join(t.TempDir(), "open.json")
	runOK(t, homeB, "open",
		"--to", hex.EncodeToString(pubA),
		"--amount", "6",
		"--nonce", "1",
		"--out", openMsgPath,
	)
	runOK(t, homeA, "recv", "--in", openMsgPath)

	iou := proto.IOU{Creditor: pubA, Debtor: loadPub(t, homeB), Amount: 6, Nonce: 1}
	cid := proto.ContractID(iou)
	cidHex := hex.EncodeToString(cid[:])

	closeMsgPath := filepath.Join(t.TempDir(), "close.json")
	runOK(t, homeB, "close",
		"--id", cidHex,
		"--reqnonce", "1",
		"--out", closeMsgPath,
	)
	runOK(t, homeA, "recv", "--in", closeMsgPath)
	runOK(t, homeA, "recv", "--in", closeMsgPath)

	count := countLines(t, filepath.Join(homeA, ".web4mvp", "repayreqs.jsonl"))
	if count != 1 {
		t.Fatalf("expected 1 repay request, got %d", count)
	}
}

func TestAckDuplicateRecv(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()

	runOK(t, homeA, "keygen")
	runOK(t, homeB, "keygen")

	pubA := loadPub(t, homeA)

	openMsgPath := filepath.Join(t.TempDir(), "open.json")
	runOK(t, homeB, "open",
		"--to", hex.EncodeToString(pubA),
		"--amount", "7",
		"--nonce", "1",
		"--out", openMsgPath,
	)
	runOK(t, homeA, "recv", "--in", openMsgPath)

	iou := proto.IOU{Creditor: pubA, Debtor: loadPub(t, homeB), Amount: 7, Nonce: 1}
	cid := proto.ContractID(iou)
	cidHex := hex.EncodeToString(cid[:])

	closeMsgPath := filepath.Join(t.TempDir(), "close.json")
	runOK(t, homeB, "close",
		"--id", cidHex,
		"--reqnonce", "1",
		"--out", closeMsgPath,
	)
	runOK(t, homeA, "recv", "--in", closeMsgPath)

	ackMsgPath := filepath.Join(t.TempDir(), "ack.json")
	runOK(t, homeA, "ack",
		"--id", cidHex,
		"--reqnonce", "1",
		"--decision", "1",
		"--out", ackMsgPath,
	)
	runOK(t, homeB, "recv", "--in", ackMsgPath)
	if err := runWithHome(homeB, "recv", "--in", ackMsgPath); err == nil || !strings.Contains(err.Error(), "contract already closed") {
		t.Fatalf("expected closed rejection, got: %v", err)
	}

	count := countLines(t, filepath.Join(homeB, ".web4mvp", "acks.jsonl"))
	if count != 1 {
		t.Fatalf("expected 1 ack, got %d", count)
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
	selfPub, selfPriv := loadKeypair(t, homeA)
	ready := make(chan struct{})
	done := make(chan struct{})
	go func() {
		_ = network.ListenAndServeWithReady(addr, ready, func(data []byte) {
			recvData(data, st, selfPub, selfPriv)
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

func oversizedPayload(t *testing.T, msgType string, maxSize int) []byte {
	t.Helper()
	pad := strings.Repeat("a", maxSize)
	payload := []byte(fmt.Sprintf(`{"type":"%s","pad":"%s"}`, msgType, pad))
	if len(payload) <= maxSize {
		t.Fatalf("payload not oversized: %d <= %d", len(payload), maxSize)
	}
	return payload
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

func countLines(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	count := 0
	for sc.Scan() {
		if len(sc.Bytes()) != 0 {
			count++
		}
	}
	return count
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
