package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"web4mvp/internal/crypto"
	"web4mvp/internal/math4"
	"web4mvp/internal/network"
	"web4mvp/internal/node"
	"web4mvp/internal/peer"
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
	if err := runWithHome(homeB, "recv", "--in", closeMsgPath); err == nil || !strings.Contains(err.Error(), "invalid message") {
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

	if err := runWithHome(homeA, "recv", "--in", tamperedPath); err == nil || !strings.Contains(err.Error(), "invalid message") {
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

	if err := runWithHome(homeB, "recv", "--in", tamperedPath); err == nil || !strings.Contains(err.Error(), "invalid message") {
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
	data := oversizedPayload(t, proto.MsgTypeAck, proto.MaxAckSize)
	inPath := filepath.Join(t.TempDir(), "ack-oversize.json")
	if err := os.WriteFile(inPath, data, 0600); err != nil {
		t.Fatalf("write oversize ack failed: %v", err)
	}
	if err := runWithHome(home, "recv", "--in", inPath); err == nil || !strings.Contains(err.Error(), "invalid message") {
		t.Fatalf("expected size rejection, got: %v", err)
	}
}

func TestRecvRejectsOversizeRepayReq(t *testing.T) {
	home := t.TempDir()
	runOK(t, home, "keygen")
	data := oversizedPayload(t, proto.MsgTypeRepayReq, proto.MaxRepayReqSize)
	inPath := filepath.Join(t.TempDir(), "repay-oversize.json")
	if err := os.WriteFile(inPath, data, 0600); err != nil {
		t.Fatalf("write oversize repay req failed: %v", err)
	}
	if err := runWithHome(home, "recv", "--in", inPath); err == nil || !strings.Contains(err.Error(), "invalid message") {
		t.Fatalf("expected size rejection, got: %v", err)
	}
}

func TestRecvRejectsBurstUpdates(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()

	runOK(t, homeA, "keygen")
	runOK(t, homeB, "keygen")

	pubA := loadPub(t, homeA)

	openMsgPath1 := filepath.Join(t.TempDir(), "open1.json")
	runOK(t, homeB, "open",
		"--to", hex.EncodeToString(pubA),
		"--amount", "4",
		"--nonce", "1",
		"--out", openMsgPath1,
	)
	openMsgPath2 := filepath.Join(t.TempDir(), "open2.json")
	runOK(t, homeB, "open",
		"--to", hex.EncodeToString(pubA),
		"--amount", "4",
		"--nonce", "2",
		"--out", openMsgPath2,
	)
	data1, err := os.ReadFile(openMsgPath1)
	if err != nil {
		t.Fatalf("read open1 failed: %v", err)
	}
	data2, err := os.ReadFile(openMsgPath2)
	if err != nil {
		t.Fatalf("read open2 failed: %v", err)
	}

	root := filepath.Join(homeA, ".web4mvp")
	st := store.New(
		filepath.Join(root, "contracts.jsonl"),
		filepath.Join(root, "acks.jsonl"),
		filepath.Join(root, "repayreqs.jsonl"),
	)
	self, err := node.NewNode(root, node.Options{})
	if err != nil {
		t.Fatalf("load node failed: %v", err)
	}
	checker := math4.NewLocalChecker(math4.Options{
		MaxAbsV:          5,
		MaxAbsS:          6,
		AlphaNumerator:   1,
		AlphaDenominator: 1,
		ColdStartUpdates: -1,
	})

	if err := recvData(data1, st, self, checker); err != nil {
		t.Fatalf("expected first recv ok, got %v", err)
	}
	if err := recvData(data2, st, self, checker); err == nil || !strings.Contains(err.Error(), "smoothness") {
		t.Fatalf("expected smoothness rejection, got %v", err)
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
	if err := runWithHome(homeA, "recv", "--in", inPath); err == nil || !strings.Contains(err.Error(), "invalid message") {
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
	if err := runWithHome(homeB, "recv", "--in", inPath); err == nil || !strings.Contains(err.Error(), "invalid message") {
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
	if err := runWithHome(homeA, "recv", "--in", closeMsgPath2); err == nil || !strings.Contains(err.Error(), "invalid message") {
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
	if err := runWithHome(homeB, "recv", "--in", ackMsgPath); err == nil || !strings.Contains(err.Error(), "invalid message") {
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
	self, err := node.NewNode(root, node.Options{})
	if err != nil {
		t.Fatalf("load node failed: %v", err)
	}
	peerB := peer.Peer{
		NodeID: node.DeriveNodeID(pubB),
		PubKey: pubB,
		Addr:   "127.0.0.1:1",
	}
	if err := self.Peers.Upsert(peerB, true); err != nil {
		t.Fatalf("seed peer failed: %v", err)
	}
	checker := math4.NewLocalChecker(math4.Options{})
	ready := make(chan struct{})
	done := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		_ = network.ListenAndServeWithResponderFrom(addr, ready, false, func(senderAddr string, data []byte) ([]byte, error) {
			if _, _, err := recvDataWithResponse(data, st, self, checker, senderAddr); err != nil {
				select {
				case errCh <- err:
				default:
				}
				return nil, err
			}
			select {
			case <-done:
			default:
				close(done)
			}
			return nil, nil
		})
	}()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for quic server ready")
	}

	_, privB := loadKeypair(t, homeB)
	if err := sendNodeHello(t, addr, pubB, privB, "", false); err != nil {
		t.Fatalf("node hello failed: %v", err)
	}

	msgData, err := os.ReadFile(openMsgPath)
	if err != nil {
		t.Fatalf("read open msg failed: %v", err)
	}
	if err := network.Send(addr, msgData, true, false, ""); err != nil {
		t.Fatalf("quic send failed: %v", err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for quic receive")
	}
	select {
	case err := <-errCh:
		t.Fatalf("recv failed: %v", err)
	default:
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

func sendNodeHello(t *testing.T, addr string, pub, priv []byte, caPath string, devTLS bool) error {
	t.Helper()
	n := &node.Node{
		ID:      node.DeriveNodeID(pub),
		PubKey:  pub,
		PrivKey: priv,
	}
	msg, err := n.Hello(1, "")
	if err != nil {
		return err
	}
	data, err := proto.EncodeNodeHelloMsg(msg)
	if err != nil {
		return err
	}
	return network.Send(addr, data, !devTLS, devTLS, caPath)
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

func loadPriv(t *testing.T, home string) []byte {
	t.Helper()
	_, priv := loadKeypair(t, home)
	return priv
}

func TestQuicNodeHello(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()
	t.Setenv("HOME", homeB)

	runOK(t, homeA, "keygen")
	runOK(t, homeB, "keygen")

	addr := freeUDPAddr(t)
	root := filepath.Join(homeB, ".web4mvp")
	_ = os.MkdirAll(root, 0700)
	st := store.New(
		filepath.Join(root, "contracts.jsonl"),
		filepath.Join(root, "acks.jsonl"),
		filepath.Join(root, "repayreqs.jsonl"),
	)
	self, err := node.NewNode(root, node.Options{})
	if err != nil {
		t.Fatalf("load node failed: %v", err)
	}
	checker := math4.NewLocalChecker(math4.Options{})
	ready := make(chan struct{})
	done := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		_ = network.ListenAndServeWithResponderFrom(addr, ready, true, func(senderAddr string, data []byte) ([]byte, error) {
			if _, _, err := recvDataWithResponse(data, st, self, checker, senderAddr); err != nil {
				select {
				case errCh <- err:
				default:
				}
				return nil, err
			}
			select {
			case <-done:
			default:
				close(done)
			}
			return nil, nil
		})
	}()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for quic server ready")
	}

	devTLSCAPath := filepath.Join(homeB, ".web4mvp", "devtls_ca.pem")
	if err := runWithHome(homeA, "node", "hello", "--devtls", "--addr", addr, "--devtls-ca", devTLSCAPath); err != nil {
		t.Fatalf("node hello failed: %v", err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("recv error: %v", err)
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for node hello")
	}

	senderPub := loadPub(t, homeA)
	senderID := node.DeriveNodeID(senderPub)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if hasPeerID(self.Peers.List(), senderID) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected sender in peer store")
}

func TestNodeExchange(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()
	homeC := t.TempDir()

	runOK(t, homeA, "keygen")
	runOK(t, homeB, "keygen")
	runOK(t, homeC, "keygen")

	addr := freeUDPAddr(t)
	t.Setenv("HOME", homeA)
	root := filepath.Join(homeA, ".web4mvp")
	_ = os.MkdirAll(root, 0700)
	st := store.New(
		filepath.Join(root, "contracts.jsonl"),
		filepath.Join(root, "acks.jsonl"),
		filepath.Join(root, "repayreqs.jsonl"),
	)
	self, err := node.NewNode(root, node.Options{})
	if err != nil {
		t.Fatalf("load node failed: %v", err)
	}

	pubC := loadPub(t, homeC)
	peerC := peer.Peer{
		NodeID: node.DeriveNodeID(pubC),
		PubKey: pubC,
		Addr:   "127.0.0.1:42430",
	}
	if err := self.Peers.Upsert(peerC, true); err != nil {
		t.Fatalf("seed peer failed: %v", err)
	}

	checker := math4.NewLocalChecker(math4.Options{})
	ready := make(chan struct{})
	go func() {
		_ = network.ListenAndServeWithResponderFrom(addr, ready, true, func(senderAddr string, data []byte) ([]byte, error) {
			resp, _, err := recvDataWithResponse(data, st, self, checker, senderAddr)
			if err != nil {
				return nil, err
			}
			return resp, nil
		})
	}()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for quic server ready")
	}

	devTLSCAPath := filepath.Join(homeA, ".web4mvp", "devtls_ca.pem")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(devTLSCAPath); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(devTLSCAPath); err != nil {
		t.Fatalf("missing devtls CA: %v", err)
	}
	pubB, privB := loadKeypair(t, homeB)
	if err := sendNodeHello(t, addr, pubB, privB, devTLSCAPath, true); err != nil {
		t.Fatalf("node hello failed: %v", err)
	}
	rootB := filepath.Join(homeB, ".web4mvp")
	stB := store.New(
		filepath.Join(rootB, "contracts.jsonl"),
		filepath.Join(rootB, "acks.jsonl"),
		filepath.Join(rootB, "repayreqs.jsonl"),
	)
	selfB, err := node.NewNode(rootB, node.Options{})
	if err != nil {
		t.Fatalf("load node failed: %v", err)
	}
	msg, err := self.Hello(1, "")
	if err != nil {
		t.Fatalf("node hello failed: %v", err)
	}
	msgData, err := proto.EncodeNodeHelloMsg(msg)
	if err != nil {
		t.Fatalf("encode node hello failed: %v", err)
	}
	if _, _, err := recvDataWithResponse(msgData, stB, selfB, checker, addr); err != nil {
		t.Fatalf("accept node hello failed: %v", err)
	}
	reloadBeforeExchange, err := node.NewNode(rootB, node.Options{})
	if err != nil {
		t.Fatalf("reload node failed: %v", err)
	}
	if !hasPeerID(reloadBeforeExchange.Peers.List(), self.ID) {
		t.Fatalf("expected sender identity before exchange")
	}
	if err := runWithHome(homeB, "node", "exchange", "--devtls", "--addr", addr, "--devtls-ca", devTLSCAPath, "--k", "16"); err != nil {
		t.Fatalf("node exchange failed: %v", err)
	}

	reloadB, err := node.NewNode(rootB, node.Options{})
	if err != nil {
		t.Fatalf("reload node failed: %v", err)
	}
	pC, ok := findPeerByNodeID(reloadB.Peers.List(), peerC.NodeID)
	if !ok {
		t.Fatalf("expected identity from exchange")
	}
	if len(pC.PubKey) == 0 || !bytes.Equal(pC.PubKey, pubC) {
		t.Fatalf("expected matching pubkey from exchange")
	}
	if reloadB.Members.Has(peerC.NodeID) {
		t.Fatalf("did not expect member from exchange")
	}
}

func TestGossipForwarding(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()
	homeC := t.TempDir()

	runOK(t, homeA, "keygen")
	runOK(t, homeB, "keygen")
	runOK(t, homeC, "keygen")

	t.Setenv("WEB4_GOSSIP_FANOUT", "1")
	t.Setenv("WEB4_GOSSIP_TTL_HOPS", "3")

	addrB := freeUDPAddr(t)
	addrC := freeUDPAddr(t)

	rootB := filepath.Join(homeB, ".web4mvp")
	_ = os.MkdirAll(rootB, 0700)
	stB := store.New(
		filepath.Join(rootB, "contracts.jsonl"),
		filepath.Join(rootB, "acks.jsonl"),
		filepath.Join(rootB, "repayreqs.jsonl"),
	)
	selfB, err := node.NewNode(rootB, node.Options{})
	if err != nil {
		t.Fatalf("load node failed: %v", err)
	}
	pubC := loadPub(t, homeC)
	peerC := peer.Peer{
		NodeID: node.DeriveNodeID(pubC),
		PubKey: pubC,
		Addr:   addrC,
	}

	rootC := filepath.Join(homeC, ".web4mvp")
	_ = os.MkdirAll(rootC, 0700)
	stC := store.New(
		filepath.Join(rootC, "contracts.jsonl"),
		filepath.Join(rootC, "acks.jsonl"),
		filepath.Join(rootC, "repayreqs.jsonl"),
	)
	selfC, err := node.NewNode(rootC, node.Options{})
	if err != nil {
		t.Fatalf("load node failed: %v", err)
	}

	checker := math4.NewLocalChecker(math4.Options{})
	readyB := make(chan struct{})
	readyC := make(chan struct{})

	t.Setenv("HOME", homeC)
	go func() {
		_ = network.ListenAndServeWithResponderFrom(addrC, readyC, true, func(senderAddr string, data []byte) ([]byte, error) {
			resp, _, err := recvDataWithResponse(data, stC, selfC, checker, senderAddr)
			if err != nil {
				return nil, err
			}
			return resp, nil
		})
	}()
	select {
	case <-readyC:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for quic server ready")
	}
	devTLSCAPathC := filepath.Join(homeC, ".web4mvp", "devtls_ca.pem")
	waitForFile := func(path string) error {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(path); err == nil {
				return nil
			}
			time.Sleep(20 * time.Millisecond)
		}
		return fmt.Errorf("missing devtls CA: %s", path)
	}
	if err := waitForFile(devTLSCAPathC); err != nil {
		t.Fatalf("%v", err)
	}

	t.Setenv("HOME", homeB)
	go func() {
		_ = network.ListenAndServeWithResponderFrom(addrB, readyB, true, func(senderAddr string, data []byte) ([]byte, error) {
			resp, _, err := recvDataWithResponse(data, stB, selfB, checker, senderAddr)
			if err != nil {
				return nil, err
			}
			return resp, nil
		})
	}()
	select {
	case <-readyB:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for quic server ready")
	}
	devTLSCAPath := filepath.Join(homeB, ".web4mvp", "devtls_ca.pem")
	if err := waitForFile(devTLSCAPath); err != nil {
		t.Fatalf("%v", err)
	}

	pubA, privA := loadKeypair(t, homeA)
	if err := sendNodeHello(t, addrB, pubA, privA, devTLSCAPath, true); err != nil {
		t.Fatalf("node hello failed: %v", err)
	}
	peerAID := node.DeriveNodeID(pubA)
	waitForPeer := func(id [32]byte, requireAddr bool, requirePub bool, list func() []peer.Peer) bool {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			p, ok := findPeerByNodeID(list(), id)
			if ok {
				if requireAddr && p.Addr == "" {
					time.Sleep(20 * time.Millisecond)
					continue
				}
				if requirePub && len(p.PubKey) == 0 {
					time.Sleep(20 * time.Millisecond)
					continue
				}
				return true
			}
			time.Sleep(20 * time.Millisecond)
		}
		return false
	}

	peerDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(peerDeadline) {
		if hasPeerID(selfB.Peers.List(), peerAID) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !hasPeerID(selfB.Peers.List(), peerAID) {
		t.Fatalf("expected identity from node hello")
	}
	pubB := loadPub(t, homeB)
	peerBID := node.DeriveNodeID(pubB)
	if err := sendNodeHello(t, addrC, selfB.PubKey, selfB.PrivKey, devTLSCAPathC, true); err != nil {
		t.Fatalf("node hello failed: %v", err)
	}
	if !waitForPeer(peerBID, true, true, selfC.Peers.List) {
		t.Fatalf("expected identity from node hello")
	}
	selfB.Candidates.Add(addrC)
	if err := sendNodeHello(t, addrB, selfC.PubKey, selfC.PrivKey, devTLSCAPath, true); err != nil {
		t.Fatalf("node hello failed: %v", err)
	}
	if !waitForPeer(peerC.NodeID, true, true, selfB.Peers.List) {
		t.Fatalf("expected identity from node hello")
	}
	pubD, privD, err := crypto.GenKeypair()
	if err != nil {
		t.Fatalf("gen keypair failed: %v", err)
	}
	selfA, err := node.NewNode(filepath.Join(homeA, ".web4mvp"), node.Options{})
	if err != nil {
		t.Fatalf("load node failed: %v", err)
	}
	hello := node.Node{
		ID:      node.DeriveNodeID(pubD),
		PubKey:  pubD,
		PrivKey: privD,
	}
	msg, err := hello.Hello(1, "")
	if err != nil {
		t.Fatalf("node hello failed: %v", err)
	}
	envelope, err := proto.EncodeNodeHelloMsg(msg)
	if err != nil {
		t.Fatalf("encode node hello failed: %v", err)
	}
	gossipData, err := buildGossipPushForPeer(peer.Peer{PubKey: pubB}, envelope, 3, selfA)
	if err != nil {
		t.Fatalf("encode gossip push failed: %v", err)
	}
	if err := network.Send(addrB, gossipData, false, true, ""); err != nil {
		t.Fatalf("gossip push send failed: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if hasPeerID(selfC.Peers.List(), hello.ID) {
		t.Fatalf("expected rejection before membership")
	}
	peerCHex := hex.EncodeToString(peerC.NodeID[:])
	if err := runWithHome(homeB, "node", "join", "--node-id", peerCHex); err != nil {
		t.Fatalf("add member failed: %v", err)
	}
	if err := selfB.Members.Add(peerC.NodeID, false); err != nil {
		t.Fatalf("add member failed: %v", err)
	}
	if err := selfB.Members.Add(selfB.ID, false); err != nil {
		t.Fatalf("add member failed: %v", err)
	}
	if !selfB.Members.Has(selfB.ID) {
		t.Fatalf("expected self member for forward")
	}
	if err := selfC.Members.Add(peerBID, false); err != nil {
		t.Fatalf("add member failed: %v", err)
	}
	if err := selfC.Members.Add(selfC.ID, false); err != nil {
		t.Fatalf("add member failed: %v", err)
	}
	if !selfC.Members.Has(selfC.ID) {
		t.Fatalf("expected self member for receive")
	}
	if !waitForPeer(peerC.NodeID, true, true, selfB.Peers.List) {
		t.Fatalf("expected forward target ready")
	}
	if err := network.Send(addrB, gossipData, false, true, ""); err != nil {
		t.Fatalf("gossip push send failed: %v", err)
	}
	if !waitForPeer(hello.ID, false, true, selfC.Peers.List) {
		t.Fatalf("timeout waiting for gossip forward")
	}
	if !hasPeerID(selfC.Peers.List(), hello.ID) {
		t.Fatalf("expected identity from gossip")
	}
}

func TestGossipRejectsUnknownSender(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()

	runOK(t, homeA, "keygen")
	runOK(t, homeB, "keygen")

	t.Setenv("WEB4_GOSSIP_FANOUT", "1")
	t.Setenv("WEB4_GOSSIP_TTL_HOPS", "2")
	t.Setenv("HOME", homeB)

	addrB := freeUDPAddr(t)
	rootB := filepath.Join(homeB, ".web4mvp")
	_ = os.MkdirAll(rootB, 0700)
	stB := store.New(
		filepath.Join(rootB, "contracts.jsonl"),
		filepath.Join(rootB, "acks.jsonl"),
		filepath.Join(rootB, "repayreqs.jsonl"),
	)
	selfB, err := node.NewNode(rootB, node.Options{})
	if err != nil {
		t.Fatalf("load node failed: %v", err)
	}
	checker := math4.NewLocalChecker(math4.Options{})
	ready := make(chan struct{})
	go func() {
		_ = network.ListenAndServeWithResponderFrom(addrB, ready, true, func(senderAddr string, data []byte) ([]byte, error) {
			resp, _, err := recvDataWithResponse(data, stB, selfB, checker, senderAddr)
			if err != nil {
				return nil, err
			}
			return resp, nil
		})
	}()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for quic server ready")
	}

	devTLSCAPath := filepath.Join(homeB, ".web4mvp", "devtls_ca.pem")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(devTLSCAPath); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(devTLSCAPath); err != nil {
		t.Fatalf("missing devtls CA: %v", err)
	}
	pubB := loadPub(t, homeB)
	openMsg := filepath.Join(t.TempDir(), "open.json")
	runOK(t, homeA, "open", "--to", hex.EncodeToString(pubB), "--amount", "4", "--nonce", "2", "--out", openMsg)
	envelope, err := os.ReadFile(openMsg)
	if err != nil {
		t.Fatalf("read open message failed: %v", err)
	}
	selfA, err := node.NewNode(filepath.Join(homeA, ".web4mvp"), node.Options{})
	if err != nil {
		t.Fatalf("load node failed: %v", err)
	}
	gossipData, err := buildGossipPushForPeer(peer.Peer{PubKey: pubB}, envelope, 2, selfA)
	if err != nil {
		t.Fatalf("encode gossip push failed: %v", err)
	}
	if err := network.Send(addrB, gossipData, false, true, devTLSCAPath); err != nil {
		t.Fatalf("gossip push send failed: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	cs, err := stB.ListContracts()
	if err != nil {
		t.Fatalf("list contracts failed: %v", err)
	}
	if len(cs) != 0 {
		t.Fatalf("expected gossip drop for unknown sender")
	}
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
		if isPermissionErr(err) {
			t.Skipf("udp listen not permitted: %v", err)
		}
		t.Fatalf("listen udp failed: %v", err)
	}
	defer pc.Close()
	return pc.LocalAddr().String()
}

func isPermissionErr(err error) bool {
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return true
	}
	return strings.Contains(err.Error(), "operation not permitted")
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
