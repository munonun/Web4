package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
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
	pair := newSessionPair(t, homeA, homeB, nil, nil)
	openMsg, err := os.ReadFile(openMsgPath)
	if err != nil {
		t.Fatalf("read open msg failed: %v", err)
	}
	if err := pair.recvToA(openMsg); err != nil {
		t.Fatalf("recv open failed: %v", err)
	}

	iou := proto.IOU{Creditor: pubA, Debtor: pubB, Amount: 500, Nonce: 1}
	cid := proto.ContractID(iou)
	cidHex := hex.EncodeToString(cid[:])

	closeMsgPath := filepath.Join(t.TempDir(), "close.json")
	runOK(t, homeB, "close",
		"--id", cidHex,
		"--reqnonce", "1",
		"--out", closeMsgPath,
	)
	closeMsg, err := os.ReadFile(closeMsgPath)
	if err != nil {
		t.Fatalf("read close msg failed: %v", err)
	}
	if err := pair.recvToA(closeMsg); err != nil {
		t.Fatalf("recv close failed: %v", err)
	}
	msgType, err := decodeMsgType(closeMsg)
	if err != nil {
		t.Fatalf("decode close type failed: %v", err)
	}
	secureClose, err := sealSecureEnvelope(pair.b, pair.a.ID, msgType, "", closeMsg)
	if err != nil {
		t.Fatalf("seal close failed: %v", err)
	}
	if err := recvData(secureClose, pair.stB, pair.b, pair.checkerB); err == nil {
		t.Fatalf("expected recipient decrypt failure")
	}

	ackMsgPath := filepath.Join(t.TempDir(), "ack.json")
	runOK(t, homeA, "ack",
		"--id", cidHex,
		"--reqnonce", "1",
		"--decision", "1",
		"--out", ackMsgPath,
	)
	ackMsg, err := os.ReadFile(ackMsgPath)
	if err != nil {
		t.Fatalf("read ack msg failed: %v", err)
	}
	if err := pair.recvToB(ackMsg); err != nil {
		t.Fatalf("recv ack failed: %v", err)
	}

	if err := runWithHome(homeA, "close", "--id", cidHex, "--reqnonce", "2"); err == nil || !strings.Contains(err.Error(), "debtor mismatch") {
		t.Fatalf("expected debtor mismatch error, got: %v", err)
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

	pubA := loadPub(t, homeA)
	pubB := loadPub(t, homeB)

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
	want, err := proto.EncodeOpenPayload(hex.EncodeToString(pubA), hex.EncodeToString(pubB), 42, 7)
	if err != nil {
		t.Fatalf("encode payload failed: %v", err)
	}
	if len(ephPub) != 0 {
		t.Fatalf("expected empty eph pub")
	}
	if !bytes.Equal(sealed, want) {
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
	pair := newSessionPair(t, homeA, homeB, nil, nil)
	openMsg, err := os.ReadFile(openMsgPath)
	if err != nil {
		t.Fatalf("read open msg failed: %v", err)
	}
	if err := pair.recvToA(openMsg); err != nil {
		t.Fatalf("recv open failed: %v", err)
	}

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

	if err := recvSecureToReceiver(pair.b, pair.a, pair.stA, pair.checkerA, tampered); err == nil {
		t.Fatalf("expected invalid sigb error")
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
	pair := newSessionPair(t, homeA, homeB, nil, nil)
	openMsg, err := os.ReadFile(openMsgPath)
	if err != nil {
		t.Fatalf("read open msg failed: %v", err)
	}
	if err := pair.recvToA(openMsg); err != nil {
		t.Fatalf("recv open failed: %v", err)
	}

	iou := proto.IOU{Creditor: pubA, Debtor: pubB, Amount: 3, Nonce: 1}
	cid := proto.ContractID(iou)
	cidHex := hex.EncodeToString(cid[:])

	closeMsgPath := filepath.Join(t.TempDir(), "close.json")
	runOK(t, homeB, "close",
		"--id", cidHex,
		"--reqnonce", "1",
		"--out", closeMsgPath,
	)
	closeMsg, err := os.ReadFile(closeMsgPath)
	if err != nil {
		t.Fatalf("read close msg failed: %v", err)
	}
	if err := pair.recvToA(closeMsg); err != nil {
		t.Fatalf("recv close failed: %v", err)
	}

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

	if err := recvSecureToReceiver(pair.a, pair.b, pair.stB, pair.checkerB, tampered); err == nil {
		t.Fatalf("expected invalid siga error")
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

	if len(ephPub1) != 0 || len(ephPub2) != 0 {
		t.Fatalf("expected empty ephemeral public keys")
	}
	if !bytes.Equal(sealed1, sealed2) {
		t.Fatalf("expected deterministic sealed payloads")
	}
	if !bytes.Equal(sealed1, payload) {
		t.Fatalf("expected plaintext payload")
	}
}

func TestRecvRejectsOversizeAck(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()
	runOK(t, homeA, "keygen")
	runOK(t, homeB, "keygen")
	pair := newSessionPair(t, homeA, homeB, nil, nil)
	data := oversizedPayload(t, proto.MsgTypeAck, proto.MaxAckSize)
	if err := pair.recvToA(data); err == nil {
		t.Fatalf("expected size rejection")
	}
}

func TestRecvRejectsOversizeRepayReq(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()
	runOK(t, homeA, "keygen")
	runOK(t, homeB, "keygen")
	pair := newSessionPair(t, homeA, homeB, nil, nil)
	data := oversizedPayload(t, proto.MsgTypeRepayReq, proto.MaxRepayReqSize)
	if err := pair.recvToA(data); err == nil {
		t.Fatalf("expected size rejection")
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

	checker := math4.NewLocalChecker(math4.Options{
		MaxAbsV:          5,
		MaxAbsS:          6,
		AlphaNumerator:   1,
		AlphaDenominator: 1,
		ColdStartUpdates: -1,
	})
	pair := newSessionPair(t, homeA, homeB, checker, nil)
	if err := pair.recvToA(data1); err != nil {
		t.Fatalf("expected first recv ok, got %v", err)
	}
	if err := pair.recvToA(data2); err == nil || !strings.Contains(err.Error(), "smoothness") {
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
	pair := newSessionPair(t, homeA, homeB, nil, nil)
	if err := pair.recvToA(data); err == nil {
		t.Fatalf("expected payload mismatch")
	}
}

func TestZKModeRejectsMissingProofOpen(t *testing.T) {
	t.Setenv("WEB4_ZK_MODE", "1")
	homeA := t.TempDir()
	homeB := t.TempDir()

	runOK(t, homeA, "keygen")
	runOK(t, homeB, "keygen")

	pubA, _ := loadKeypair(t, homeA)
	pubB, privB := loadKeypair(t, homeB)

	iou := proto.IOU{Creditor: pubA, Debtor: pubB, Amount: 5, Nonce: 1}
	cid := proto.ContractID(iou)
	payload, err := proto.EncodeOpenPayload(hex.EncodeToString(pubA), hex.EncodeToString(pubB), 5, 1)
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
	pair := newSessionPair(t, homeA, homeB, nil, nil)
	if err := pair.recvToA(data); err == nil {
		t.Fatalf("expected zk rejection")
	}
}

func TestZKModeAcceptsProofOpen(t *testing.T) {
	t.Setenv("WEB4_ZK_MODE", "1")
	homeA := t.TempDir()
	homeB := t.TempDir()

	runOK(t, homeA, "keygen")
	runOK(t, homeB, "keygen")

	pubA, _ := loadKeypair(t, homeA)
	pubB, privB := loadKeypair(t, homeB)

	iou := proto.IOU{Creditor: pubA, Debtor: pubB, Amount: 5, Nonce: 1}
	cid := proto.ContractID(iou)
	openPayload := proto.OpenPayload{
		Type:     proto.MsgTypeContractOpen,
		Creditor: hex.EncodeToString(pubA),
		Debtor:   hex.EncodeToString(pubB),
		Amount:   5,
		Nonce:    1,
	}
	ctx, err := openPayloadContext(openPayload)
	if err != nil {
		t.Fatalf("payload ctx failed: %v", err)
	}
	zk, err := buildDeltaProof(5, ctx)
	if err != nil {
		t.Fatalf("build zk failed: %v", err)
	}
	openPayload.ZK = zk
	payload, err := json.Marshal(openPayload)
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
	pair := newSessionPair(t, homeA, homeB, nil, nil)
	if err := pair.recvToA(data); err != nil {
		t.Fatalf("expected zk accept, got %v", err)
	}
}

func TestDeltaBRejectsSumMismatch(t *testing.T) {
	t.Setenv("WEB4_DELTA_MODE", "deltab")
	homeA := t.TempDir()
	homeB := t.TempDir()

	runOK(t, homeA, "keygen")
	runOK(t, homeB, "keygen")

	pair := newSessionPair(t, homeA, homeB, nil, nil)
	members := pair.a.Members.List()
	if len(members) < 2 {
		t.Fatalf("need at least 2 members")
	}
	view := membersViewID(members)
	msg := proto.DeltaBMsg{
		ProtoVersion: proto.ProtoVersion,
		Suite:        proto.Suite,
		ViewID:       hex.EncodeToString(view[:]),
		Entries: []proto.DeltaBEntry{
			{NodeID: hex.EncodeToString(members[0][:]), Delta: 5},
			{NodeID: hex.EncodeToString(members[1][:]), Delta: -3},
		},
	}
	data, err := proto.EncodeDeltaBMsg(msg)
	if err != nil {
		t.Fatalf("encode delta_b failed: %v", err)
	}
	if err := pair.recvToA(data); err == nil {
		t.Fatalf("expected sum mismatch rejection")
	}
}

func TestDeltaBZKMissingRejected(t *testing.T) {
	t.Setenv("WEB4_DELTA_MODE", "deltab")
	t.Setenv("WEB4_ZK_MODE", "1")
	homeA := t.TempDir()
	homeB := t.TempDir()

	runOK(t, homeA, "keygen")
	runOK(t, homeB, "keygen")

	pair := newSessionPair(t, homeA, homeB, nil, nil)
	members := pair.a.Members.List()
	if len(members) < 2 {
		t.Fatalf("need at least 2 members")
	}
	view := membersViewID(members)
	msg := proto.DeltaBMsg{
		ProtoVersion: proto.ProtoVersion,
		Suite:        proto.Suite,
		ViewID:       hex.EncodeToString(view[:]),
		Entries: []proto.DeltaBEntry{
			{NodeID: hex.EncodeToString(members[0][:]), Delta: 5},
			{NodeID: hex.EncodeToString(members[1][:]), Delta: -5},
		},
	}
	data, err := proto.EncodeDeltaBMsg(msg)
	if err != nil {
		t.Fatalf("encode delta_b failed: %v", err)
	}
	if err := pair.recvToA(data); err == nil {
		t.Fatalf("expected missing zk rejection")
	}
}

func TestDeltaBZKAcceptsAndTamperFails(t *testing.T) {
	t.Setenv("WEB4_DELTA_MODE", "deltab")
	t.Setenv("WEB4_ZK_MODE", "1")
	homeA := t.TempDir()
	homeB := t.TempDir()

	runOK(t, homeA, "keygen")
	runOK(t, homeB, "keygen")

	pair := newSessionPair(t, homeA, homeB, nil, nil)
	members := pair.a.Members.List()
	if len(members) < 2 {
		t.Fatalf("need at least 2 members")
	}
	view := membersViewID(members)
	msg := proto.DeltaBMsg{
		ProtoVersion: proto.ProtoVersion,
		Suite:        proto.Suite,
		ViewID:       hex.EncodeToString(view[:]),
		Entries: []proto.DeltaBEntry{
			{NodeID: hex.EncodeToString(members[0][:]), Delta: 5},
			{NodeID: hex.EncodeToString(members[1][:]), Delta: -5},
		},
	}
	zk, err := buildDeltaBProof(msg, view)
	if err != nil {
		t.Fatalf("build zk failed: %v", err)
	}
	msg.ZK = zk
	data, err := proto.EncodeDeltaBMsg(msg)
	if err != nil {
		t.Fatalf("encode delta_b failed: %v", err)
	}
	if err := pair.recvToA(data); err != nil {
		t.Fatalf("expected delta_b accept, got %v", err)
	}

	msg.Entries[0].Delta = 6
	msg.Entries[1].Delta = -6
	data, err = proto.EncodeDeltaBMsg(msg)
	if err != nil {
		t.Fatalf("encode delta_b failed: %v", err)
	}
	if err := pair.recvToA(data); err == nil {
		t.Fatalf("expected zk tamper rejection")
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
	pair := newSessionPair(t, homeA, homeB, nil, nil)
	openMsg, err := os.ReadFile(openMsgPath)
	if err != nil {
		t.Fatalf("read open msg failed: %v", err)
	}
	if err := pair.recvToA(openMsg); err != nil {
		t.Fatalf("recv open failed: %v", err)
	}

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
	if err := pair.recvToB(data); err == nil {
		t.Fatalf("expected missing repay request")
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
	pair := newSessionPair(t, homeA, homeB, nil, nil)
	openMsg, err := os.ReadFile(openMsgPath)
	if err != nil {
		t.Fatalf("read open msg failed: %v", err)
	}
	if err := pair.recvToA(openMsg); err != nil {
		t.Fatalf("recv open failed: %v", err)
	}

	iou := proto.IOU{Creditor: pubA, Debtor: pubB, Amount: 10, Nonce: 1}
	cid := proto.ContractID(iou)
	cidHex := hex.EncodeToString(cid[:])

	closeMsgPath := filepath.Join(t.TempDir(), "close.json")
	runOK(t, homeB, "close",
		"--id", cidHex,
		"--reqnonce", "1",
		"--out", closeMsgPath,
	)
	closeMsg, err := os.ReadFile(closeMsgPath)
	if err != nil {
		t.Fatalf("read close msg failed: %v", err)
	}
	if err := pair.recvToA(closeMsg); err != nil {
		t.Fatalf("recv close failed: %v", err)
	}

	ackMsgPath := filepath.Join(t.TempDir(), "ack.json")
	runOK(t, homeA, "ack",
		"--id", cidHex,
		"--reqnonce", "1",
		"--decision", "1",
		"--out", ackMsgPath,
	)
	ackMsg, err := os.ReadFile(ackMsgPath)
	if err != nil {
		t.Fatalf("read ack msg failed: %v", err)
	}
	if err := pair.recvToB(ackMsg); err != nil {
		t.Fatalf("recv ack failed: %v", err)
	}

	closeMsgPath2 := filepath.Join(t.TempDir(), "close2.json")
	runOK(t, homeB, "close",
		"--id", cidHex,
		"--reqnonce", "2",
		"--out", closeMsgPath2,
	)
	closeMsg2, err := os.ReadFile(closeMsgPath2)
	if err != nil {
		t.Fatalf("read close2 msg failed: %v", err)
	}
	if err := pair.recvToA(closeMsg2); err == nil {
		t.Fatalf("expected closed rejection")
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
	pair := newSessionPair(t, homeA, homeB, nil, nil)
	openMsg, err := os.ReadFile(openMsgPath)
	if err != nil {
		t.Fatalf("read open msg failed: %v", err)
	}
	if err := pair.recvToA(openMsg); err != nil {
		t.Fatalf("recv open failed: %v", err)
	}

	iou := proto.IOU{Creditor: pubA, Debtor: loadPub(t, homeB), Amount: 6, Nonce: 1}
	cid := proto.ContractID(iou)
	cidHex := hex.EncodeToString(cid[:])

	closeMsgPath := filepath.Join(t.TempDir(), "close.json")
	runOK(t, homeB, "close",
		"--id", cidHex,
		"--reqnonce", "1",
		"--out", closeMsgPath,
	)
	closeMsg, err := os.ReadFile(closeMsgPath)
	if err != nil {
		t.Fatalf("read close msg failed: %v", err)
	}
	if err := pair.recvToA(closeMsg); err != nil {
		t.Fatalf("recv close failed: %v", err)
	}
	if err := pair.recvToA(closeMsg); err != nil {
		t.Fatalf("recv close failed: %v", err)
	}

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
	pair := newSessionPair(t, homeA, homeB, nil, nil)
	openMsg, err := os.ReadFile(openMsgPath)
	if err != nil {
		t.Fatalf("read open msg failed: %v", err)
	}
	if err := pair.recvToA(openMsg); err != nil {
		t.Fatalf("recv open failed: %v", err)
	}

	iou := proto.IOU{Creditor: pubA, Debtor: loadPub(t, homeB), Amount: 7, Nonce: 1}
	cid := proto.ContractID(iou)
	cidHex := hex.EncodeToString(cid[:])

	closeMsgPath := filepath.Join(t.TempDir(), "close.json")
	runOK(t, homeB, "close",
		"--id", cidHex,
		"--reqnonce", "1",
		"--out", closeMsgPath,
	)
	closeMsg, err := os.ReadFile(closeMsgPath)
	if err != nil {
		t.Fatalf("read close msg failed: %v", err)
	}
	if err := pair.recvToA(closeMsg); err != nil {
		t.Fatalf("recv close failed: %v", err)
	}

	ackMsgPath := filepath.Join(t.TempDir(), "ack.json")
	runOK(t, homeA, "ack",
		"--id", cidHex,
		"--reqnonce", "1",
		"--decision", "1",
		"--out", ackMsgPath,
	)
	ackMsg, err := os.ReadFile(ackMsgPath)
	if err != nil {
		t.Fatalf("read ack msg failed: %v", err)
	}
	if err := pair.recvToB(ackMsg); err != nil {
		t.Fatalf("recv ack failed: %v", err)
	}
	if err := pair.recvToB(ackMsg); err == nil {
		t.Fatalf("expected closed rejection")
	}

	count := countLines(t, filepath.Join(homeB, ".web4mvp", "acks.jsonl"))
	if count != 1 {
		t.Fatalf("expected 1 ack, got %d", count)
	}
}

func TestQuicRecvOpen(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()
	t.Setenv("HOME", homeA)

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
	}
	if err := self.Peers.Upsert(peerB, true); err != nil {
		t.Fatalf("seed peer failed: %v", err)
	}
	if err := self.Members.AddWithScope(peerB.NodeID, proto.InviteScopeContract, false); err != nil {
		t.Fatalf("seed member failed: %v", err)
	}
	if _, err := self.Peers.ObserveAddr(peerB, "127.0.0.1:1", "127.0.0.1:1", true, true); err != nil {
		t.Fatalf("seed peer addr failed: %v", err)
	}
	checker := math4.NewLocalChecker(math4.Options{})
	ready := make(chan struct{})
	done := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		_ = network.ListenAndServeWithResponderFrom(addr, ready, true, func(senderAddr string, data []byte) ([]byte, error) {
			resp, newState, err := recvDataWithResponse(data, st, self, checker, senderAddr)
			if err != nil {
				select {
				case errCh <- err:
				default:
				}
				return nil, err
			}
			if newState {
				select {
				case <-done:
				default:
					close(done)
				}
			}
			return resp, nil
		})
	}()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for quic server ready")
	}

	rootB := filepath.Join(homeB, ".web4mvp")
	selfB, err := node.NewNode(rootB, node.Options{})
	if err != nil {
		t.Fatalf("load node failed: %v", err)
	}
	selfPeer := peer.Peer{NodeID: self.ID, PubKey: self.PubKey}
	if err := selfB.Peers.Upsert(selfPeer, true); err != nil {
		t.Fatalf("seed peer failed: %v", err)
	}
	if _, err := selfB.Peers.ObserveAddr(selfPeer, addr, addr, true, true); err != nil {
		t.Fatalf("seed peer failed: %v", err)
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
	if err := handshakeWithPeer(selfB, self.ID, addr, true, devTLSCAPath); err != nil {
		t.Fatalf("handshake failed: %v", err)
	}

	msgData, err := os.ReadFile(openMsgPath)
	if err != nil {
		t.Fatalf("read open msg failed: %v", err)
	}
	secureData, err := sealSecureEnvelope(selfB, self.ID, proto.MsgTypeContractOpen, "", msgData)
	if err != nil {
		t.Fatalf("seal secure envelope failed: %v", err)
	}
	if err := network.Send(addr, secureData, false, true, devTLSCAPath); err != nil {
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

func findPeer(peers []peer.Peer, id [32]byte) (peer.Peer, bool) {
	for _, p := range peers {
		if p.NodeID == id {
			return p, true
		}
	}
	return peer.Peer{}, false
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

func sendNodeHello(t *testing.T, addr string, pub, priv []byte, target peer.Peer, caPath string, devTLS bool) error {
	t.Helper()
	dir := t.TempDir()
	peerStore, err := peer.NewStore(filepath.Join(dir, "peers.jsonl"), peer.Options{
		Cap:          8,
		TTL:          time.Minute,
		LoadLimit:    0,
		DeriveNodeID: node.DeriveNodeID,
	})
	if err != nil {
		return err
	}
	if err := peerStore.Upsert(target, true); err != nil {
		return err
	}
	n := &node.Node{
		ID:       node.DeriveNodeID(pub),
		PubKey:   pub,
		PrivKey:  priv,
		Peers:    peerStore,
		Sessions: node.NewSessionStore(),
	}
	return handshakeWithPeer(n, target.NodeID, addr, devTLS, caPath)
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

func partyID(label string) string {
	sum := crypto.SHA3_256([]byte("web4:party:v1:" + label))
	return hex.EncodeToString(sum[:])
}

type sessionPair struct {
	a        *node.Node
	b        *node.Node
	stA      *store.Store
	stB      *store.Store
	checkerA math4.LocalChecker
	checkerB math4.LocalChecker
}

func newSessionPair(t *testing.T, homeA, homeB string, checkerA, checkerB math4.LocalChecker) *sessionPair {
	t.Helper()
	rootA := filepath.Join(homeA, ".web4mvp")
	rootB := filepath.Join(homeB, ".web4mvp")
	_ = os.MkdirAll(rootA, 0700)
	_ = os.MkdirAll(rootB, 0700)
	nodeA, err := node.NewNode(rootA, node.Options{})
	if err != nil {
		t.Fatalf("load node A failed: %v", err)
	}
	nodeB, err := node.NewNode(rootB, node.Options{})
	if err != nil {
		t.Fatalf("load node B failed: %v", err)
	}
	if err := nodeA.Peers.Upsert(peer.Peer{NodeID: nodeB.ID, PubKey: nodeB.PubKey}, true); err != nil {
		t.Fatalf("seed peer B failed: %v", err)
	}
	if err := nodeB.Peers.Upsert(peer.Peer{NodeID: nodeA.ID, PubKey: nodeA.PubKey}, true); err != nil {
		t.Fatalf("seed peer A failed: %v", err)
	}
	if err := nodeA.Members.AddWithScope(nodeB.ID, proto.InviteScopeAll, false); err != nil {
		t.Fatalf("seed member B failed: %v", err)
	}
	if err := nodeB.Members.AddWithScope(nodeA.ID, proto.InviteScopeAll, false); err != nil {
		t.Fatalf("seed member A failed: %v", err)
	}
	hello1, err := nodeA.BuildHello1(nodeB.ID)
	if err != nil {
		t.Fatalf("build hello1 failed: %v", err)
	}
	hello2, err := nodeB.HandleHello1(hello1)
	if err != nil {
		t.Fatalf("handle hello1 failed: %v", err)
	}
	if err := nodeA.HandleHello2(hello2); err != nil {
		t.Fatalf("handle hello2 failed: %v", err)
	}
	if checkerA == nil {
		checkerA = math4.NewLocalChecker(math4.Options{})
	}
	if checkerB == nil {
		checkerB = math4.NewLocalChecker(math4.Options{})
	}
	return &sessionPair{
		a:        nodeA,
		b:        nodeB,
		stA:      store.New(filepath.Join(rootA, "contracts.jsonl"), filepath.Join(rootA, "acks.jsonl"), filepath.Join(rootA, "repayreqs.jsonl")),
		stB:      store.New(filepath.Join(rootB, "contracts.jsonl"), filepath.Join(rootB, "acks.jsonl"), filepath.Join(rootB, "repayreqs.jsonl")),
		checkerA: checkerA,
		checkerB: checkerB,
	}
}

func (p *sessionPair) recvToA(payload []byte) error {
	return recvSecureToReceiver(p.b, p.a, p.stA, p.checkerA, payload)
}

func (p *sessionPair) recvToB(payload []byte) error {
	return recvSecureToReceiver(p.a, p.b, p.stB, p.checkerB, payload)
}

func recvSecureToReceiver(sender, receiver *node.Node, st *store.Store, checker math4.LocalChecker, payload []byte) error {
	msgType, err := decodeMsgType(payload)
	if err != nil {
		return err
	}
	secure, err := sealSecureEnvelope(sender, receiver.ID, msgType, "", payload)
	if err != nil {
		return err
	}
	return recvData(secure, st, receiver, checker)
}

func recvPlainToReceiver(receiver *node.Node, st *store.Store, checker math4.LocalChecker, payload []byte) error {
	_, _, err := recvDataWithResponse(payload, st, receiver, checker, "test-sender")
	if err == nil {
		return nil
	}
	return err
}

func decodeMsgType(payload []byte) (string, error) {
	var hdr struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(payload, &hdr); err != nil {
		return "", err
	}
	if hdr.Type == "" {
		return "", fmt.Errorf("missing message type")
	}
	return hdr.Type, nil
}

func buildInviteCert(t *testing.T, inviter *node.Node, inviteePub []byte, inviteID []byte, scope uint32, powBits uint8, issuedAt, expiresAt uint64, powNonce *uint64) ([]byte, proto.InviteCert) {
	t.Helper()
	if inviteID == nil {
		inviteID = bytes.Repeat([]byte{0x11}, 16)
	}
	cert := proto.InviteCert{
		V:          1,
		InviterPub: inviter.PubKey,
		InviteePub: inviteePub,
		InviteID:   inviteID,
		IssuedAt:   issuedAt,
		ExpiresAt:  expiresAt,
		Scope:      scope,
		PowBits:    powBits,
	}
	if powNonce != nil {
		cert.PowNonce = *powNonce
	} else {
		inviteeID := node.DeriveNodeID(inviteePub)
		nonce, ok := crypto.PoWaDSolve(inviteID, inviteeID[:], powBits)
		if !ok {
			t.Fatalf("powad solve failed")
		}
		cert.PowNonce = nonce
	}
	signBytes, err := proto.EncodeInviteCertForSig(cert)
	if err != nil {
		t.Fatalf("invite sign bytes failed: %v", err)
	}
	sig, err := crypto.SignDigest(inviter.PrivKey, crypto.SHA3_256(signBytes))
	if err != nil {
		t.Fatalf("invite sign failed: %v", err)
	}
	cert.Sig = sig
	msg := proto.InviteCertMsgFromCert(cert)
	data, err := proto.EncodeInviteCertMsg(msg)
	if err != nil {
		t.Fatalf("encode invite cert failed: %v", err)
	}
	return data, cert
}

func buildRevokeMsg(t *testing.T, revoker *node.Node, targetID [32]byte, revokeID []byte, reason string, issuedAt uint64) []byte {
	t.Helper()
	if revokeID == nil {
		revokeID = bytes.Repeat([]byte{0x22}, 16)
	}
	if issuedAt == 0 {
		issuedAt = uint64(time.Now().Unix())
	}
	signBytes, err := proto.RevokeSignBytes(revoker.ID, targetID, revokeID, issuedAt, reason)
	if err != nil {
		t.Fatalf("revoke sign bytes failed: %v", err)
	}
	sig := crypto.Sign(revoker.PrivKey, crypto.SHA3_256(signBytes))
	msg := proto.RevokeMsg{
		Type:          proto.MsgTypeRevoke,
		RevokerNodeID: hex.EncodeToString(revoker.ID[:]),
		TargetNodeID:  hex.EncodeToString(targetID[:]),
		Reason:        reason,
		IssuedAt:      issuedAt,
		RevokeID:      hex.EncodeToString(revokeID),
		Sig:           hex.EncodeToString(sig),
	}
	out, err := proto.EncodeRevokeMsg(msg)
	if err != nil {
		t.Fatalf("encode revoke failed: %v", err)
	}
	return out
}

func buildInviteApproval(t *testing.T, approver *node.Node, inviteID []byte, inviteeID [32]byte, expiresAt uint64, scope uint32) proto.InviteApproval {
	t.Helper()
	signBytes, err := proto.InviteApproveSignBytes(inviteID, inviteeID, expiresAt, scope)
	if err != nil {
		t.Fatalf("approve sign bytes failed: %v", err)
	}
	sig := crypto.Sign(approver.PrivKey, crypto.SHA3_256(signBytes))
	return proto.InviteApproval{
		ApproverNodeID: hex.EncodeToString(approver.ID[:]),
		Sig:            hex.EncodeToString(sig),
	}
}

func TestInviteCertValidAddsMember(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()
	homeC := t.TempDir()
	inviter, err := node.NewNode(filepath.Join(homeA, ".web4mvp"), node.Options{})
	if err != nil {
		t.Fatalf("load inviter failed: %v", err)
	}
	invitee, err := node.NewNode(filepath.Join(homeB, ".web4mvp"), node.Options{})
	if err != nil {
		t.Fatalf("load invitee failed: %v", err)
	}
	receiver, err := node.NewNode(filepath.Join(homeC, ".web4mvp"), node.Options{})
	if err != nil {
		t.Fatalf("load receiver failed: %v", err)
	}
	now := uint64(time.Now().Unix())
	data, cert := buildInviteCert(t, inviter, invitee.PubKey, nil, proto.InviteScopeGossip, proto.InvitePoWaDBits, now, now+3600, nil)
	_, _, recvErr := recvDataWithResponse(data, nil, receiver, math4.NewLocalChecker(math4.Options{}), "10.0.0.1:1111")
	if recvErr != nil {
		t.Fatalf("invite recv failed: %v", recvErr)
	}
	inviteeID := node.DeriveNodeID(invitee.PubKey)
	if receiver.Members == nil || !receiver.Members.HasScope(inviteeID, cert.Scope) {
		t.Fatalf("expected invitee to be member")
	}
	inviterID := node.DeriveNodeID(inviter.PubKey)
	if receiver.Invites == nil || !receiver.Invites.Seen(inviterID, cert.InviteID) {
		t.Fatalf("expected invite replay marker")
	}
}

func TestInviteCertReplayRejected(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()
	homeC := t.TempDir()
	inviter, err := node.NewNode(filepath.Join(homeA, ".web4mvp"), node.Options{})
	if err != nil {
		t.Fatalf("load inviter failed: %v", err)
	}
	invitee, err := node.NewNode(filepath.Join(homeB, ".web4mvp"), node.Options{})
	if err != nil {
		t.Fatalf("load invitee failed: %v", err)
	}
	receiver, err := node.NewNode(filepath.Join(homeC, ".web4mvp"), node.Options{})
	if err != nil {
		t.Fatalf("load receiver failed: %v", err)
	}
	now := uint64(time.Now().Unix())
	data, _ := buildInviteCert(t, inviter, invitee.PubKey, nil, proto.InviteScopeGossip, proto.InvitePoWaDBits, now, now+3600, nil)
	_, _, recvErr := recvDataWithResponse(data, nil, receiver, math4.NewLocalChecker(math4.Options{}), "10.0.0.1:1111")
	if recvErr != nil {
		t.Fatalf("invite recv failed: %v", recvErr)
	}
	_, _, recvErr = recvDataWithResponse(data, nil, receiver, math4.NewLocalChecker(math4.Options{}), "10.0.0.1:1111")
	if recvErr == nil || !strings.Contains(recvErr.err.Error(), "replay") {
		t.Fatalf("expected replay rejection, got %v", recvErr)
	}
}

func TestInviteCertWrongSigRejected(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()
	homeC := t.TempDir()
	inviter, err := node.NewNode(filepath.Join(homeA, ".web4mvp"), node.Options{})
	if err != nil {
		t.Fatalf("load inviter failed: %v", err)
	}
	invitee, err := node.NewNode(filepath.Join(homeB, ".web4mvp"), node.Options{})
	if err != nil {
		t.Fatalf("load invitee failed: %v", err)
	}
	receiver, err := node.NewNode(filepath.Join(homeC, ".web4mvp"), node.Options{})
	if err != nil {
		t.Fatalf("load receiver failed: %v", err)
	}
	now := uint64(time.Now().Unix())
	data, _ := buildInviteCert(t, inviter, invitee.PubKey, nil, proto.InviteScopeGossip, proto.InvitePoWaDBits, now, now+3600, nil)
	var msg map[string]any
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("decode invite msg failed: %v", err)
	}
	sigHex := msg["sig"].(string)
	if len(sigHex) < 2 {
		t.Fatalf("sig too short")
	}
	if sigHex[len(sigHex)-1] == '0' {
		sigHex = sigHex[:len(sigHex)-1] + "1"
	} else {
		sigHex = sigHex[:len(sigHex)-1] + "0"
	}
	msg["sig"] = sigHex
	bad, _ := json.Marshal(msg)
	_, _, recvErr := recvDataWithResponse(bad, nil, receiver, math4.NewLocalChecker(math4.Options{}), "10.0.0.1:1111")
	if recvErr == nil || !strings.Contains(recvErr.err.Error(), "signature") {
		t.Fatalf("expected bad signature, got %v", recvErr)
	}
}

func TestInviteCertWrongPowRejected(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()
	homeC := t.TempDir()
	inviter, err := node.NewNode(filepath.Join(homeA, ".web4mvp"), node.Options{})
	if err != nil {
		t.Fatalf("load inviter failed: %v", err)
	}
	invitee, err := node.NewNode(filepath.Join(homeB, ".web4mvp"), node.Options{})
	if err != nil {
		t.Fatalf("load invitee failed: %v", err)
	}
	receiver, err := node.NewNode(filepath.Join(homeC, ".web4mvp"), node.Options{})
	if err != nil {
		t.Fatalf("load receiver failed: %v", err)
	}
	now := uint64(time.Now().Unix())
	badNonce := uint64(0)
	data, _ := buildInviteCert(t, inviter, invitee.PubKey, nil, proto.InviteScopeGossip, proto.InvitePoWaDBits, now, now+3600, &badNonce)
	_, _, recvErr := recvDataWithResponse(data, nil, receiver, math4.NewLocalChecker(math4.Options{}), "10.0.0.1:1111")
	if recvErr == nil || !strings.Contains(recvErr.err.Error(), "powad") {
		t.Fatalf("expected powad rejection, got %v", recvErr)
	}
}

func TestInviteCertExpiredRejected(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()
	homeC := t.TempDir()
	inviter, err := node.NewNode(filepath.Join(homeA, ".web4mvp"), node.Options{})
	if err != nil {
		t.Fatalf("load inviter failed: %v", err)
	}
	invitee, err := node.NewNode(filepath.Join(homeB, ".web4mvp"), node.Options{})
	if err != nil {
		t.Fatalf("load invitee failed: %v", err)
	}
	receiver, err := node.NewNode(filepath.Join(homeC, ".web4mvp"), node.Options{})
	if err != nil {
		t.Fatalf("load receiver failed: %v", err)
	}
	now := uint64(time.Now().Unix())
	data, _ := buildInviteCert(t, inviter, invitee.PubKey, nil, proto.InviteScopeGossip, proto.InvitePoWaDBits, now-7200, now-3600, nil)
	_, _, recvErr := recvDataWithResponse(data, nil, receiver, math4.NewLocalChecker(math4.Options{}), "10.0.0.1:1111")
	if recvErr == nil || !strings.Contains(recvErr.err.Error(), "expired") {
		t.Fatalf("expected expired rejection, got %v", recvErr)
	}
}

func TestInviteCertNodeIDMismatchRejected(t *testing.T) {
	homeA := t.TempDir()
	homeC := t.TempDir()
	inviter, err := node.NewNode(filepath.Join(homeA, ".web4mvp"), node.Options{})
	if err != nil {
		t.Fatalf("load inviter failed: %v", err)
	}
	receiver, err := node.NewNode(filepath.Join(homeC, ".web4mvp"), node.Options{})
	if err != nil {
		t.Fatalf("load receiver failed: %v", err)
	}
	now := uint64(time.Now().Unix())
	badPub := []byte("not-a-valid-pubkey")
	data, _ := buildInviteCert(t, inviter, badPub, nil, proto.InviteScopeGossip, proto.InvitePoWaDBits, now, now+3600, nil)
	_, _, recvErr := recvDataWithResponse(data, nil, receiver, math4.NewLocalChecker(math4.Options{}), "10.0.0.1:1111")
	if recvErr == nil || !strings.Contains(recvErr.err.Error(), "node_id mismatch") {
		t.Fatalf("expected node_id mismatch rejection, got %v", recvErr)
	}
}

func TestInviteCertAcceptsWithoutKnownPeer(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()
	homeC := t.TempDir()
	inviter, err := node.NewNode(filepath.Join(homeA, ".web4mvp"), node.Options{})
	if err != nil {
		t.Fatalf("load inviter failed: %v", err)
	}
	invitee, err := node.NewNode(filepath.Join(homeB, ".web4mvp"), node.Options{})
	if err != nil {
		t.Fatalf("load invitee failed: %v", err)
	}
	receiver, err := node.NewNode(filepath.Join(homeC, ".web4mvp"), node.Options{})
	if err != nil {
		t.Fatalf("load receiver failed: %v", err)
	}
	now := uint64(time.Now().Unix())
	data, _ := buildInviteCert(t, inviter, invitee.PubKey, nil, proto.InviteScopeGossip, proto.InvitePoWaDBits, now, now+3600, nil)
	_, _, recvErr := recvDataWithResponse(data, nil, receiver, math4.NewLocalChecker(math4.Options{}), "10.0.0.1:1111")
	if recvErr != nil {
		t.Fatalf("invite recv failed: %v", recvErr)
	}
	inviteeID := node.DeriveNodeID(invitee.PubKey)
	if receiver.Members == nil || !receiver.Members.HasScope(inviteeID, proto.InviteScopeGossip) {
		t.Fatalf("expected invitee member without prior peer")
	}
}

func TestHandshakeRetryRegeneratesHello1(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()
	rootA := filepath.Join(homeA, ".web4mvp")
	rootB := filepath.Join(homeB, ".web4mvp")
	_ = os.MkdirAll(rootA, 0700)
	_ = os.MkdirAll(rootB, 0700)
	nodeA, err := node.NewNode(rootA, node.Options{})
	if err != nil {
		t.Fatalf("load node A failed: %v", err)
	}
	nodeB, err := node.NewNode(rootB, node.Options{})
	if err != nil {
		t.Fatalf("load node B failed: %v", err)
	}
	if err := nodeA.Peers.Upsert(peer.Peer{NodeID: nodeB.ID, PubKey: nodeB.PubKey}, true); err != nil {
		t.Fatalf("seed peer B failed: %v", err)
	}
	if err := nodeB.Peers.Upsert(peer.Peer{NodeID: nodeA.ID, PubKey: nodeA.PubKey}, true); err != nil {
		t.Fatalf("seed peer A failed: %v", err)
	}
	call := 0
	var firstHello1 string
	exchange := func(_ context.Context, _ string, data []byte, _ bool, _ bool, _ string) ([]byte, error) {
		call++
		msg, err := proto.DecodeHello1Msg(data)
		if err != nil {
			return nil, err
		}
		if call == 1 {
			firstHello1 = msg.Na
			_, err := nodeB.HandleHello1(msg)
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("simulated drop")
		}
		if call == 2 {
			if msg.Na == firstHello1 {
				return nil, fmt.Errorf("reused hello1 nonce")
			}
			resp, err := nodeB.HandleHello1(msg)
			if err != nil {
				return nil, err
			}
			return proto.EncodeHello2Msg(resp)
		}
		return nil, fmt.Errorf("unexpected attempt")
	}
	if err := handshakeWithPeerWithExchange(nodeA, nodeB.ID, "127.0.0.1:1", true, "", exchange); err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	if !nodeA.Sessions.Has(nodeB.ID) {
		t.Fatalf("expected session on node A")
	}
}

func TestRateLimitDropsBeforeVerify(t *testing.T) {
	resetRecvLimiters(1, 0, time.Minute)
	defer resetRecvLimiters(defaultHostRateLimit, defaultNodeRateLimit, defaultRateWindow)

	homeA := t.TempDir()
	homeB := t.TempDir()
	rootA := filepath.Join(homeA, ".web4mvp")
	rootB := filepath.Join(homeB, ".web4mvp")
	_ = os.MkdirAll(rootA, 0700)
	_ = os.MkdirAll(rootB, 0700)
	sender, err := node.NewNode(rootA, node.Options{})
	if err != nil {
		t.Fatalf("load sender failed: %v", err)
	}
	receiver, err := node.NewNode(rootB, node.Options{})
	if err != nil {
		t.Fatalf("load receiver failed: %v", err)
	}
	st := store.New(
		filepath.Join(rootB, "contracts.jsonl"),
		filepath.Join(rootB, "acks.jsonl"),
		filepath.Join(rootB, "repayreqs.jsonl"),
	)
	hello1, err := sender.BuildHello1(receiver.ID)
	if err != nil {
		t.Fatalf("build hello1 failed: %v", err)
	}
	if len(hello1.Sig) == 0 {
		t.Fatalf("missing hello1 sig")
	}
	last := hello1.Sig[len(hello1.Sig)-1]
	if last == '0' {
		last = '1'
	} else {
		last = '0'
	}
	hello1.Sig = hello1.Sig[:len(hello1.Sig)-1] + string(last)
	data, err := proto.EncodeHello1Msg(hello1)
	if err != nil {
		t.Fatalf("encode hello1 failed: %v", err)
	}
	_, _, recvErr := recvDataWithResponse(data, st, receiver, math4.NewLocalChecker(math4.Options{}), "10.0.0.1:1111")
	if recvErr == nil || recvErr.msg != "invalid hello1" {
		t.Fatalf("expected invalid hello1, got %v", recvErr)
	}
	_, _, recvErr = recvDataWithResponse(data, st, receiver, math4.NewLocalChecker(math4.Options{}), "10.0.0.1:1111")
	if recvErr == nil || recvErr.msg != "rate_limit_host" {
		t.Fatalf("expected rate_limit_host, got %v", recvErr)
	}
}

func TestRateLimitDropsBeforeDecrypt(t *testing.T) {
	resetRecvLimiters(1, 1, time.Minute)
	defer resetRecvLimiters(defaultHostRateLimit, defaultNodeRateLimit, defaultRateWindow)

	homeA := t.TempDir()
	homeB := t.TempDir()
	pair := newSessionPair(t, homeA, homeB, nil, nil)
	req := proto.PeerExchangeReqMsg{
		Type:         proto.MsgTypePeerExchangeReq,
		ProtoVersion: proto.ProtoVersion,
		Suite:        proto.Suite,
		K:            1,
	}
	payload, err := proto.EncodePeerExchangeReq(req)
	if err != nil {
		t.Fatalf("encode peer exchange req failed: %v", err)
	}
	secure, err := sealSecureEnvelope(pair.a, pair.b.ID, proto.MsgTypePeerExchangeReq, "", payload)
	if err != nil {
		t.Fatalf("seal secure envelope failed: %v", err)
	}
	env, err := proto.DecodeSecureEnvelope(secure)
	if err != nil {
		t.Fatalf("decode secure envelope failed: %v", err)
	}
	if len(env.Sealed) == 0 {
		t.Fatalf("missing sealed payload")
	}
	sealed := []byte(env.Sealed)
	if sealed[len(sealed)-1] == 'A' {
		sealed[len(sealed)-1] = 'B'
	} else {
		sealed[len(sealed)-1] = 'A'
	}
	env.Sealed = string(sealed)
	bad, err := proto.EncodeSecureEnvelope(env)
	if err != nil {
		t.Fatalf("encode secure envelope failed: %v", err)
	}
	_, _, recvErr := recvDataWithResponse(bad, pair.stB, pair.b, pair.checkerB, "10.0.0.2:2222")
	if recvErr == nil || recvErr.msg != "open secure envelope failed" {
		t.Fatalf("expected open secure envelope failed, got %v", recvErr)
	}
	_, _, recvErr = recvDataWithResponse(bad, pair.stB, pair.b, pair.checkerB, "10.0.0.2:2222")
	if recvErr == nil || recvErr.msg != "rate_limit_host" {
		t.Fatalf("expected rate_limit_host, got %v", recvErr)
	}
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
	senderPub := loadPub(t, homeA)
	senderID := node.DeriveNodeID(senderPub)
	if err := self.Peers.Upsert(peer.Peer{NodeID: senderID, PubKey: senderPub, Addr: ""}, true); err != nil {
		t.Fatalf("seed peer failed: %v", err)
	}
	checker := math4.NewLocalChecker(math4.Options{})
	ready := make(chan struct{})
	done := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		_ = network.ListenAndServeWithResponderFrom(addr, ready, true, func(senderAddr string, data []byte) ([]byte, error) {
			resp, _, err := recvDataWithResponse(data, st, self, checker, senderAddr)
			if err != nil {
				select {
				case errCh <- err:
				default:
				}
				return nil, err
			}
			if len(resp) > 0 {
				select {
				case <-done:
				default:
					close(done)
				}
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
	if err := runWithHome(homeA, "node", "hello", "--devtls", "--addr", addr, "--devtls-ca", devTLSCAPath, "--to-id", hex.EncodeToString(self.ID[:])); err != nil {
		t.Fatalf("node hello failed: %v", err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("recv error: %v", err)
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for node hello")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if self.Sessions.Has(senderID) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected sender session")
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
	}
	if err := self.Peers.Upsert(peerC, true); err != nil {
		t.Fatalf("seed peer failed: %v", err)
	}
	if _, err := self.Peers.ObserveAddr(peerC, "127.0.0.1:42430", "127.0.0.1:42430", true, true); err != nil {
		t.Fatalf("seed peer addr failed: %v", err)
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
	pubB, _ := loadKeypair(t, homeB)
	peerB := peer.Peer{NodeID: node.DeriveNodeID(pubB), PubKey: pubB, Addr: ""}
	if err := self.Peers.Upsert(peerB, true); err != nil {
		t.Fatalf("seed peer failed: %v", err)
	}
	if err := self.Members.AddWithScope(peerB.NodeID, proto.InviteScopeGossip, false); err != nil {
		t.Fatalf("seed member failed: %v", err)
	}
	rootB := filepath.Join(homeB, ".web4mvp")
	selfB, err := node.NewNode(rootB, node.Options{})
	if err != nil {
		t.Fatalf("load node failed: %v", err)
	}
	selfPeer := peer.Peer{NodeID: self.ID, PubKey: self.PubKey}
	if err := selfB.Peers.Upsert(selfPeer, true); err != nil {
		t.Fatalf("seed peer failed: %v", err)
	}
	if _, err := selfB.Peers.ObserveAddr(selfPeer, addr, addr, true, true); err != nil {
		t.Fatalf("seed peer failed: %v", err)
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
	homeB := t.TempDir()
	homeC := t.TempDir()

	runOK(t, homeB, "keygen")
	runOK(t, homeC, "keygen")

	rootB := filepath.Join(homeB, ".web4mvp")
	rootC := filepath.Join(homeC, ".web4mvp")
	selfB, err := node.NewNode(rootB, node.Options{})
	if err != nil {
		t.Fatalf("load node failed: %v", err)
	}
	selfC, err := node.NewNode(rootC, node.Options{})
	if err != nil {
		t.Fatalf("load node failed: %v", err)
	}

	peerB := peer.Peer{NodeID: selfB.ID, PubKey: selfB.PubKey}
	peerC := peer.Peer{NodeID: selfC.ID, PubKey: selfC.PubKey}
	if err := selfB.Peers.Upsert(peerC, true); err != nil {
		t.Fatalf("seed peer failed: %v", err)
	}
	if err := selfC.Peers.Upsert(peerB, true); err != nil {
		t.Fatalf("seed peer failed: %v", err)
	}

	hello1, err := selfB.BuildHello1(selfC.ID)
	if err != nil {
		t.Fatalf("build hello1 failed: %v", err)
	}
	hello2, err := selfC.HandleHello1(hello1)
	if err != nil {
		t.Fatalf("handle hello1 failed: %v", err)
	}
	if err := selfB.HandleHello2(hello2); err != nil {
		t.Fatalf("handle hello2 failed: %v", err)
	}

	payload := []byte(`{"type":"peer_exchange_req","proto_version":"` + proto.ProtoVersion + `","suite":"` + proto.Suite + `","k":1}`)
	gossipData, err := buildGossipPushForPeer(peerC, payload, 1, selfB)
	if err != nil {
		t.Fatalf("encode gossip push failed: %v", err)
	}
	secureData, err := sealSecureEnvelope(selfB, peerC.NodeID, proto.MsgTypeGossipPush, "", gossipData)
	if err != nil {
		t.Fatalf("seal secure envelope failed: %v", err)
	}
	env, err := proto.DecodeSecureEnvelope(secureData)
	if err != nil {
		t.Fatalf("decode secure envelope failed: %v", err)
	}
	msgType, plain, _, err := openSecureEnvelope(selfC, env)
	if err != nil {
		t.Fatalf("open secure envelope failed: %v", err)
	}
	if msgType != proto.MsgTypeGossipPush {
		t.Fatalf("unexpected msg type: %s", msgType)
	}
	msg, err := proto.DecodeGossipPushMsg(plain)
	if err != nil {
		t.Fatalf("decode gossip push failed: %v", err)
	}
	opened, err := openGossipEnvelope(selfC, msg)
	if err != nil {
		t.Fatalf("open gossip envelope failed: %v", err)
	}
	if !bytes.Equal(opened, payload) {
		t.Fatalf("gossip payload mismatch")
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
	if err := selfB.Peers.Upsert(peer.Peer{NodeID: selfA.ID, PubKey: selfA.PubKey, Addr: ""}, true); err != nil {
		t.Fatalf("seed peer failed: %v", err)
	}
	peerB := peer.Peer{NodeID: selfB.ID, PubKey: selfB.PubKey}
	if err := selfA.Peers.Upsert(peerB, true); err != nil {
		t.Fatalf("seed peer failed: %v", err)
	}
	if _, err := selfA.Peers.ObserveAddr(peerB, addrB, addrB, true, true); err != nil {
		t.Fatalf("seed peer failed: %v", err)
	}
	if err := handshakeWithPeer(selfA, selfB.ID, addrB, true, devTLSCAPath); err != nil {
		t.Fatalf("handshake failed: %v", err)
	}

	var fakeFrom [32]byte
	copy(fakeFrom[:], crypto.SHA3_256([]byte("web4:test:unknown")))
	var zero [32]byte
	ephPub, sealed, err := e2eSeal(proto.MsgTypeGossipPush, zero, 0, pubB, envelope)
	if err != nil {
		t.Fatalf("seal gossip payload failed: %v", err)
	}
	gossipMsg := proto.GossipPushMsg{
		Type:         proto.MsgTypeGossipPush,
		ProtoVersion: proto.ProtoVersion,
		Suite:        proto.Suite,
		FromNodeID:   hex.EncodeToString(fakeFrom[:]),
		EphemeralPub: base64.StdEncoding.EncodeToString(ephPub),
		Sealed:       base64.StdEncoding.EncodeToString(sealed),
		Hops:         2,
	}
	gossipData, err := proto.EncodeGossipPushMsg(gossipMsg)
	if err != nil {
		t.Fatalf("encode gossip push failed: %v", err)
	}
	secureData, err := sealSecureEnvelope(selfA, selfB.ID, proto.MsgTypeGossipPush, "", gossipData)
	if err != nil {
		t.Fatalf("seal secure envelope failed: %v", err)
	}
	if err := network.Send(addrB, secureData, false, true, devTLSCAPath); err != nil {
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

func TestGossipForwardHello1LearnsPeer(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()
	homeC := t.TempDir()
	homeD := t.TempDir()
	homeTLS := t.TempDir()

	runOK(t, homeA, "keygen")
	runOK(t, homeB, "keygen")
	runOK(t, homeC, "keygen")
	runOK(t, homeD, "keygen")

	t.Setenv("HOME", homeTLS)
	t.Setenv("WEB4_GOSSIP_FANOUT", "1")
	t.Setenv("WEB4_GOSSIP_TTL_HOPS", "2")
	t.Setenv("WEB4_DEBUG", "1")

	rootA := filepath.Join(homeA, ".web4mvp")
	rootB := filepath.Join(homeB, ".web4mvp")
	rootC := filepath.Join(homeC, ".web4mvp")
	rootD := filepath.Join(homeD, ".web4mvp")

	selfA, err := node.NewNode(rootA, node.Options{})
	if err != nil {
		t.Fatalf("load node A failed: %v", err)
	}
	selfB, err := node.NewNode(rootB, node.Options{})
	if err != nil {
		t.Fatalf("load node B failed: %v", err)
	}
	selfC, err := node.NewNode(rootC, node.Options{})
	if err != nil {
		t.Fatalf("load node C failed: %v", err)
	}
	selfD, err := node.NewNode(rootD, node.Options{})
	if err != nil {
		t.Fatalf("load node D failed: %v", err)
	}

	addrC := freeUDPAddr(t)
	if err := selfB.Peers.Upsert(peer.Peer{NodeID: selfA.ID, PubKey: selfA.PubKey}, true); err != nil {
		t.Fatalf("seed peer A failed: %v", err)
	}
	if err := selfB.Peers.Upsert(peer.Peer{NodeID: selfC.ID, PubKey: selfC.PubKey}, true); err != nil {
		t.Fatalf("seed peer C failed: %v", err)
	}
	if _, err := selfB.Peers.SetAddrUnverified(peer.Peer{NodeID: selfC.ID, PubKey: selfC.PubKey}, addrC, true); err != nil {
		t.Fatalf("set C addr hint failed: %v", err)
	}
	if err := selfC.Peers.Upsert(peer.Peer{NodeID: selfB.ID, PubKey: selfB.PubKey}, true); err != nil {
		t.Fatalf("seed peer B failed: %v", err)
	}

	if err := selfB.Members.Add(selfA.ID, false); err != nil {
		t.Fatalf("add member A to B failed: %v", err)
	}
	if err := selfB.Members.Add(selfB.ID, false); err != nil {
		t.Fatalf("add member B to B failed: %v", err)
	}
	if err := selfB.Members.Add(selfC.ID, false); err != nil {
		t.Fatalf("add member C to B failed: %v", err)
	}
	if err := selfC.Members.Add(selfB.ID, false); err != nil {
		t.Fatalf("add member B to C failed: %v", err)
	}
	if err := selfC.Members.Add(selfC.ID, false); err != nil {
		t.Fatalf("add member C to C failed: %v", err)
	}

	checker := math4.NewLocalChecker(math4.Options{})
	ready := make(chan struct{})
	go func() {
		_ = network.ListenAndServeWithResponderFrom(addrC, ready, true, func(senderAddr string, data []byte) ([]byte, error) {
			resp, _, err := recvDataWithResponse(data, nil, selfC, checker, senderAddr)
			if err != nil {
				return nil, err
			}
			return resp, nil
		})
	}()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for C quic server ready")
	}

	hello1, err := selfD.BuildHello1(selfA.ID)
	if err != nil {
		t.Fatalf("build hello1 failed: %v", err)
	}
	hello1Data, err := proto.EncodeHello1Msg(hello1)
	if err != nil {
		t.Fatalf("encode hello1 failed: %v", err)
	}
	if err := enforceTypeMax(proto.MsgTypeHello1, len(hello1Data)); err != nil {
		t.Fatalf("hello1 too large: %v", err)
	}

	peerB := peer.Peer{NodeID: selfB.ID, PubKey: selfB.PubKey}
	gossipData, err := buildGossipPushForPeer(peerB, hello1Data, 2, selfA)
	if err != nil {
		t.Fatalf("build gossip push failed: %v", err)
	}
	_, _, recvErr := handleGossipPush(gossipData, nil, selfB, checker, "127.0.0.1:1111")
	if recvErr != nil {
		t.Fatalf("handle gossip push failed: msg=%s err=%v", recvErr.msg, recvErr.err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := findPeer(selfC.Peers.List(), selfD.ID); ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected C to learn D from forwarded gossip")
}

func TestGossipForwardSendsGossipPush(t *testing.T) {
	homeB := t.TempDir()
	homeC := t.TempDir()

	runOK(t, homeB, "keygen")
	runOK(t, homeC, "keygen")

	t.Setenv("WEB4_GOSSIP_FANOUT", "1")
	t.Setenv("WEB4_GOSSIP_TTL_HOPS", "2")

	rootB := filepath.Join(homeB, ".web4mvp")
	rootC := filepath.Join(homeC, ".web4mvp")

	selfB, err := node.NewNode(rootB, node.Options{})
	if err != nil {
		t.Fatalf("load node B failed: %v", err)
	}
	selfC, err := node.NewNode(rootC, node.Options{})
	if err != nil {
		t.Fatalf("load node C failed: %v", err)
	}

	addrC := freeUDPAddr(t)
	if err := selfB.Peers.Upsert(peer.Peer{NodeID: selfC.ID, PubKey: selfC.PubKey}, true); err != nil {
		t.Fatalf("seed peer C failed: %v", err)
	}
	if _, err := selfB.Peers.SetAddrUnverified(peer.Peer{NodeID: selfC.ID, PubKey: selfC.PubKey}, addrC, true); err != nil {
		t.Fatalf("set C addr hint failed: %v", err)
	}
	if err := selfB.Members.Add(selfC.ID, false); err != nil {
		t.Fatalf("add member C failed: %v", err)
	}

	var sent []byte
	prevSend := sendFunc
	sendFunc = func(addr string, data []byte, insecure bool, devTLS bool, devTLSCAPath string) error {
		sent = append([]byte(nil), data...)
		return nil
	}
	t.Cleanup(func() {
		sendFunc = prevSend
	})

	hello1, err := selfC.BuildHello1(selfB.ID)
	if err != nil {
		t.Fatalf("build hello1 failed: %v", err)
	}
	envelope, err := proto.EncodeHello1Msg(hello1)
	if err != nil {
		t.Fatalf("encode hello1 failed: %v", err)
	}
	forwardGossip(proto.GossipPushMsg{Hops: 2}, envelope, proto.MsgTypeHello1, "testmsgid", selfB, "127.0.0.1:12345")
	if len(sent) == 0 {
		t.Fatalf("expected gossip forward send")
	}
	var hdr struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(sent, &hdr); err != nil {
		t.Fatalf("decode forwarded message failed: %v", err)
	}
	if hdr.Type != proto.MsgTypeGossipPush {
		t.Fatalf("expected gossip_push, got %q", hdr.Type)
	}
}

func TestRevokeInviterCanRevoke(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()
	homeR := t.TempDir()

	pair := newSessionPair(t, homeA, homeR, nil, nil)
	invitee, err := node.NewNode(filepath.Join(homeB, ".web4mvp"), node.Options{})
	if err != nil {
		t.Fatalf("load invitee failed: %v", err)
	}

	now := uint64(time.Now().Unix())
	inviteData, _ := buildInviteCert(t, pair.a, invitee.PubKey, nil, proto.InviteScopeContract, proto.InvitePoWaDBits, now, now+3600, nil)
	if err := recvPlainToReceiver(pair.b, pair.stB, pair.checkerB, inviteData); err != nil {
		t.Fatalf("invite recv failed: %v", err)
	}

	revokeMsg := buildRevokeMsg(t, pair.a, invitee.ID, nil, "misbehave", 0)
	if err := recvSecureToReceiver(pair.a, pair.b, pair.stB, pair.checkerB, revokeMsg); err != nil {
		t.Fatalf("revoke recv failed: %v", err)
	}
	if pair.b.Members.HasScope(invitee.ID, 0) {
		t.Fatalf("expected invitee scope revoked")
	}
}

func TestRevokeNonInviterRejected(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()
	homeC := t.TempDir()
	homeR := t.TempDir()

	pair := newSessionPair(t, homeC, homeR, nil, nil)
	inviter, err := node.NewNode(filepath.Join(homeA, ".web4mvp"), node.Options{})
	if err != nil {
		t.Fatalf("load inviter failed: %v", err)
	}
	invitee, err := node.NewNode(filepath.Join(homeB, ".web4mvp"), node.Options{})
	if err != nil {
		t.Fatalf("load invitee failed: %v", err)
	}

	now := uint64(time.Now().Unix())
	inviteData, _ := buildInviteCert(t, inviter, invitee.PubKey, nil, proto.InviteScopeContract, proto.InvitePoWaDBits, now, now+3600, nil)
	if err := recvPlainToReceiver(pair.b, pair.stB, pair.checkerB, inviteData); err != nil {
		t.Fatalf("invite recv failed: %v", err)
	}

	revokeMsg := buildRevokeMsg(t, pair.a, invitee.ID, nil, "unauthorized", 0)
	if err := recvSecureToReceiver(pair.a, pair.b, pair.stB, pair.checkerB, revokeMsg); err == nil {
		t.Fatalf("expected non-inviter revoke to be rejected")
	}
}

func TestRevokeReplayRejected(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()
	homeR := t.TempDir()

	pair := newSessionPair(t, homeA, homeR, nil, nil)
	invitee, err := node.NewNode(filepath.Join(homeB, ".web4mvp"), node.Options{})
	if err != nil {
		t.Fatalf("load invitee failed: %v", err)
	}

	now := uint64(time.Now().Unix())
	inviteData, _ := buildInviteCert(t, pair.a, invitee.PubKey, nil, proto.InviteScopeContract, proto.InvitePoWaDBits, now, now+3600, nil)
	if err := recvPlainToReceiver(pair.b, pair.stB, pair.checkerB, inviteData); err != nil {
		t.Fatalf("invite recv failed: %v", err)
	}

	revokeID := bytes.Repeat([]byte{0x33}, 16)
	revokeMsg := buildRevokeMsg(t, pair.a, invitee.ID, revokeID, "replay", 0)
	if err := recvSecureToReceiver(pair.a, pair.b, pair.stB, pair.checkerB, revokeMsg); err != nil {
		t.Fatalf("revoke recv failed: %v", err)
	}
	if err := recvSecureToReceiver(pair.a, pair.b, pair.stB, pair.checkerB, revokeMsg); err == nil {
		t.Fatalf("expected replay revoke to be rejected")
	}
}

func TestInviteBundleThreshold(t *testing.T) {
	t.Setenv("WEB4_INVITE_THRESHOLD", "2")

	setup := func() (*node.Node, *store.Store, math4.LocalChecker, *node.Node, *node.Node, *node.Node) {
		homeR := t.TempDir()
		homeA := t.TempDir()
		homeC := t.TempDir()
		homeI := t.TempDir()
		receiver, err := node.NewNode(filepath.Join(homeR, ".web4mvp"), node.Options{})
		if err != nil {
			t.Fatalf("load receiver failed: %v", err)
		}
		approverA, err := node.NewNode(filepath.Join(homeA, ".web4mvp"), node.Options{})
		if err != nil {
			t.Fatalf("load approver A failed: %v", err)
		}
		approverC, err := node.NewNode(filepath.Join(homeC, ".web4mvp"), node.Options{})
		if err != nil {
			t.Fatalf("load approver C failed: %v", err)
		}
		invitee, err := node.NewNode(filepath.Join(homeI, ".web4mvp"), node.Options{})
		if err != nil {
			t.Fatalf("load invitee failed: %v", err)
		}
		if receiver.Peers != nil {
			_ = receiver.Peers.Upsert(peer.Peer{NodeID: approverA.ID, PubKey: approverA.PubKey}, true)
			_ = receiver.Peers.Upsert(peer.Peer{NodeID: approverC.ID, PubKey: approverC.PubKey}, true)
		}
		if receiver.Members != nil {
			_ = receiver.Members.AddWithScope(approverA.ID, proto.InviteScopeAll, false)
			_ = receiver.Members.AddWithScope(approverC.ID, proto.InviteScopeAll, false)
		}
		st := store.New(filepath.Join(homeR, ".web4mvp", "contracts.jsonl"), filepath.Join(homeR, ".web4mvp", "acks.jsonl"), filepath.Join(homeR, ".web4mvp", "repayreqs.jsonl"))
		checker := math4.NewLocalChecker(math4.Options{})
		return receiver, st, checker, approverA, approverC, invitee
	}

	t.Run("one approval rejected", func(t *testing.T) {
		receiver, st, checker, approverA, _, invitee := setup()
		inviteID := bytes.Repeat([]byte{0x44}, 16)
		expiresAt := uint64(time.Now().Unix() + 3600)
		scope := proto.InviteScopeGossip
		approvalA := buildInviteApproval(t, approverA, inviteID, invitee.ID, expiresAt, scope)
		msg := proto.InviteBundleMsg{
			InviteePub:    hex.EncodeToString(invitee.PubKey),
			InviteeNodeID: hex.EncodeToString(invitee.ID[:]),
			InviteID:      hex.EncodeToString(inviteID),
			ExpiresAt:     expiresAt,
			Scope:         scope,
			Approvals:     []proto.InviteApproval{approvalA},
		}
		data, err := proto.EncodeInviteBundleMsg(msg)
		if err != nil {
			t.Fatalf("encode invite bundle failed: %v", err)
		}
		if err := recvPlainToReceiver(receiver, st, checker, data); err == nil {
			t.Fatalf("expected insufficient approvals rejection")
		}
	})

	t.Run("two approvals accepted", func(t *testing.T) {
		receiver, st, checker, approverA, approverC, invitee := setup()
		inviteID := bytes.Repeat([]byte{0x45}, 16)
		expiresAt := uint64(time.Now().Unix() + 3600)
		scope := proto.InviteScopeGossip
		approvalA := buildInviteApproval(t, approverA, inviteID, invitee.ID, expiresAt, scope)
		approvalC := buildInviteApproval(t, approverC, inviteID, invitee.ID, expiresAt, scope)
		msg := proto.InviteBundleMsg{
			InviteePub:    hex.EncodeToString(invitee.PubKey),
			InviteeNodeID: hex.EncodeToString(invitee.ID[:]),
			InviteID:      hex.EncodeToString(inviteID),
			ExpiresAt:     expiresAt,
			Scope:         scope,
			Approvals:     []proto.InviteApproval{approvalA, approvalC},
		}
		data, err := proto.EncodeInviteBundleMsg(msg)
		if err != nil {
			t.Fatalf("encode invite bundle failed: %v", err)
		}
		if err := recvPlainToReceiver(receiver, st, checker, data); err != nil {
			t.Fatalf("invite bundle recv failed: %v", err)
		}
		if !receiver.Members.HasScope(invitee.ID, scope) {
			t.Fatalf("expected invitee added with scope")
		}
	})

	t.Run("duplicate approvals rejected", func(t *testing.T) {
		receiver, st, checker, approverA, _, invitee := setup()
		inviteID := bytes.Repeat([]byte{0x46}, 16)
		expiresAt := uint64(time.Now().Unix() + 3600)
		scope := proto.InviteScopeGossip
		approvalA := buildInviteApproval(t, approverA, inviteID, invitee.ID, expiresAt, scope)
		msg := proto.InviteBundleMsg{
			InviteePub:    hex.EncodeToString(invitee.PubKey),
			InviteeNodeID: hex.EncodeToString(invitee.ID[:]),
			InviteID:      hex.EncodeToString(inviteID),
			ExpiresAt:     expiresAt,
			Scope:         scope,
			Approvals:     []proto.InviteApproval{approvalA, approvalA},
		}
		data, err := proto.EncodeInviteBundleMsg(msg)
		if err != nil {
			t.Fatalf("encode invite bundle failed: %v", err)
		}
		if err := recvPlainToReceiver(receiver, st, checker, data); err == nil {
			t.Fatalf("expected duplicate approvals rejection")
		}
	})

	t.Run("expired bundle rejected", func(t *testing.T) {
		receiver, st, checker, approverA, approverC, invitee := setup()
		inviteID := bytes.Repeat([]byte{0x47}, 16)
		expiresAt := uint64(time.Now().Unix() - 1)
		scope := proto.InviteScopeGossip
		approvalA := buildInviteApproval(t, approverA, inviteID, invitee.ID, expiresAt, scope)
		approvalC := buildInviteApproval(t, approverC, inviteID, invitee.ID, expiresAt, scope)
		msg := proto.InviteBundleMsg{
			InviteePub:    hex.EncodeToString(invitee.PubKey),
			InviteeNodeID: hex.EncodeToString(invitee.ID[:]),
			InviteID:      hex.EncodeToString(inviteID),
			ExpiresAt:     expiresAt,
			Scope:         scope,
			Approvals:     []proto.InviteApproval{approvalA, approvalC},
		}
		data, err := proto.EncodeInviteBundleMsg(msg)
		if err != nil {
			t.Fatalf("encode invite bundle failed: %v", err)
		}
		if err := recvPlainToReceiver(receiver, st, checker, data); err == nil {
			t.Fatalf("expected expired bundle rejection")
		}
	})

	t.Run("replay rejected", func(t *testing.T) {
		receiver, st, checker, approverA, approverC, invitee := setup()
		inviteID := bytes.Repeat([]byte{0x48}, 16)
		expiresAt := uint64(time.Now().Unix() + 3600)
		scope := proto.InviteScopeGossip
		approvalA := buildInviteApproval(t, approverA, inviteID, invitee.ID, expiresAt, scope)
		approvalC := buildInviteApproval(t, approverC, inviteID, invitee.ID, expiresAt, scope)
		msg := proto.InviteBundleMsg{
			InviteePub:    hex.EncodeToString(invitee.PubKey),
			InviteeNodeID: hex.EncodeToString(invitee.ID[:]),
			InviteID:      hex.EncodeToString(inviteID),
			ExpiresAt:     expiresAt,
			Scope:         scope,
			Approvals:     []proto.InviteApproval{approvalA, approvalC},
		}
		data, err := proto.EncodeInviteBundleMsg(msg)
		if err != nil {
			t.Fatalf("encode invite bundle failed: %v", err)
		}
		if err := recvPlainToReceiver(receiver, st, checker, data); err != nil {
			t.Fatalf("invite bundle recv failed: %v", err)
		}
		if err := recvPlainToReceiver(receiver, st, checker, data); err == nil {
			t.Fatalf("expected invite bundle replay rejection")
		}
	})
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
