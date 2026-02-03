package main

import (
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"crypto/x509"

	"web4mvp/internal/wallet"
)

func TestWalletIdentityPersistence(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".web4mvp")
	self1, err := loadNode(root)
	if err != nil {
		t.Fatalf("load node: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "node_id.hex")); err != nil {
		t.Fatalf("node_id.hex missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "id_key")); err != nil {
		t.Fatalf("id_key missing: %v", err)
	}
	self2, err := loadNode(root)
	if err != nil {
		t.Fatalf("load node: %v", err)
	}
	if self1.ID != self2.ID {
		t.Fatalf("expected stable node id across runs")
	}
}

func TestWalletExportImportRoundTrip(t *testing.T) {
	root1 := filepath.Join(t.TempDir(), ".web4mvp")
	self1, err := loadNode(root1)
	if err != nil {
		t.Fatalf("load node: %v", err)
	}
	out := filepath.Join(t.TempDir(), "wallet.json")
	if err := exportWallet(root1, out); err != nil {
		t.Fatalf("export wallet: %v", err)
	}
	root2 := filepath.Join(t.TempDir(), ".web4mvp")
	if err := importWallet(root2, out, false); err != nil {
		t.Fatalf("import wallet: %v", err)
	}
	self2, err := loadNode(root2)
	if err != nil {
		t.Fatalf("load node: %v", err)
	}
	if self1.ID != self2.ID {
		t.Fatalf("expected node id to match after import")
	}
}

func TestWalletImportRejectsTamperedNodeID(t *testing.T) {
	root1 := filepath.Join(t.TempDir(), ".web4mvp")
	if _, err := loadNode(root1); err != nil {
		t.Fatalf("load node: %v", err)
	}
	out := filepath.Join(t.TempDir(), "wallet.json")
	if err := exportWallet(root1, out); err != nil {
		t.Fatalf("export wallet: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	var payload walletExport
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	payload.NodeIDHex = "00" + payload.NodeIDHex[2:]
	data, _ = json.Marshal(payload)
	tampered := filepath.Join(t.TempDir(), "wallet_bad.json")
	if err := os.WriteFile(tampered, data, 0600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}
	root2 := filepath.Join(t.TempDir(), ".web4mvp")
	if err := importWallet(root2, tampered, false); err == nil {
		t.Fatalf("expected mismatch error")
	}
}

func TestWalletImportAcceptsPKCS1AndPKCS8(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".web4mvp")
	self, err := loadNode(root)
	if err != nil {
		t.Fatalf("load node: %v", err)
	}
	out := filepath.Join(t.TempDir(), "wallet.json")
	if err := exportWallet(root, out); err != nil {
		t.Fatalf("export wallet: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	var payload walletExport
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// PKCS1 private key (already default)
	root1 := filepath.Join(t.TempDir(), ".web4mvp")
	if err := importWallet(root1, out, false); err != nil {
		t.Fatalf("import pkcs1: %v", err)
	}
	self1, _ := loadNode(root1)
	if self.ID != self1.ID {
		t.Fatalf("pkcs1 id mismatch")
	}

	// PKCS8 private key
	block, _ := pem.Decode([]byte(payload.PrivateKeyPEM))
	if block == nil {
		t.Fatalf("decode pem")
	}
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse pkcs1: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	payload.PrivateKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	pkcs8File := filepath.Join(t.TempDir(), "wallet_pkcs8.json")
	data, _ = json.Marshal(payload)
	if err := os.WriteFile(pkcs8File, data, 0600); err != nil {
		t.Fatalf("write pkcs8: %v", err)
	}
	root2 := filepath.Join(t.TempDir(), ".web4mvp")
	if err := importWallet(root2, pkcs8File, false); err != nil {
		t.Fatalf("import pkcs8: %v", err)
	}
	self2, _ := loadNode(root2)
	if self.ID != self2.ID {
		t.Fatalf("pkcs8 id mismatch")
	}
}

func TestWalletRotateResetsStores(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".web4mvp")
	self, err := loadNode(root)
	if err != nil {
		t.Fatalf("load node: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "claims.jsonl"), []byte(`{"id":"x"}`+"\n"), 0600); err != nil {
		t.Fatalf("write claims: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "field.json"), []byte(`{}`), 0600); err != nil {
		t.Fatalf("write field: %v", err)
	}
	oldID := self.ID
	oldIDHex := hex.EncodeToString(oldID[:])

	oldIDStr, newIDStr, cleared, err := rotateWallet(root)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if oldIDStr != oldIDHex {
		t.Fatalf("old id mismatch")
	}
	if newIDStr == oldIDHex {
		t.Fatalf("expected new id after rotate")
	}
	if len(cleared) == 0 {
		t.Fatalf("expected cleared stores")
	}
	self2, err := loadNode(root)
	if err != nil {
		t.Fatalf("load node: %v", err)
	}
	if self2.ID == oldID {
		t.Fatalf("node id did not change")
	}
	claims, err := wallet.NewStore(filepath.Join(root, "claims.jsonl"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	list, err := claims.List(10)
	if err != nil {
		t.Fatalf("claims list: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected empty claims after rotate")
	}
	if _, err := os.Stat(filepath.Join(root, "field.json")); err == nil {
		t.Fatalf("field.json should be cleared")
	}
	if got := len(self2.Members.List()); got != 1 {
		t.Fatalf("expected fresh members store, got %d", got)
	}
}
