package network

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestClientTLSConfigUsesEnvDevTLSCAPath(t *testing.T) {
	_, der, err := devTLSCert()
	if err != nil {
		t.Fatalf("devTLSCert: %v", err)
	}
	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "devtls_ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(caPath, pemBytes, 0600); err != nil {
		t.Fatalf("write ca: %v", err)
	}

	t.Setenv("WEB4_DEVTLS_CA_PATH", caPath)
	if _, err := clientTLSConfig(false, true, "/nonexistent"); err != nil {
		t.Fatalf("clientTLSConfig with env override: %v", err)
	}
}

func TestClientTLSConfigUsesExplicitDevTLSCAPath(t *testing.T) {
	_, der, err := devTLSCert()
	if err != nil {
		t.Fatalf("devTLSCert: %v", err)
	}
	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "devtls_ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(caPath, pemBytes, 0600); err != nil {
		t.Fatalf("write ca: %v", err)
	}

	if _, err := clientTLSConfig(false, true, caPath); err != nil {
		t.Fatalf("clientTLSConfig with explicit path: %v", err)
	}
}

func TestLoadDevTLSCertFromConfiguredPathsFailsWithoutKey(t *testing.T) {
	_, der, err := devTLSCert()
	if err != nil {
		t.Fatalf("devTLSCert: %v", err)
	}
	tmp := t.TempDir()
	certPath := filepath.Join(tmp, "ca_cert.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, pemBytes, 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	t.Setenv("WEB4_DEVTLS_CA_CERT_PATH", certPath)
	t.Setenv("WEB4_DEVTLS_CA_KEY_PATH", "")
	if _, ok, err := loadDevTLSCertFromConfiguredPaths(); err == nil || ok {
		t.Fatalf("expected configured cert without key to fail, ok=%v err=%v", ok, err)
	}
}

func TestLoadDevTLSCertFromConfiguredPathsSucceedsWithCertAndKey(t *testing.T) {
	tmp := t.TempDir()
	certPath, keyPath, err := GenerateDeterministicDevTLSCA(tmp, "127.0.0.1")
	if err != nil {
		t.Fatalf("GenerateDeterministicDevTLSCA: %v", err)
	}
	t.Setenv("WEB4_DEVTLS_CA_CERT_PATH", certPath)
	t.Setenv("WEB4_DEVTLS_CA_KEY_PATH", keyPath)
	cert, ok, err := loadDevTLSCertFromConfiguredPaths()
	if err != nil {
		t.Fatalf("loadDevTLSCertFromConfiguredPaths: %v", err)
	}
	if !ok {
		t.Fatalf("expected configured cert/key to be used")
	}
	if len(cert.Certificate) == 0 {
		t.Fatalf("expected non-empty certificate chain")
	}
}
