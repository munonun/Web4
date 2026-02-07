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
