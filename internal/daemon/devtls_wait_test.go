package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"web4mvp/internal/network"
)

func TestWaitDevTLSCAFailsWhenCertProvidedWithoutKey(t *testing.T) {
	tmp := t.TempDir()
	certPath, _, err := network.GenerateDeterministicDevTLSCA(tmp, "127.0.0.1")
	if err != nil {
		t.Fatalf("GenerateDeterministicDevTLSCA: %v", err)
	}

	t.Setenv("WEB4_DEVTLS_CA_CERT_PATH", certPath)
	t.Setenv("WEB4_DEVTLS_CA_KEY_PATH", filepath.Join(tmp, "missing_key.pem"))

	err = waitDevTLSCA(context.Background(), tmp, 100*time.Millisecond)
	if err == nil {
		t.Fatalf("expected waitDevTLSCA to fail when key is missing")
	}
}

func TestWaitDevTLSCASucceedsWhenCertAndKeyProvided(t *testing.T) {
	tmp := t.TempDir()
	certPath, keyPath, err := network.GenerateDeterministicDevTLSCA(tmp, "127.0.0.1")
	if err != nil {
		t.Fatalf("GenerateDeterministicDevTLSCA: %v", err)
	}
	if fi, err := os.Stat(certPath); err != nil || fi.Size() == 0 {
		t.Fatalf("cert not ready: %v", err)
	}
	if fi, err := os.Stat(keyPath); err != nil || fi.Size() == 0 {
		t.Fatalf("key not ready: %v", err)
	}

	t.Setenv("WEB4_DEVTLS_CA_CERT_PATH", certPath)
	t.Setenv("WEB4_DEVTLS_CA_KEY_PATH", keyPath)

	if err := waitDevTLSCA(context.Background(), tmp, 500*time.Millisecond); err != nil {
		t.Fatalf("waitDevTLSCA: %v", err)
	}
}
