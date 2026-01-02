// internal/crypto/crypto.go
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

const PubLen = ed25519.PublicKeySize

func GenKeypair() ([]byte, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	return pub, priv, err
}

func Sign(priv []byte, msg []byte) []byte {
	return ed25519.Sign(ed25519.PrivateKey(priv), msg)
}

func Verify(pub []byte, msg []byte, sig []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

func SaveKeypair(dir string, pub, priv []byte) error {
	if err := os.WriteFile(filepath.Join(dir, "pub.hex"), []byte(hex.EncodeToString(pub)), 0600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "priv.hex"), []byte(hex.EncodeToString(priv)), 0600)
}

func LoadKeypair(dir string) ([]byte, []byte, error) {
	pubHex, err := os.ReadFile(filepath.Join(dir, "pub.hex"))
	if err != nil {
		return nil, nil, err
	}
	privHex, err := os.ReadFile(filepath.Join(dir, "priv.hex"))
	if err != nil {
		return nil, nil, err
	}
	pub, err := hex.DecodeString(string(pubHex))
	if err != nil {
		return nil, nil, fmt.Errorf("bad pub.hex")
	}
	priv, err := hex.DecodeString(string(privHex))
	if err != nil {
		return nil, nil, fmt.Errorf("bad priv.hex")
	}
	return pub, priv, nil
}
