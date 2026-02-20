package node

import (
	"errors"
	"os"
	"path/filepath"

	"web4mvp/internal/crypto"
)

const (
	mldsaPubFile   = "mldsa_pub.bin"
	mldsaPrivFile  = "mldsa_priv.bin"
	slhdsaPubFile  = "slhdsa_pub.bin"
	slhdsaPrivFile = "slhdsa_priv.bin"
)

func (n *Node) loadOrCreateMLDSAKeypair() ([]byte, []byte, error) {
	if n == nil {
		return nil, nil, errors.New("missing node")
	}
	n.pqMu.Lock()
	defer n.pqMu.Unlock()
	if len(n.pqPub) > 0 && len(n.pqPriv) > 0 {
		return cloneBytes(n.pqPub), cloneBytes(n.pqPriv), nil
	}
	if n.Home == "" {
		pub, priv, err := crypto.GenMLDSAKeypair()
		if err != nil {
			return nil, nil, err
		}
		n.pqPub = cloneBytes(pub)
		n.pqPriv = cloneBytes(priv)
		return pub, priv, nil
	}
	pubPath := filepath.Join(n.Home, mldsaPubFile)
	privPath := filepath.Join(n.Home, mldsaPrivFile)
	pub, pubErr := os.ReadFile(pubPath)
	priv, privErr := os.ReadFile(privPath)
	if pubErr == nil && privErr == nil && len(pub) > 0 && len(priv) > 0 {
		n.pqPub = cloneBytes(pub)
		n.pqPriv = cloneBytes(priv)
		return pub, priv, nil
	}
	pub, priv, err := crypto.GenMLDSAKeypair()
	if err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(pubPath, pub, 0600); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(privPath, priv, 0600); err != nil {
		return nil, nil, err
	}
	n.pqPub = cloneBytes(pub)
	n.pqPriv = cloneBytes(priv)
	return pub, priv, nil
}

func cloneBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
