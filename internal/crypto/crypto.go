// internal/crypto/crypto.go
package crypto

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"
)

// -----------------------------------------------------------------------------
// Web4 Crypto Stack v0.0.2
//
// 목표:
// - 기존 MVP(main.go) 변경 최소화: GenKeypair/Sign/Verify/SaveKeypair/LoadKeypair 유지
// - Web4 문서 스택 반영: XChaCha20-Poly1305, SHA-3, HMAC-SHA3
// - PQC(MV)는 인터페이스로 분리하고, 당장은 ed25519를 "임시 백엔드"로 사용
//   (즉, MV가 들어갈 자리에 지금은 ed25519가 들어가 있음)
// -----------------------------------------------------------------------------

const (
	// 기존 코드 호환용 (현재는 ed25519 pubkey size)
	PubLen = ed25519.PublicKeySize

	// XChaCha20-Poly1305 sizes
	XKeySize   = chacha20poly1305.KeySize          // 32
	XNonceSize = chacha20poly1305.NonceSizeX       // 24
)

// -----------------------------------------------------------------------------
// SHA-3 / HMAC-SHA3
// -----------------------------------------------------------------------------

func SHA3_256(msg []byte) []byte {
	sum := sha3.Sum256(msg)
	return sum[:]
}

func SHA3_512(msg []byte) []byte {
	sum := sha3.Sum512(msg)
	return sum[:]
}

func HMAC_SHA3_256(key, msg []byte) []byte {
	mac := hmac.New(sha3.New256, key)
	_, _ = mac.Write(msg)
	return mac.Sum(nil)
}

func HMAC_SHA3_512(key, msg []byte) []byte {
	mac := hmac.New(sha3.New512, key)
	_, _ = mac.Write(msg)
	return mac.Sum(nil)
}

// -----------------------------------------------------------------------------
// XChaCha20-Poly1305 AEAD
// -----------------------------------------------------------------------------

// XSeal: 랜덤 nonce(24) 생성 + XChaCha20-Poly1305로 봉인.
// aad는 "헤더/컨텍스트" 같은 인증 데이터(선택).
func XSeal(key32, plaintext, aad []byte) (nonce24 []byte, ciphertext []byte, err error) {
	if len(key32) != XKeySize {
		return nil, nil, fmt.Errorf("bad key size: need %d", XKeySize)
	}
	aead, err := chacha20poly1305.NewX(key32)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, XNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}

	ct := aead.Seal(nil, nonce, plaintext, aad)
	return nonce, ct, nil
}

func XOpen(key32, nonce24, ciphertext, aad []byte) ([]byte, error) {
	if len(key32) != XKeySize {
		return nil, fmt.Errorf("bad key size: need %d", XKeySize)
	}
	if len(nonce24) != XNonceSize {
		return nil, fmt.Errorf("bad nonce size: need %d", XNonceSize)
	}
	aead, err := chacha20poly1305.NewX(key32)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce24, ciphertext, aad)
}

// -----------------------------------------------------------------------------
// MV(PQC) placeholder interface
// -----------------------------------------------------------------------------

type MVSigner interface {
	PublicKey() []byte
	Sign(msg []byte) ([]byte, error)
}

type MVVerifier interface {
	Verify(pub, msg, sig []byte) bool
}

// -----------------------------------------------------------------------------
// MVP 호환 API (현재는 ed25519를 임시 "MV"로 사용)
// -----------------------------------------------------------------------------

func GenKeypair() ([]byte, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	return pub, priv, err
}

// Sign: 현재는 ed25519 서명.
// MVP 단계에서는 "msg를 그대로" 서명해도 되지만,
// Web4 스택 느낌을 살리려면 보통 SHA3_256(msg) 같은 해시-선서명으로 바꾸는 게 좋음.
// (단, 프로토콜 호환 깨지기 쉬우니 여기서는 그대로 둠)
func Sign(priv []byte, msg []byte) []byte {
	return ed25519.Sign(ed25519.PrivateKey(priv), msg)
}

func Verify(pub []byte, msg []byte, sig []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

// -----------------------------------------------------------------------------
// Key storage (기존 호환 유지)
// -----------------------------------------------------------------------------

func SaveKeypair(dir string, pub, priv []byte) error {
	if len(pub) == 0 || len(priv) == 0 {
		return errors.New("empty key")
	}
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
