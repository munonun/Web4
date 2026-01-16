// internal/crypto/crypto.go
package crypto

import (
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"
)

// -----------------------------------------------------------------------------
// Web4 Crypto Stack v0.0.3
//
// 목표:
// - 고정 스위트: RSA-PSS + X25519 + XChaCha20-Poly1305 + SHA3-256
// - RSA는 서명 전용, X25519는 ephemeral only
// - HMAC/HKDF 제거, SHA3-256 기반 KDF만 사용
// -----------------------------------------------------------------------------

const RSABits = 4096

const (
	// XChaCha20-Poly1305 sizes
	XKeySize   = chacha20poly1305.KeySize    // 32
	XNonceSize = chacha20poly1305.NonceSizeX // 24
)

// -----------------------------------------------------------------------------
// SHA-3
// -----------------------------------------------------------------------------

func SHA3_256(msg []byte) []byte {
	sum := sha3.Sum256(msg)
	return sum[:]
}

func KDF(label string, parts ...[]byte) []byte {
	buf := make([]byte, 0, len(label))
	buf = append(buf, []byte(label)...)
	for _, p := range parts {
		buf = append(buf, p...)
	}
	return SHA3_256(buf)
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

func XSealWithNonce(key32, nonce24, plaintext, aad []byte) ([]byte, error) {
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
	return aead.Seal(nil, nonce24, plaintext, aad), nil
}

// -----------------------------------------------------------------------------
// X25519 ephemeral helpers (optional)
// -----------------------------------------------------------------------------

type Ephemeral struct {
	priv      *ecdh.PrivateKey
	privBytes []byte
	pub       []byte
	destroyed bool
}

func (e *Ephemeral) String() string {
	return "Ephemeral{REDACTED}"
}

func (e *Ephemeral) GoString() string {
	return "crypto.Ephemeral{REDACTED}"
}

func (e *Ephemeral) Public() ([]byte, error) {
	if e == nil || e.destroyed {
		return nil, errors.New("ephemeral key destroyed")
	}
	out := make([]byte, len(e.pub))
	copy(out, e.pub)
	return out, nil
}

func (e *Ephemeral) Shared(peerPub []byte) ([]byte, error) {
	if e == nil || e.destroyed {
		return nil, errors.New("ephemeral key destroyed")
	}
	if len(peerPub) == 0 {
		return nil, errors.New("empty key material")
	}
	pub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, err
	}
	return e.priv.ECDH(pub)
}

func (e *Ephemeral) Destroy() {
	if e == nil || e.destroyed {
		return
	}
	for i := range e.privBytes {
		e.privBytes[i] = 0
	}
	for i := range e.pub {
		e.pub[i] = 0
	}
	e.priv = nil
	e.destroyed = true
}

func GenerateEphemeral() (*Ephemeral, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	privBytes := priv.Bytes()
	privCopy := make([]byte, len(privBytes))
	copy(privCopy, privBytes)
	pubBytes := priv.PublicKey().Bytes()
	pubCopy := make([]byte, len(pubBytes))
	copy(pubCopy, pubBytes)
	return &Ephemeral{priv: priv, privBytes: privCopy, pub: pubCopy}, nil
}

func X25519Shared(privKey, peerPub []byte) ([]byte, error) {
	if len(privKey) == 0 || len(peerPub) == 0 {
		return nil, errors.New("empty key material")
	}
	priv, err := ecdh.X25519().NewPrivateKey(privKey)
	if err != nil {
		return nil, err
	}
	pub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(pub)
}

func DeriveShared(privKey, peerPub []byte) ([]byte, error) {
	if len(privKey) == 0 || len(peerPub) == 0 {
		return nil, errors.New("empty key material")
	}
	priv, err := ecdh.X25519().NewPrivateKey(privKey)
	if err != nil {
		return nil, err
	}
	pub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	return shared, nil
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
// MVP 호환 API (현재는 RSA-PSS를 서명 백엔드로 사용)
// -----------------------------------------------------------------------------

func GenKeypair() ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, RSABits)
	if err != nil {
		return nil, nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	return pubDER, privDER, nil
}

func Sign(priv []byte, digest []byte) []byte {
	sig, err := SignDigest(priv, digest)
	if err != nil {
		return nil
	}
	return sig
}

func SignDigest(priv []byte, digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, errors.New("bad digest size")
	}
	key, err := ParseRSAPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return rsa.SignPSS(rand.Reader, key, crypto.SHA3_256, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
}

func Verify(pub []byte, digest []byte, sig []byte) bool {
	return VerifyDigest(pub, digest, sig)
}

func VerifyDigest(pub []byte, digest []byte, sig []byte) bool {
	if len(digest) != 32 {
		return false
	}
	key, err := ParseRSAPublicKey(pub)
	if err != nil {
		return false
	}
	return rsa.VerifyPSS(key, crypto.SHA3_256, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
}

func ParseRSAPublicKey(pub []byte) (*rsa.PublicKey, error) {
	key, err := x509.ParsePKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not rsa public key")
	}
	return rsaKey, nil
}

func ParseRSAPrivateKey(priv []byte) (*rsa.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not rsa private key")
	}
	return rsaKey, nil
}

func IsRSAPublicKey(pub []byte) bool {
	_, err := ParseRSAPublicKey(pub)
	return err == nil
}

func IsRSAPrivateKey(priv []byte) bool {
	_, err := ParseRSAPrivateKey(priv)
	return err == nil
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
