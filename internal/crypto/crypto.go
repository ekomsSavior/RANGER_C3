// Package crypto provides cryptographic primitives for the C2 framework.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// KeyPair holds an Ed25519 signing keypair.
type KeyPair struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// GenerateKeyPair creates a new Ed25519 signing keypair.
func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}
	return &KeyPair{Private: priv, Public: pub}, nil
}

// Sign signs data with the private key, including a timestamp and nonce to prevent replay.
func (kp *KeyPair) Sign(data []byte) (signature []byte, nonce string, ts int64, err error) {
	nonceBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonceBytes); err != nil {
		return nil, "", 0, err
	}
	nonce = base64.RawStdEncoding.EncodeToString(nonceBytes)
	ts = time.Now().Unix()
	msg := append(data, []byte(fmt.Sprintf("%d%s", ts, nonce))...)
	sig := ed25519.Sign(kp.Private, msg)
	return sig, nonce, ts, nil
}

// Verify checks an Ed25519 signature with optional replay protection.
// If nonce is empty, only timestamp window is checked.
func Verify(publicKey ed25519.PublicKey, data, sig []byte, nonce string, ts int64, seenNonces map[string]bool) error {
	now := time.Now().Unix()
	if abs(now-ts) > 300 {
		return errors.New("signature timestamp out of window")
	}
	if nonce != "" {
		if len(nonce) < 8 {
			return errors.New("nonce too short")
		}
		if seenNonces != nil {
			if seenNonces[nonce] {
				return errors.New("nonce replay detected")
			}
			seenNonces[nonce] = true
		}
	}
	msg := append(data, []byte(fmt.Sprintf("%d%s", ts, nonce))...)
	if !ed25519.Verify(publicKey, msg, sig) {
		return errors.New("invalid signature")
	}
	return nil
}

// EncryptWithAEAD encrypts plaintext using XChaCha20-Poly1305.
// Returns nonce || ciphertext.
func EncryptWithAEAD(key []byte, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptWithAEAD decrypts using XChaCha20-Poly1305.
// Expects nonce || ciphertext.
func DecryptWithAEAD(key []byte, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonceSize := aead.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return aead.Open(nil, nonce, ciphertext, nil)
}

// DeriveSessionKey derives a 32-byte session key from a shared secret.
func DeriveSessionKey(secret []byte, salt []byte) []byte {
	h := sha256.Sum256(append(secret, salt...))
	return h[:]
}

// MarshalPublicKey PEM-encodes an Ed25519 public key.
func MarshalPublicKey(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}), nil
}

// UnmarshalPublicKey decodes a PEM-encoded Ed25519 public key.
func UnmarshalPublicKey(pemData []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not an Ed25519 public key")
	}
	return edPub, nil
}

// HexDecode decodes a hex string into bytes.
func HexDecode(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
