package crypto

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestAEADRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	msg := []byte("ranger c3 encrypted channel")

	ct, err := EncryptWithAEAD(key, msg)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Equal(ct, msg) {
		t.Fatal("ciphertext equals plaintext")
	}
	pt, err := DecryptWithAEAD(key, ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatalf("round-trip mismatch: %q", pt)
	}
}

func TestAEADTamperDetected(t *testing.T) {
	key := make([]byte, 32)
	msg := []byte("integrity check")

	ct, err := EncryptWithAEAD(key, msg)
	if err != nil {
		t.Fatal(err)
	}
	ct[len(ct)-1] ^= 0xff
	if _, err := DecryptWithAEAD(key, ct); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}

	badKey := make([]byte, 32)
	badKey[0] = 0x42
	ct2, _ := EncryptWithAEAD(key, msg)
	if _, err := DecryptWithAEAD(badKey, ct2); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestKeyPairSignVerify(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("mesh heartbeat payload")
	sig, nonce, ts, err := kp.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	if err := Verify(kp.Public, data, sig, nonce, ts, seen); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Replay with same nonce must fail.
	if err := Verify(kp.Public, data, sig, nonce, ts, seen); err == nil {
		t.Fatal("replay with same nonce accepted")
	}

	// Tampered data must fail.
	if err := Verify(kp.Public, []byte("tampered"), sig, nonce, ts, seen); err == nil {
		t.Fatal("tampered data accepted")
	}
}

func TestDeriveSessionKeyDeterministic(t *testing.T) {
	secret := []byte("shared-secret")
	salt := []byte("dns-tunnel")

	a := DeriveSessionKey(secret, salt)
	b := DeriveSessionKey(secret, salt)
	if !bytes.Equal(a, b) {
		t.Fatal("derivation not deterministic")
	}
	if len(a) != 32 {
		t.Fatalf("derived key length %d", len(a))
	}
	c := DeriveSessionKey(secret, []byte("other"))
	if bytes.Equal(a, c) {
		t.Fatal("different salt produced same key")
	}
}

func TestPublicKeyMarshal(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := MarshalPublicKey(kp.Public)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := UnmarshalPublicKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(ed25519.PublicKey(kp.Public)) {
		t.Fatal("public key round-trip mismatch")
	}
}
