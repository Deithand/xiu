package crypto

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// KeySize is size of symmetric keys
	KeySize = 32
)

// KeyPair represents X25519 key pair.
type KeyPair struct {
	Public  [KeySize]byte
	Private [KeySize]byte
}

// GenerateKeyPair creates new key pair using crypto/rand.
func GenerateKeyPair() (*KeyPair, error) {
	var priv [KeySize]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, err
	}
	pubBytes, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	var pub [KeySize]byte
	copy(pub[:], pubBytes)
	return &KeyPair{Public: pub, Private: priv}, nil
}

// DeriveShared derives shared key using ECDH X25519 and HKDF-SHA256 with PSK salt.
func DeriveShared(priv, peerPub, psk []byte) ([]byte, error) {
	// Use X25519 to derive the raw shared secret
	shared, err := curve25519.X25519(priv, peerPub)
	if err != nil {
		return nil, err
	}
	var info []byte
	kdf := hkdf.New(sha256.New, shared, psk, info)
	key := make([]byte, KeySize)
	if _, err := kdf.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// NewCipher creates new XChaCha20-Poly1305 AEAD with given key.
func NewCipher(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.NewX(key)
}

// Hash computes SHA256 of data.
func Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// HMAC computes HMAC-SHA256.
func HMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
