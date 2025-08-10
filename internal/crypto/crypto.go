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
	var priv, pub [KeySize]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, err
	}
	curve25519.ScalarBaseMult(&pub, &priv)
	return &KeyPair{Public: pub, Private: priv}, nil
}

// DeriveShared derives shared key using ECDH X25519 and HKDF-SHA256 with PSK salt.
func DeriveShared(priv, peerPub, psk []byte) ([]byte, error) {
	var privArr, pubArr [KeySize]byte
	copy(privArr[:], priv)
	copy(pubArr[:], peerPub)
	var shared [KeySize]byte
	curve25519.ScalarMult(&shared, &privArr, &pubArr)
	var info []byte
	kdf := hkdf.New(sha256.New, shared[:], psk, info)
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
