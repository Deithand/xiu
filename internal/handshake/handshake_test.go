package handshake

import (
	"net"
	"testing"

	"golang.org/x/crypto/curve25519"

	"xiu/internal/crypto"
	"xiu/internal/wire"
)

func TestHandshake(t *testing.T) {
	psk := []byte("psk")
	srv := NewServer(psk)
	priv := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)
	initPayload := append(pub[:], crypto.HMAC(psk, pub[:])...)
	pkt := wire.Packet{Type: wire.TypeHandshakeInit, Counter: 1, Payload: initPayload}
	addr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}
	resp, err := srv.HandleInit(addr, pkt)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	rpkt, err := wire.Decode(resp)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	serverPub := rpkt.Payload[:32]
	cookie := rpkt.Payload[32:]
	sharedClient, err := crypto.DeriveShared(priv[:], serverPub, psk)
	if err != nil {
		t.Fatalf("client derive: %v", err)
	}
	sharedServer, err := srv.HandleFinish(addr, wire.Packet{Type: wire.TypeHandshakeFinish, Counter: 1, Payload: cookie})
	if err != nil {
		t.Fatalf("finish: %v", err)
	}
	for i := range sharedClient {
		if sharedClient[i] != sharedServer[i] {
			t.Fatalf("key mismatch")
		}
	}
}
