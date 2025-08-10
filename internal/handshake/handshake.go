package handshake

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"time"

	"xiu/internal/crypto"
	"xiu/internal/wire"
)

const (
	cookieSize = 16
)

// Server implements handshake logic and DoS mitigation.
type Server struct {
	psk       []byte
	cookieKey []byte
	mu        sync.Mutex
	pending   map[string]pending
	lastInit  map[string]time.Time
}

type pending struct {
	serverPriv [crypto.KeySize]byte
	clientPub  [crypto.KeySize]byte
	created    time.Time
}

// NewServer creates new handshake server.
func NewServer(psk []byte) *Server {
	ck := make([]byte, crypto.KeySize)
	rand.Read(ck)
	return &Server{psk: psk, cookieKey: ck, pending: make(map[string]pending), lastInit: make(map[string]time.Time)}
}

// HandleInit processes HANDSHAKE_INIT packet.
func (s *Server) HandleInit(addr *net.UDPAddr, pkt wire.Packet) ([]byte, error) {
	if len(pkt.Payload) < crypto.KeySize+crypto.KeySize {
		return nil, errors.New("init payload too short")
	}
	clientPub := pkt.Payload[:crypto.KeySize]
	hmac := pkt.Payload[crypto.KeySize : 2*crypto.KeySize]
	calc := crypto.HMAC(s.psk, clientPub)
	if !hmacEqual(calc, hmac) {
		return nil, errors.New("bad hmac")
	}
	// rate limit
	s.mu.Lock()
	last := s.lastInit[addr.IP.String()]
	if time.Since(last) < time.Second {
		s.mu.Unlock()
		return nil, errors.New("rate limited")
	}
	s.lastInit[addr.IP.String()] = time.Now()
	s.mu.Unlock()
	// generate server key
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	cookie := crypto.HMAC(s.cookieKey, append(addr.IP, clientPub...))[:cookieSize]
	// store pending
	s.mu.Lock()
	s.pending[hex.EncodeToString(cookie)] = pending{serverPriv: kp.Private, clientPub: toArray(clientPub), created: time.Now()}
	s.mu.Unlock()
	payload := append(kp.Public[:], cookie...)
	resp := wire.Encode(wire.Packet{Type: wire.TypeHandshakeResp, Counter: pkt.Counter, Payload: payload})
	return resp, nil
}

// HandleFinish processes HANDSHAKE_FINISH packet.
func (s *Server) HandleFinish(addr *net.UDPAddr, pkt wire.Packet) ([]byte, error) {
	cookie := pkt.Payload
	if len(cookie) != cookieSize {
		return nil, errors.New("bad cookie size")
	}
	key := hex.EncodeToString(cookie)
	s.mu.Lock()
	pend, ok := s.pending[key]
	if ok {
		delete(s.pending, key)
	}
	s.mu.Unlock()
	if !ok {
		return nil, errors.New("unknown cookie")
	}
	shared, err := crypto.DeriveShared(pend.serverPriv[:], pend.clientPub[:], s.psk)
	if err != nil {
		return nil, err
	}
	return shared, nil
}

func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func toArray(b []byte) [crypto.KeySize]byte {
	var arr [crypto.KeySize]byte
	copy(arr[:], b)
	return arr
}
