package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// Message types
const (
	TypeHandshakeInit   uint8 = 1
	TypeHandshakeResp   uint8 = 2
	TypeHandshakeFinish uint8 = 3
	TypeData            uint8 = 4
	TypeKeepalive       uint8 = 5
	TypeRekey           uint8 = 6
)

// Packet represents generic packet.
type Packet struct {
	Type    uint8
	Counter uint64
	Payload []byte
}

// Encode encodes packet to bytes.
func Encode(p Packet) []byte {
	buf := &bytes.Buffer{}
	buf.WriteByte(p.Type)
	binary.Write(buf, binary.BigEndian, p.Counter)
	buf.Write(p.Payload)
	return buf.Bytes()
}

// Decode decodes bytes into packet.
func Decode(b []byte) (Packet, error) {
	if len(b) < 9 {
		return Packet{}, errors.New("short packet")
	}
	p := Packet{Type: b[0]}
	p.Counter = binary.BigEndian.Uint64(b[1:9])
	p.Payload = b[9:]
	return p, nil
}
