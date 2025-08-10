package main

import (
	"flag"
	"net"
	"time"

	"github.com/rs/zerolog/log"

	"xiu/internal/config"
	"xiu/internal/crypto"
	"xiu/internal/tun"
	"xiu/internal/wire"
)

func main() {
	cfgPath := flag.String("config", "client.yaml", "config file")
	flag.Parse()
	cfg, err := config.LoadClient(*cfgPath)
	if err != nil {
		log.Fatal().Err(err).Msg("load config")
	}
	iface, err := tun.Create(cfg.Interface, 1280)
	if err != nil {
		log.Fatal().Err(err).Msg("tun")
	}
	_ = iface
	addr, err := net.ResolveUDPAddr("udp", cfg.Server)
	if err != nil {
		log.Fatal().Err(err).Msg("server addr")
	}
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		log.Fatal().Err(err).Msg("udp")
	}
	key, err := handshake(conn, addr, []byte(cfg.PSK))
	if err != nil {
		log.Fatal().Err(err).Msg("handshake")
	}
	log.Info().Msg("session established")
	ticker := time.NewTicker(25 * time.Second)
	go func() {
		for range ticker.C {
			msg := wire.Encode(wire.Packet{Type: wire.TypeKeepalive})
			conn.WriteTo(msg, addr)
		}
	}()
	buf := make([]byte, 65535)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		pkt, err := wire.Decode(buf[:n])
		if err != nil {
			continue
		}
		if pkt.Type == wire.TypeRekey {
			key, err = handshake(conn, addr, []byte(cfg.PSK))
			if err != nil {
				log.Error().Err(err).Msg("rehandshake")
			} else {
				log.Info().Msg("rekeyed")
			}
			_ = key
		}
	}
}

func handshake(conn *net.UDPConn, addr *net.UDPAddr, psk []byte) ([]byte, error) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	initPayload := append(kp.Public[:], crypto.HMAC(psk, kp.Public[:])...)
	init := wire.Encode(wire.Packet{Type: wire.TypeHandshakeInit, Payload: initPayload})
	if _, err := conn.WriteTo(init, addr); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}
	pkt, err := wire.Decode(buf[:n])
	if err != nil {
		return nil, err
	}
	serverPub := pkt.Payload[:32]
	cookie := pkt.Payload[32:]
	fin := wire.Encode(wire.Packet{Type: wire.TypeHandshakeFinish, Payload: cookie})
	if _, err := conn.WriteTo(fin, addr); err != nil {
		return nil, err
	}
	key, err := crypto.DeriveShared(kp.Private[:], serverPub, psk)
	if err != nil {
		return nil, err
	}
	return key, nil
}
