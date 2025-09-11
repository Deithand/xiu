package main

import (
	"flag"
	"net"
	"time"

	"github.com/rs/zerolog/log"

	"xiu/internal/config"
	"xiu/internal/handshake"
	"xiu/internal/wire"
)

func main() {
	cfgPath := flag.String("config", "server.yaml", "config file")
	flag.Parse()
	cfg, err := config.LoadServer(*cfgPath)
	if err != nil {
		log.Fatal().Err(err).Msg("load config")
	}
	addr, err := net.ResolveUDPAddr("udp", cfg.Listen)
	if err != nil {
		log.Fatal().Err(err).Msg("resolve addr")
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal().Err(err).Msg("listen")
	}
	defer conn.Close()
	hs := handshake.NewServer([]byte(cfg.PSK))
	sessions := make(map[string]*session)
	log.Info().Str("listen", cfg.Listen).Msg("server started")
	buf := make([]byte, 65535)
	for {
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		pkt, err := wire.Decode(buf[:n])
		if err != nil {
			continue
		}
		switch pkt.Type {
		case wire.TypeHandshakeInit:
			resp, err := hs.HandleInit(raddr, pkt)
			if err == nil {
				conn.WriteTo(resp, raddr)
			}
		case wire.TypeHandshakeFinish:
			shared, err := hs.HandleFinish(raddr, pkt)
			if err == nil {
				sessions[raddr.String()] = &session{addr: raddr, key: shared, lastSeen: time.Now()}
				log.Info().Str("client", raddr.String()).Msg("session established")
			}
		case wire.TypeKeepalive:
			if s, ok := sessions[raddr.String()]; ok {
				s.lastSeen = time.Now()
			}
		}
	}
}

type session struct {
	addr     *net.UDPAddr
	key      []byte
	lastSeen time.Time
}
