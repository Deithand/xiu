# xiu-vpn

Implementation of xiu VPN server and client.

## Server

Example configuration `server.yaml`:

```yaml
listen: ":51828"
psk: "secret"
ip_pool: "10.0.0.0/24"
metrics_addr: ":9090"
```

Run:

```
go run ./cmd/server -config server.yaml
```

Example systemd unit:

```
[Unit]
Description=Xiu VPN Server
After=network.target

[Service]
ExecStart=/usr/bin/xiu-vpn-server -config /etc/xiu/server.yaml
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## Client

Example configuration `client.yaml`:

```yaml
server: "127.0.0.1:51828"
psk: "secret"
interface: "xiu0"
routes:
  - "10.0.0.0/24"
metrics_addr: ":9091"
```

Run:

```
go run ./cmd/client -config client.yaml
```

Example systemd unit:

```
[Unit]
Description=Xiu VPN Client
After=network.target

[Service]
ExecStart=/usr/bin/xiu-vpn-client -config /etc/xiu/client.yaml
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## Development

```
go test ./...
```

