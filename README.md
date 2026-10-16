# ariadns

[فارسی](README.fa.md) · English

A fast, single-binary DNS server written in Go (standard library only, no third-party dependencies).

## Features
- **Protocols:** UDP/TCP on port 53, DNS-over-TLS (853), DNS-over-HTTPS (RFC 8484)
- **Upstreams:** plain, DoT (`tls://ip:853#hostname`); strategies `fastest` (hedged), `race`, `failover`
- **Cache:** sharded LRU, TTL clamping, negative caching, serve-stale, request coalescing
- **Rules:** block lists (hosts/domain files), allow-list overrides, local hosts, per-zone forwarding; block mode `nxdomain | null | refused`
- **Access control:** client allow-list (CIDR) and per-client rate limiting. Refuses to start as an accidental open resolver
- **Dashboard & metrics:** web UI, JSON API, Prometheus `/metrics`, `/healthz`
- **Privacy:** optional client-IP anonymization, query log kept in memory only
- **Ops:** hot reload on `SIGHUP`, graceful shutdown, systemd unit, Docker image

## Install (Linux, systemd)
```bash
curl -fsSL https://raw.githubusercontent.com/davod69/ariadns/main/scripts/install.sh | sudo bash
# serve your LAN (otherwise it listens on 127.0.0.1 only):
curl -fsSL https://raw.githubusercontent.com/davod69/ariadns/main/scripts/install.sh | sudo ARIADNS_ALLOW="192.168.0.0/16" bash
```
Upgrade = run the same command again (config is kept). Uninstall: `ARIADNS_UNINSTALL=1`.

## Quick start
```bash
make build
./bin/ariadns                                 # loopback on 127.0.0.1:5353
./bin/ariadns -config config.example.json -check
sudo ./bin/ariadns -config /etc/ariadns/config.json
```
Test: `dig @127.0.0.1 -p 5353 example.com`

Docker: `docker build -t ariadns . && docker run --network host -v $PWD/config.json:/etc/ariadns/config.json ariadns`

Reload rules without downtime: `kill -HUP $(pidof ariadns)`

## Layout
```
cmd/ariadns     entry point
internal/dnsmsg DNS wire-format parser/builder
internal/cache  sharded LRU cache
internal/upstream, rules, server, stats, web
deploy/         systemd unit
```

## Security notes
- Binding to a non-loopback address requires `access.allow` (or an explicit `access.allow_all`).
- Exposing the dashboard beyond loopback requires `web.token` (>= 16 chars).
- Self-signed TLS is for testing only.

## License
MIT
