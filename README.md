# ariadns

[فارسی](README.fa.md) · English

A self-hosted **SmartDNS + SNI relay** and DNS server in one static Go binary (standard library only).
Point a client's DNS at your server and the domains you choose (games, AI tools, developer registries, ...) are carried through the server, while everything else resolves normally. Includes a web admin panel on a hidden URL, subscribers with IP / quota / expiry, and a terminal menu.

## Install (Linux with systemd)
```bash
curl -fsSL https://raw.githubusercontent.com/davod69/ariadns/main/scripts/install.sh | sudo bash
```
The installer downloads the release binary (checksum verified), detects the public IP, frees port 53 from `systemd-resolved` if needed, opens ports in `ufw`, starts the service and prints the **panel address and password once**. Re-run it to upgrade (config and data are kept). Open ports `53` (udp+tcp), `80`, `443` and `8080` in your provider's firewall.

Then run **`adns`** for the terminal menu.

## How it works
1. A client asks your server for `store.steampowered.com`.
2. The domain is in an enabled category, so the answer is **your server's IP**.
3. The client connects to your server on 443/80. The relay reads only the TLS SNI (or HTTP Host), connects to the real site and copies bytes in both directions. **TLS is never terminated**, so the server cannot read the traffic.
4. Other domains are resolved through encrypted upstreams (DoT) with a cache.

Safety by design: unknown clients are refused (whitelist), the relay only serves domains in your routing list (never an open proxy), private/loopback destinations are blocked, and the panel lives under a random secret path with a login lockout.

## Features
- **Smart routing:** 9 preset categories (game platforms, online games, anti-cheat, AI, developer registries, streaming, social, cloud gaming, bulk downloads) plus custom domains; toggle in the panel or menu
- **SNI relay:** layer-4, no TLS termination, optional TLS ClientHello fragmentation, concurrency cap
- **Subscribers:** one IP each, traffic quota, expiry, per-user portal link `/sub/<token>` where the user can bind their current IP in one click
- **Admin panel:** random hidden path, PBKDF2 password, session cookies, live statistics
- **Terminal menu:** `adns` (status, subscribers, categories, public IP, password reset, restart, logs, update, uninstall)
- **DNS server:** UDP/TCP/DoT/DoH, sharded LRU cache with serve-stale, block lists, local hosts, per-zone forwarding, rate limiting, Prometheus `/metrics`
- **Ops:** hot reload on `SIGHUP`, graceful shutdown, systemd unit, Docker image, CI and automatic releases

## Configuration
`/etc/ariadns/config.json` (see `config.example.json`). State (subscribers, routing, credentials) is stored in `data_dir` (`/var/lib/ariadns`). Panel TLS is optional (`panel.tls` + `tls.cert_file/key_file`); without it use an SSH tunnel or a reverse proxy if you do not want the password sent in clear text.

## Build
```bash
make build          # ./bin/ariadns
make test
./bin/ariadns -config config.example.json -check
```

## Responsible use
Run it on servers and networks you are authorised to use, and respect the terms of the services you reach through it.

## License
MIT
