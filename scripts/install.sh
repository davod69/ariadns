#!/usr/bin/env bash
# ariadns installer — one command install/upgrade on Linux (systemd).
#   curl -fsSL https://raw.githubusercontent.com/davod69/ariadns/main/scripts/install.sh | sudo bash
# Options (environment variables):
#   ARIADNS_ALLOW="203.0.113.0/24,..."          networks allowed to query (default: private LAN ranges)
#   ARIADNS_VERSION=v1.0.0                      install a specific release (default: latest)
#   ARIADNS_BINARY=/path/to/ariadns             install a local binary instead of downloading
#   ARIADNS_UNINSTALL=1                         remove ariadns (config in /etc/ariadns is kept)
set -euo pipefail

REPO="davod69/ariadns"
BIN=/usr/local/bin/ariadns
CONF_DIR=/etc/ariadns
UNIT=/etc/systemd/system/ariadns.service

say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (use sudo)"
[ "$(uname -s)" = Linux ] || die "Linux only"
HAS_SYSTEMD=0; command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] && HAS_SYSTEMD=1

if [ "${ARIADNS_UNINSTALL:-0}" = 1 ]; then
  if [ "$HAS_SYSTEMD" = 1 ]; then systemctl disable --now ariadns 2>/dev/null || true; fi
  rm -f "$UNIT" "$BIN"
  [ "$HAS_SYSTEMD" = 1 ] && systemctl daemon-reload
  say "removed. Config kept in $CONF_DIR (delete it manually if you want)."
  exit 0
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

if [ -n "${ARIADNS_BINARY:-}" ]; then
  say "using local binary $ARIADNS_BINARY"
  install -m 0755 "$ARIADNS_BINARY" "$TMP/ariadns"
else
  command -v curl >/dev/null || die "curl is required"
  if [ -n "${ARIADNS_VERSION:-}" ]; then BASE="https://github.com/$REPO/releases/download/$ARIADNS_VERSION"
  else BASE="https://github.com/$REPO/releases/latest/download"; fi
  say "downloading ariadns_linux_$ARCH"
  if curl -fsSL "$BASE/ariadns_linux_$ARCH" -o "$TMP/ariadns" && curl -fsSL "$BASE/checksums.txt" -o "$TMP/checksums.txt"; then
    (cd "$TMP" && grep " ariadns_linux_$ARCH\$" checksums.txt | sed "s/ariadns_linux_$ARCH/ariadns/" | sha256sum -c -) \
      || die "checksum verification failed"
  else
    say "no release found, building from source"
    command -v go >/dev/null && command -v git >/dev/null || die "no release available and go/git are not installed"
    git clone --depth 1 "https://github.com/$REPO" "$TMP/src"
    (cd "$TMP/src" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$TMP/ariadns" ./cmd/ariadns)
  fi
fi
chmod 0755 "$TMP/ariadns"
"$TMP/ariadns" -version >/dev/null || die "downloaded binary does not run on this machine"

id ariadns >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin ariadns
mkdir -p "$CONF_DIR"
install -m 0755 "$TMP/ariadns" "$BIN"

if [ ! -f "$CONF_DIR/config.json" ]; then
  ALLOW_LIST="${ARIADNS_ALLOW:-127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16}"
  ALLOW=$(printf '%s' "$ALLOW_LIST" | sed 's/ //g; s/,/","/g')
  cat > "$CONF_DIR/config.json" <<CFG
{
  "listen": { "udp": "0.0.0.0:53", "tcp": "0.0.0.0:53" },
  "upstreams": [
    "tls://1.1.1.1:853#cloudflare-dns.com",
    "tls://9.9.9.9:853#dns.quad9.net"
  ],
  "access": { "allow": ["$ALLOW"], "rate_limit_qps": 100, "rate_burst": 200 },
  "web": { "listen": "127.0.0.1:5380" }
}
CFG
  say "created $CONF_DIR/config.json (allowed clients: $ALLOW_LIST)"
else
  say "keeping existing $CONF_DIR/config.json"
fi
chown -R root:ariadns "$CONF_DIR"; chmod 750 "$CONF_DIR"; chmod 640 "$CONF_DIR/config.json"
"$BIN" -config "$CONF_DIR/config.json" -check

if [ "$HAS_SYSTEMD" = 1 ]; then
  systemctl stop ariadns 2>/dev/null || true
  port53_busy() { ss -H -lntu 2>/dev/null | grep -qE '[:.]53[[:space:]]'; }
  if port53_busy && systemctl is-active --quiet systemd-resolved; then
    say "port 53 is used by systemd-resolved: turning off its DNS stub listener"
    mkdir -p /etc/systemd/resolved.conf.d
    printf '[Resolve]\nDNSStubListener=no\n' > /etc/systemd/resolved.conf.d/ariadns.conf
    [ -e /run/systemd/resolve/resolv.conf ] && ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    systemctl restart systemd-resolved
    sleep 1
  fi
  if port53_busy; then
    echo "--- who is using port 53:"; ss -lntup 2>/dev/null | grep -E '[:.]53[[:space:]]' || true
    die "port 53 is still busy. Stop that program, or change \"listen\" in $CONF_DIR/config.json to another port and re-run."
  fi
  cat > "$UNIT" <<'SVC'
[Unit]
Description=ariadns DNS server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/ariadns -config /etc/ariadns/config.json
ExecReload=/bin/kill -HUP $MAINPID
User=ariadns
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
Restart=on-failure

[Install]
WantedBy=multi-user.target
SVC
  systemctl daemon-reload
  systemctl enable ariadns >/dev/null 2>&1
  systemctl restart ariadns
  sleep 1
  if ! systemctl is-active --quiet ariadns; then
    echo "--- service log:"; journalctl -u ariadns -n 15 --no-pager 2>/dev/null || true
    die "ariadns failed to start (see log above)"
  fi
  say "ariadns is running"
else
  say "systemd not found: run manually with  $BIN -config $CONF_DIR/config.json"
fi
say "done. Test: dig @127.0.0.1 example.com   |   config: $CONF_DIR/config.json   |   logs: journalctl -u ariadns"
