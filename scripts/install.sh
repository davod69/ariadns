#!/usr/bin/env bash
# ariadns installer: one command to install or upgrade (Linux + systemd).
#   curl -fsSL https://raw.githubusercontent.com/davod69/ariadns/main/scripts/install.sh | sudo bash
# Optional environment variables:
#   ARIADNS_PUBLIC_IP=1.2.3.4   server address clients connect to (default: auto-detected)
#   ARIADNS_ALLOW="a,b"         extra networks always allowed to use the DNS (CIDR list)
#   ARIADNS_VERSION=v0.1.5      install a specific release (default: latest)
#   ARIADNS_BINARY=/path/bin    install a local binary instead of downloading
#   ARIADNS_UNINSTALL=1         remove ariadns (config and data are kept)
set -euo pipefail

REPO="davod69/ariadns"
BIN=/usr/local/bin/ariadns
CONF_DIR=/etc/ariadns
CONF="$CONF_DIR/config.json"
DATA_DIR=/var/lib/ariadns
UNIT=/etc/systemd/system/ariadns.service
PANEL_PORT=8080

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (use sudo)"
[ "$(uname -s)" = Linux ] || die "Linux only"
HAS_SYSTEMD=0
command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] && HAS_SYSTEMD=1

if [ "${ARIADNS_UNINSTALL:-0}" = 1 ]; then
  [ "$HAS_SYSTEMD" = 1 ] && { systemctl disable --now ariadns 2>/dev/null || true; }
  rm -f "$UNIT" "$BIN" /usr/local/bin/adns
  [ "$HAS_SYSTEMD" = 1 ] && systemctl daemon-reload
  say "removed. Config ($CONF_DIR) and data ($DATA_DIR) were kept; delete them manually if you want."
  exit 0
fi

case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# ---------------------------------------------------------------- binary
if [ -n "${ARIADNS_BINARY:-}" ]; then
  say "using local binary $ARIADNS_BINARY"
  install -m 0755 "$ARIADNS_BINARY" "$TMP/ariadns"
else
  command -v curl >/dev/null || die "curl is required (apt install curl)"
  if [ -n "${ARIADNS_VERSION:-}" ]; then BASE="https://github.com/$REPO/releases/download/$ARIADNS_VERSION"
  else BASE="https://github.com/$REPO/releases/latest/download"; fi
  say "downloading ariadns ($ARCH)"
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
"$TMP/ariadns" -version >/dev/null || die "the binary does not run on this machine"

# ---------------------------------------------------------------- public IP
detect_ip() {
  local u ip
  for u in https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com; do
    ip=$(curl -4 -fsS --max-time 5 "$u" 2>/dev/null | tr -d '[:space:]') || true
    if printf '%s' "$ip" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then echo "$ip"; return; fi
  done
}
PUBLIC_IP="${ARIADNS_PUBLIC_IP:-}"
[ -n "$PUBLIC_IP" ] || { command -v curl >/dev/null && PUBLIC_IP=$(detect_ip) || true; }
[ -n "$PUBLIC_IP" ] || warn "could not detect the public IP; set it later in the panel (Routing) or with 'adns' option 7"

# ---------------------------------------------------------------- user, files, config
id ariadns >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin ariadns
mkdir -p "$CONF_DIR" "$DATA_DIR"
systemctl stop ariadns 2>/dev/null || true
install -m 0755 "$TMP/ariadns" "$BIN"

if [ -f "$CONF" ] && ! grep -q '"data_dir"' "$CONF"; then
  cp "$CONF" "$CONF.old"; rm -f "$CONF"
  warn "old config format replaced (backup: $CONF.old)"
fi
if [ ! -f "$CONF" ]; then
  ALLOW_JSON=""
  if [ -n "${ARIADNS_ALLOW:-}" ]; then
    ALLOW_JSON="\"allow\": [\"$(printf '%s' "$ARIADNS_ALLOW" | sed 's/ //g; s/,/","/g')\"], "
  fi
  cat > "$CONF" <<CFG
{
  "listen": { "udp": "0.0.0.0:53", "tcp": "0.0.0.0:53" },
  "upstreams": [
    "tls://1.1.1.1:853#cloudflare-dns.com",
    "tls://9.9.9.9:853#dns.quad9.net"
  ],
  "data_dir": "$DATA_DIR",
  "access": { ${ALLOW_JSON}"rate_limit_qps": 100, "rate_burst": 200 },
  "smart": {
    "enabled": true,
    "public_ip": "$PUBLIC_IP",
    "listen_tls": "0.0.0.0:443",
    "listen_http": "0.0.0.0:80",
    "fragment": true,
    "max_relays": 4096
  },
  "panel": { "listen": "0.0.0.0:$PANEL_PORT" },
  "web": { "listen": "127.0.0.1:5380" }
}
CFG
  say "created $CONF"
else
  say "keeping existing $CONF"
fi
chown -R root:ariadns "$CONF_DIR"; chmod 750 "$CONF_DIR"; chmod 640 "$CONF"
"$BIN" -config "$CONF" -check

# Create admin credentials now so the password is shown here, not hidden in the logs.
INIT_OUT=$("$BIN" -config "$CONF" -init)
chown -R ariadns:ariadns "$DATA_DIR"; chmod 750 "$DATA_DIR"

printf '#!/bin/sh\nexec %s -config %s menu\n' "$BIN" "$CONF" > /usr/local/bin/adns
chmod 0755 /usr/local/bin/adns

# ---------------------------------------------------------------- service
if [ "$HAS_SYSTEMD" = 1 ]; then
  port_busy() { ss -H -lntu 2>/dev/null | grep -qE "[:.]$1[[:space:]]"; }
  show_port() { ss -lntup 2>/dev/null | grep -E "[:.]$1[[:space:]]" || true; }
  if port_busy 53 && systemctl is-active --quiet systemd-resolved; then
    say "port 53 is used by systemd-resolved: turning off its DNS stub listener"
    mkdir -p /etc/systemd/resolved.conf.d
    printf '[Resolve]\nDNSStubListener=no\n' > /etc/systemd/resolved.conf.d/ariadns.conf
    [ -e /run/systemd/resolve/resolv.conf ] && ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    systemctl restart systemd-resolved; sleep 1
  fi
  for p in 53 80 443 "$PANEL_PORT"; do
    if port_busy "$p"; then
      echo "--- port $p is in use by:"; show_port "$p"
      die "port $p is busy. Stop that program (or edit $CONF to use another port) and run the installer again."
    fi
  done

  cat > "$UNIT" <<'SVC'
[Unit]
Description=ariadns DNS server and SNI relay
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/ariadns -config /etc/ariadns/config.json
ExecReload=/bin/kill -HUP $MAINPID
User=ariadns
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/ariadns
ProtectHome=true
PrivateTmp=true
LimitNOFILE=65536
Restart=on-failure

[Install]
WantedBy=multi-user.target
SVC
  systemctl daemon-reload
  systemctl enable ariadns >/dev/null 2>&1
  systemctl restart ariadns
  sleep 1
  if ! systemctl is-active --quiet ariadns; then
    echo "--- service log:"; journalctl -u ariadns -n 20 --no-pager 2>/dev/null || true
    die "ariadns failed to start (see log above)"
  fi

  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    say "opening ports in ufw"
    ufw allow 53 >/dev/null; ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null; ufw allow "$PANEL_PORT/tcp" >/dev/null
  fi

  # Let the administrator use the server straight away from the SSH address.
  OWNER_IP="${SSH_CLIENT:-}"; OWNER_IP="${OWNER_IP%% *}"
  if printf '%s' "$OWNER_IP" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' && [ -r "$DATA_DIR/ctl.token" ]; then
    curl -fsS -X POST http://127.0.0.1:5380/api/subs \
      -H "Authorization: Bearer $(cat "$DATA_DIR/ctl.token")" -H 'Content-Type: application/json' \
      -d "{\"name\":\"owner (ssh $OWNER_IP)\",\"ip\":\"$OWNER_IP\",\"self_rebind\":true}" >/dev/null 2>&1 \
      && say "added your current address $OWNER_IP as a subscriber" || true
  fi
else
  warn "systemd not found: start manually with  $BIN -config $CONF"
fi

cat <<EOF

$(printf '\033[1;32m')================ ariadns is installed ================$(printf '\033[0m')
$INIT_OUT

Next steps:
  1. Open the panel address above in your browser and sign in.
     (If it does not load, open ports 53 udp/tcp, 80, 443 and $PANEL_PORT in your provider's firewall.)
  2. In the panel, add subscribers (their public IP, or send them the portal link).
  3. Each client sets its DNS server to ${PUBLIC_IP:-your server IP}.

Terminal menu:  adns
EOF
