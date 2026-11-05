#!/usr/bin/env bash
# =============================================================================
# XTCP-TUN Manager v2.0  (FRP 0.61.1 based IPv4 TUN tunnel: Iran <-> outside)
#
# What changed compared with v1 (all verified in a two-namespace lab):
#  * Firewall: traffic arriving on the tunnel interface is now accepted on BOTH
#    servers (iptables chain XTCP_TUN_IN + "ufw allow in on xtcp0" on the outside
#    server). v1 never did this: with UFW / a default-deny INPUT policy the
#    forwarded ports died (and ping died too if ICMP was filtered).
#  * Agent rewritten: non-blocking I/O (v1 could dead-lock under two-way load),
#    HMAC handshake (a path only counts as "up" after the other side answered),
#    newest authenticated connection wins (v1 served ONE connection and a stale or
#    scanner connection could block the tunnel), fast dead-peer detection,
#    reconnect backoff resets, paths are retried from the best one.
#  * Port forwarding no longer depends on detecting the WAN interface.
#  * The "wss" transport was removed: frps cannot terminate wss by itself
#    (frpc fails with "unexpected EOF"); use websocket instead.
#  * modprobe failure no longer kills the install; errors no longer close the menu.
#  * New: option 13 (test tunnel), 14 (repair / upgrade in place), subnet-conflict
#    check, "relay" mode (no UDP needed), frps hardened (allowPorts/maxPortsPerClient).
# =============================================================================
set -Eeuo pipefail

SCRIPT_VERSION="2.0"
FRP_VERSION="0.61.1"
BASE_DIR="${XTCP_BASE_DIR:-/opt/xtcp-tun}"
CONF_DIR="${XTCP_CONF_DIR:-/etc/xtcp-tun}"
LOG_DIR="${XTCP_LOG_DIR:-/var/log/xtcp-tun}"
UNIT_DIR="${XTCP_UNIT_DIR:-/etc/systemd/system}"
STATE_FILE="${XTCP_STATE_FILE:-/run/xtcp-tun/agent.json}"
MANAGER_PATH="${XTCP_MANAGER_PATH:-/usr/local/sbin/xtcp-tun-manager}"
AGENT_PATH="$BASE_DIR/tun-agent.py"
TUN_DEV="xtcp0"
IRAN_TUN_IP="10.0.0.1"
OUTSIDE_TUN_IP="10.0.0.2"
FRPS_PORT="47000"
PIPE_SERVER_PORT="17000"
PIPE_VISITOR_PORT="17001"
MTU="1280"
# Fixed TCP MSS for forwarded connections that cross the tunnel: 1280 (MTU) - 40.
TUNNEL_MSS="1240"

# Fixed shared credentials (same on both servers). Anyone holding a copy of this
# script knows them - fine for a private pair, change them (or export
# XTCP_FRP_TOKEN / XTCP_SECRET on BOTH servers before installing) if the script is
# shared. The agent handshake uses the XTCP secret.
DEFAULT_FRP_TOKEN="${XTCP_FRP_TOKEN:-740ef87eef4da026d23581899eac95a2015c6eb3d227040d18c28d5ddc86f92d}"
DEFAULT_XTCP_SECRET="${XTCP_SECRET:-81fdeae86511c25c380b37e6e20ceffa1cb13f7d0edff61bf08f86eb78db187b}"

# STUN server both frpc instances use for XTCP (UDP hole punching). If it is not
# reachable from Iran, XTCP simply falls back to the relay (stcp) path.
NAT_HOLE_STUN_SERVER="${XTCP_STUN_SERVER:-stun.easyvoip.com:3478}"
XTCP_FALLBACK_TIMEOUT_MS="1500"

# Independent fallback paths straight off frps (work even if the frpc<->frps
# control channel is blocked). The agent handshake keeps strangers out, but the
# payload on these two paths is NOT encrypted - last-resort paths only.
TCP_FALLBACK_PORT="47001"
TCPMUX_PORT="47002"
TCPMUX_DOMAIN="xtcp-l3"

log() { printf '\n\033[1;32m[XTCP-TUN]\033[0m %s\n' "$*"; }
warn() { printf '\n\033[1;33m[WARNING]\033[0m %s\n' "$*" >&2; }
die() { printf '\n\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }
require_root() { [[ "${EUID}" -eq 0 ]] || die "Run this script as root or with sudo."; }

valid_ipv4() {
  python3 - "$1" <<'PY' >/dev/null 2>&1
import ipaddress, sys
try:
    ipaddress.IPv4Address(sys.argv[1])
except Exception:
    raise SystemExit(1)
PY
}
valid_port() {
  [[ "${1:-}" =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 ))
}

get_role() { cat "$CONF_DIR/role" 2>/dev/null || true; }
peer_tun_ip() {
  case "$(get_role)" in
    iran) printf '%s' "$OUTSIDE_TUN_IP" ;;
    outside) printf '%s' "$IRAN_TUN_IP" ;;
  esac
}
ufw_active() {
  command -v ufw >/dev/null 2>&1 || return 1
  local out
  out="$(ufw status 2>/dev/null || true)"
  [[ "$out" == *"Status: active"* ]]
}
ufw_has_allow_for() {
  local out
  out="$(ufw status 2>/dev/null || true)"
  awk -v ip="$1" 'index($0, ip) && /ALLOW/ {f=1} END{exit !f}' <<<"$out"
}

# Ports the script's own channels need; a forward must never target them.
is_reserved_port() {
  case "${1:-}" in
    "$FRPS_PORT"|"$TCP_FALLBACK_PORT"|"$TCPMUX_PORT") return 0 ;;
    *) return 1 ;;
  esac
}

port_listening() {
  [[ -n "$(ss -Htln "( sport = :$1 )" 2>/dev/null || true)" ]]
}

wait_for_tun_interface() {
  local max="${1:-15}" tries=0
  until ip link show dev "$TUN_DEV" >/dev/null 2>&1; do
    (( tries < max )) || return 1
    sleep 1
    tries=$((tries + 1))
  done
  return 0
}

detect_ssh_ports() {
  local ports
  ports="$(ss -Htlnp 2>/dev/null | awk '/sshd/ {print $4}' | sed -E 's/.*:([0-9]+)$/\1/' | sort -u || true)"
  if [[ -z "$ports" ]]; then printf '22\n'; else printf '%s\n' "$ports"; fi
}

confirm_not_ssh_port() {
  local listen="$1" ssh_ports p confirm
  ssh_ports="$(detect_ssh_ports)"
  for p in $ssh_ports; do
    if [[ "$listen" == "$p" ]]; then
      warn "Port $listen looks like sshd's own port on this server. Forwarding it through the tunnel will take new SSH connections away from this box - you could lock yourself out."
      read -rp "Type YES to forward it anyway, or press Enter to skip this port: " confirm
      [[ "$confirm" == "YES" ]] || return 1
      break
    fi
  done
  return 0
}

choose_transport_protocol() {
  local choice
  printf '\nConnection protocol between the two servers (frpc -> frps):\n'
  printf '  1) tcp        - default, most stable, recommended\n'
  printf '  2) kcp        - UDP-based, can lower latency, less reliable through strict firewalls\n'
  printf '  3) quic       - UDP-based, modern, needs solid UDP reachability\n'
  printf '  4) websocket  - ws: TCP + HTTP upgrade, blends in with ordinary web traffic\n'
  read -rp "Choice [1]: " choice
  case "${choice:-1}" in
    1) CHOSEN_TRANSPORT_PROTOCOL="tcp" ;;
    2) CHOSEN_TRANSPORT_PROTOCOL="kcp" ;;
    3) CHOSEN_TRANSPORT_PROTOCOL="quic" ;;
    4) CHOSEN_TRANSPORT_PROTOCOL="websocket" ;;
    *) warn "Invalid choice; using tcp."; CHOSEN_TRANSPORT_PROTOCOL="tcp" ;;
  esac
  log "Transport protocol: $CHOSEN_TRANSPORT_PROTOCOL (must be the same on the other server)."
}

choose_mode() {
  local choice
  printf '\nPath mode on the outside server:\n'
  printf '  1) auto  - try direct UDP hole punching first (xtcp: quic -> kcp), then relay through frps (stcp)\n'
  printf '  2) relay - always relay through frps over TCP; no UDP/STUN involved, most predictable\n'
  read -rp "Choice [1]: " choice
  case "${choice:-1}" in
    2) CHOSEN_MODE="relay" ;;
    *) CHOSEN_MODE="auto" ;;
  esac
  log "Path mode: $CHOSEN_MODE"
}

# Makes sure the TUN device exists. A failing modprobe (containers, built-in
# driver) must NOT abort the install - with `set -e` the old `a && b` form did.
ensure_tun_device() {
  if command -v modprobe >/dev/null 2>&1; then
    modprobe tun >/dev/null 2>&1 || true
  fi
  if [[ ! -e /dev/net/tun ]]; then
    mkdir -p /dev/net 2>/dev/null || true
    mknod -m 600 /dev/net/tun c 10 200 2>/dev/null || true
  fi
  if [[ -d /etc/modules-load.d && ! -f /etc/modules-load.d/xtcp-tun.conf ]]; then
    printf 'tun\n' > /etc/modules-load.d/xtcp-tun.conf 2>/dev/null || true
  fi
  if [[ ! -e /dev/net/tun ]]; then
    warn "/dev/net/tun is missing. On a container (OpenVZ/LXC) the hosting provider must enable TUN/TAP for this server. The install continues, but the tunnel interface will not come up until that is fixed (see option 11 logs and option 3 status)."
  fi
}

install_self_copy() {
  local self_path target
  self_path="$(readlink -f -- "$0" 2>/dev/null || printf '%s' "$0")"
  [[ -f "$self_path" ]] || die "Could not find the script file; save xtcp-tun-manager.sh on the server first, then run it with bash."
  target="$(readlink -f -- "$MANAGER_PATH" 2>/dev/null || printf '%s' "$MANAGER_PATH")"
  if [[ "$self_path" != "$target" ]]; then
    mkdir -p "$(dirname "$MANAGER_PATH")"
    install -m 0755 "$self_path" "$MANAGER_PATH"
  fi
}

install_packages() {
  command -v apt-get >/dev/null 2>&1 || die "This version currently targets Ubuntu/Debian only."
  local spec cmd pkg missing=()
  for spec in curl:curl ip:iproute2 ss:iproute2 iptables:iptables python3:python3 ping:iputils-ping tar:tar; do
    cmd="${spec%%:*}"; pkg="${spec##*:}"
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$pkg")
  done
  [[ -f /etc/ssl/certs/ca-certificates.crt ]] || missing+=(ca-certificates)
  if (( ${#missing[@]} > 0 )); then
    log "Installing missing packages: ${missing[*]}"
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"; then
      warn "apt-get install failed; refreshing the package index once and retrying..."
      apt-get update || warn "apt-get update failed (mirror unreachable?)"
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}" \
        || die "Could not install: ${missing[*]} - install them manually, then run this script again."
    fi
  else
    log "All required packages are already installed."
  fi
  mkdir -p "$BASE_DIR" "$CONF_DIR" "$LOG_DIR"
  chmod 700 "$CONF_DIR"
  chmod 755 "$BASE_DIR" "$LOG_DIR"
  ensure_tun_device
  install_self_copy
  PYTHON_BIN="$(command -v python3)"
  [[ -n "$PYTHON_BIN" ]] || die "python3 was installed but could not be found on PATH."
}

install_frp() {
  local need_frpc="$1" need_frps="$2" machine_arch arch tmp archive extracted url cand src_dir
  machine_arch="$(uname -m)"
  case "$machine_arch" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) die "Unsupported architecture: $machine_arch (amd64 and arm64 only)" ;;
  esac
  tmp="$(mktemp -d /tmp/xtcp-frp.XXXXXX)"
  archive="$tmp/frp.tar.gz"
  url="https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/frp_${FRP_VERSION}_linux_${arch}.tar.gz"
  src_dir="$(dirname -- "$(readlink -f -- "$0" 2>/dev/null || printf '%s' "$0")")"
  # Offline friendly: a tarball already on this server is used instead of GitHub.
  local have_local=no
  for cand in "${XTCP_FRP_TARBALL:-}" "$src_dir/frp_${FRP_VERSION}_linux_${arch}.tar.gz" \
              "/root/frp_${FRP_VERSION}_linux_${arch}.tar.gz" "/tmp/frp_${FRP_VERSION}_linux_${arch}.tar.gz"; do
    if [[ -n "$cand" && -f "$cand" ]]; then cp "$cand" "$archive"; have_local=yes; log "Using the local FRP archive: $cand"; break; fi
  done
  if [[ "$have_local" == no ]]; then
    log "Downloading FRP ${FRP_VERSION} for Linux/${arch} from the official repository..."
    if ! curl -fL --retry 3 --connect-timeout 15 --max-time 240 "$url" -o "$archive"; then
      rm -rf "$tmp"
      die "FRP download failed. Check HTTPS access to GitHub, or copy frp_${FRP_VERSION}_linux_${arch}.tar.gz next to this script (or set XTCP_FRP_TARBALL=/path) and run again."
    fi
  fi
  tar -tzf "$archive" >/dev/null 2>&1 || { rm -rf "$tmp"; die "The FRP archive is not a valid tarball."; }
  tar -xzf "$archive" -C "$tmp"
  extracted="$tmp/frp_${FRP_VERSION}_linux_${arch}"
  [[ -d "$extracted" ]] || { rm -rf "$tmp"; die "Could not find the FRP version folder inside the archive."; }
  if [[ "$need_frpc" == yes ]]; then
    [[ -x "$extracted/frpc" ]] || { rm -rf "$tmp"; die "The frpc binary is missing from the archive."; }
    install -m 0755 "$extracted/frpc" "$BASE_DIR/frpc"
  fi
  if [[ "$need_frps" == yes ]]; then
    [[ -x "$extracted/frps" ]] || { rm -rf "$tmp"; die "The frps binary is missing from the archive."; }
    install -m 0755 "$extracted/frps" "$BASE_DIR/frps"
  fi
  rm -rf "$tmp"
}

write_agent() {
  mkdir -p "$BASE_DIR"
  cat > "$AGENT_PATH" <<'PY'
@@AGENT_PY@@
PY
  chmod 0755 "$AGENT_PATH"
  python3 -m py_compile "$AGENT_PATH" || die "Syntax check of the TUN agent script failed."
  rm -rf "$BASE_DIR/__pycache__"
}

# frpc-iran must not log in before frps really listens (systemd marks a
# Type=simple unit started the moment it is forked).
write_wait_for_frps_script() {
  cat > "$BASE_DIR/wait-for-frps.sh" <<'SCRIPT_EOF'
#!/usr/bin/env bash
# Usage: wait-for-frps.sh PORT [LOG_DIR]
set -u
port="${1:?usage: wait-for-frps.sh PORT [LOG_DIR]}"
log_dir="${2:-}"
for ((i = 0; i < 30; i++)); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    exec 3>&-
    exit 0
  fi
  sleep 1
done
echo "frps is still not listening on 127.0.0.1:$port after 30s." >&2
echo "Check: systemctl status xtcp-tun-frps.service" >&2
[[ -n "$log_dir" ]] && echo "And:   tail -n 40 $log_dir/frps.log" >&2
echo "A common cause: another process (e.g. another FRP based tunnel script) already holds that port - check: ss -tlnp | grep \":$port\"" >&2
exit 1
SCRIPT_EOF
  chmod 0755 "$BASE_DIR/wait-for-frps.sh"
}

# ---------------------------------------------------------------- firewall (ufw)
setup_ufw_iran() {
  local peer_ip="${1:-}" proto="${2:-tcp}" st
  ufw_active || return 0
  st="$(ufw status 2>/dev/null || true)"
  if ! grep -Eq "(^|[[:space:]])${FRPS_PORT}/tcp.*ALLOW" <<<"$st"; then
    ufw allow "${FRPS_PORT}/tcp" comment 'xtcp-tun-managed' >/dev/null
    printf 'yes\n' > "$CONF_DIR/ufw_added_tcp_control"
    log "UFW: allowed TCP/$FRPS_PORT for the FRP control connection."
  fi
  case "$proto" in
    kcp|quic)
      if ! grep -Eq "(^|[[:space:]])${FRPS_PORT}/udp.*ALLOW" <<<"$st"; then
        ufw allow "${FRPS_PORT}/udp" comment 'xtcp-tun-managed' >/dev/null
        printf 'yes\n' > "$CONF_DIR/ufw_added_udp_control"
        log "UFW: allowed UDP/$FRPS_PORT (transport $proto)."
      fi ;;
  esac
  if [[ -n "$peer_ip" ]] && valid_ipv4 "$peer_ip"; then
    if ! ufw_has_allow_for "$peer_ip"; then
      ufw allow from "$peer_ip" to any proto udp comment 'xtcp-tun-managed' >/dev/null
      ufw allow from "$peer_ip" to any port "$TCP_FALLBACK_PORT" proto tcp comment 'xtcp-tun-managed' >/dev/null
      ufw allow from "$peer_ip" to any port "$TCPMUX_PORT" proto tcp comment 'xtcp-tun-managed' >/dev/null
      printf '%s\n' "$peer_ip" > "$CONF_DIR/ufw_added_udp_peer"
      log "UFW: allowed UDP (XTCP) and TCP/$TCP_FALLBACK_PORT, TCP/$TCPMUX_PORT (fallbacks) from the outside server."
    fi
  else
    warn "UFW is active: XTCP (UDP) and the tcp/tcpmux fallbacks (ports $TCP_FALLBACK_PORT, $TCPMUX_PORT) need inbound access from the outside server. Re-run the Iran install/repair and enter the outside server's IP, or add the rules by hand."
  fi
}

setup_ufw_outside() {
  local iran_ip="$1"
  ufw_active || return 0
  if ! ufw_has_allow_for "$iran_ip"; then
    ufw allow from "$iran_ip" to any proto udp comment 'xtcp-tun-managed' >/dev/null
    printf '%s\n' "$iran_ip" > "$CONF_DIR/ufw_added_udp_peer"
    log "UFW: allowed UDP from the Iran server's public IP."
  fi
  # The forwarded services live behind this interface; without this rule UFW's
  # default-deny drops every forwarded connection (v1 bug).
  ufw allow in on "$TUN_DEV" comment 'xtcp-tun-managed' >/dev/null
  printf 'yes\n' > "$CONF_DIR/ufw_added_tun_iface"
  log "UFW: allowed inbound traffic on the tunnel interface $TUN_DEV."
}

# ---------------------------------------------------------------- systemd units
make_rules_unit() {
  cat > "$UNIT_DIR/xtcp-tun-rules.service" <<EOF2
[Unit]
Description=Persistent firewall / forwarding rules for XTCP-TUN
After=network-online.target xtcp-tun-agent.service
Wants=network-online.target xtcp-tun-agent.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$MANAGER_PATH --apply-rules
ExecReload=$MANAGER_PATH --apply-rules

[Install]
WantedBy=multi-user.target
EOF2
}

make_iran_units() {
  : "${PYTHON_BIN:=$(command -v python3)}"
  cat > "$UNIT_DIR/xtcp-tun-frps.service" <<EOF2
[Unit]
Description=FRP server for XTCP-TUN
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BASE_DIR/frps -c $CONF_DIR/frps.toml
Restart=always
RestartSec=2
LimitNOFILE=1048576
NoNewPrivileges=true
ProtectSystem=full
ReadWritePaths=$LOG_DIR

[Install]
WantedBy=multi-user.target
EOF2
  cat > "$UNIT_DIR/xtcp-tun-agent.service" <<EOF2
[Unit]
Description=IPv4 TUN packet bridge over FRP (Iran)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=notify
RuntimeDirectory=xtcp-tun
Environment=PYTHONUNBUFFERED=1
ExecStartPre=-/usr/bin/env modprobe tun
ExecStart=$PYTHON_BIN $AGENT_PATH server --dev $TUN_DEV --cidr $IRAN_TUN_IP/30 --listen 127.0.0.1:$PIPE_SERVER_PORT --mtu $MTU --secret-file $CONF_DIR/xtcp_secret --state-file $STATE_FILE
Restart=always
RestartSec=2
LimitNOFILE=1048576
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF2
  cat > "$UNIT_DIR/xtcp-tun-frpc-iran.service" <<EOF2
[Unit]
Description=FRP proxy client (Iran side)
After=network-online.target xtcp-tun-frps.service xtcp-tun-agent.service
Requires=xtcp-tun-frps.service xtcp-tun-agent.service
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=$BASE_DIR/wait-for-frps.sh $FRPS_PORT $LOG_DIR
ExecStart=$BASE_DIR/frpc -c $CONF_DIR/frpc-iran.toml
Restart=always
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true
ProtectSystem=full
ReadWritePaths=$LOG_DIR

[Install]
WantedBy=multi-user.target
EOF2
  make_rules_unit
}

make_outside_units() {
  local iran_ip="$1"
  : "${PYTHON_BIN:=$(command -v python3)}"
  cat > "$UNIT_DIR/xtcp-tun-agent.service" <<EOF2
[Unit]
Description=IPv4 TUN packet bridge over FRP (outside side)
After=network-online.target xtcp-tun-frpc-outside.service
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=notify
RuntimeDirectory=xtcp-tun
Environment=PYTHONUNBUFFERED=1
ExecStartPre=-/usr/bin/env modprobe tun
ExecStart=$PYTHON_BIN $AGENT_PATH client --dev $TUN_DEV --cidr $OUTSIDE_TUN_IP/30 --connect 127.0.0.1:$PIPE_VISITOR_PORT --direct-tcp $iran_ip:$TCP_FALLBACK_PORT --tcpmux $iran_ip:$TCPMUX_PORT --tcpmux-host $TCPMUX_DOMAIN --mtu $MTU --secret-file $CONF_DIR/xtcp_secret --state-file $STATE_FILE
Restart=always
RestartSec=2
LimitNOFILE=1048576
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF2
  cat > "$UNIT_DIR/xtcp-tun-frpc-outside.service" <<EOF2
[Unit]
Description=FRP visitor client (outside side)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BASE_DIR/frpc -c $CONF_DIR/frpc-outside.toml
Restart=always
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true
ProtectSystem=full
ReadWritePaths=$LOG_DIR

[Install]
WantedBy=multi-user.target
EOF2
  make_rules_unit
}

# ---------------------------------------------------------------- config files
# Writes everything that depends on the saved settings. Used by install AND repair.
write_iran_files() {
  local iran_ip="$1" proto="$2" frp_token xtcp_secret extra=""
  frp_token="$DEFAULT_FRP_TOKEN"
  xtcp_secret="$DEFAULT_XTCP_SECRET"
  case "$proto" in
    kcp) extra="kcpBindPort = $FRPS_PORT"$'\n' ;;
    quic) extra="quicBindPort = $FRPS_PORT"$'\n' ;;
  esac
  mkdir -p "$CONF_DIR" "$LOG_DIR" "$(dirname "$UNIT_DIR/x")"
  printf 'iran\n' > "$CONF_DIR/role"
  printf '%s\n' "$iran_ip" > "$CONF_DIR/iran_public_ip"
  printf '%s\n' "$frp_token" > "$CONF_DIR/frp_token"
  printf '%s\n' "$xtcp_secret" > "$CONF_DIR/xtcp_secret"
  printf '%s\n' "$proto" > "$CONF_DIR/transport_protocol"
  chmod 600 "$CONF_DIR"/*
  [[ -f "$CONF_DIR/forwards.tsv" ]] || : > "$CONF_DIR/forwards.tsv"
  if [[ ! -f "$CONF_DIR/old_ip_forward" ]]; then sysctl -n net.ipv4.ip_forward > "$CONF_DIR/old_ip_forward"; fi
  printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/90-xtcp-tun.conf
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  # allowPorts/maxPortsPerClient: the token is shared, so a stranger who knows it
  # must not be able to open arbitrary public ports on this server.
  cat > "$CONF_DIR/frps.toml" <<EOF2
bindAddr = "0.0.0.0"
bindPort = $FRPS_PORT
${extra}tcpmuxHTTPConnectPort = $TCPMUX_PORT
auth.method = "token"
auth.token = "$frp_token"
allowPorts = [ { start = $TCP_FALLBACK_PORT, end = $TCP_FALLBACK_PORT } ]
maxPortsPerClient = 1
transport.heartbeatTimeout = 30
transport.tcpKeepalive = 30
log.to = "$LOG_DIR/frps.log"
log.level = "info"
log.maxDays = 3
EOF2
  cat > "$CONF_DIR/frpc-iran.toml" <<EOF2
serverAddr = "127.0.0.1"
serverPort = $FRPS_PORT
transport.protocol = "$proto"
transport.heartbeatInterval = 10
transport.heartbeatTimeout = 30
natHoleStunServer = "$NAT_HOLE_STUN_SERVER"
auth.method = "token"
auth.token = "$frp_token"
log.to = "$LOG_DIR/frpc-iran.log"
log.level = "info"
log.maxDays = 3

# Direct P2P path (UDP hole punching).
[[proxies]]
name = "xtcp-l3"
type = "xtcp"
secretKey = "$xtcp_secret"
localIP = "127.0.0.1"
localPort = $PIPE_SERVER_PORT

# Relay-through-frps path (always works while the control connection is up).
[[proxies]]
name = "xtcp-l3-stcp"
type = "stcp"
secretKey = "$xtcp_secret"
localIP = "127.0.0.1"
localPort = $PIPE_SERVER_PORT

# Public-port fallback; the agent handshake authenticates whoever connects.
[[proxies]]
name = "xtcp-l3-tcp"
type = "tcp"
localIP = "127.0.0.1"
localPort = $PIPE_SERVER_PORT
remotePort = $TCP_FALLBACK_PORT

# Same, via an HTTP CONNECT to frps's tcpmux port.
[[proxies]]
name = "xtcp-l3-tcpmux"
type = "tcpmux"
multiplexer = "httpconnect"
customDomains = ["$TCPMUX_DOMAIN"]
localIP = "127.0.0.1"
localPort = $PIPE_SERVER_PORT
EOF2
  chmod 600 "$CONF_DIR"/*.toml
  make_iran_units
}

write_outside_files() {
  local iran_ip="$1" proto="$2" mode="$3" frp_token xtcp_secret
  frp_token="$DEFAULT_FRP_TOKEN"
  xtcp_secret="$DEFAULT_XTCP_SECRET"
  mkdir -p "$CONF_DIR" "$LOG_DIR"
  printf 'outside\n' > "$CONF_DIR/role"
  printf '%s\n' "$iran_ip" > "$CONF_DIR/iran_public_ip"
  printf '%s\n' "$frp_token" > "$CONF_DIR/frp_token"
  printf '%s\n' "$xtcp_secret" > "$CONF_DIR/xtcp_secret"
  printf '%s\n' "$proto" > "$CONF_DIR/transport_protocol"
  printf '%s\n' "$mode" > "$CONF_DIR/mode"
  chmod 600 "$CONF_DIR"/*
  cat > "$CONF_DIR/frpc-outside.toml" <<EOF2
serverAddr = "$iran_ip"
serverPort = $FRPS_PORT
transport.protocol = "$proto"
transport.heartbeatInterval = 10
transport.heartbeatTimeout = 30
natHoleStunServer = "$NAT_HOLE_STUN_SERVER"
auth.method = "token"
auth.token = "$frp_token"
log.to = "$LOG_DIR/frpc-outside.log"
log.level = "info"
log.maxDays = 3
EOF2
  if [[ "$mode" == relay ]]; then
    cat >> "$CONF_DIR/frpc-outside.toml" <<EOF2

# relay mode: one TCP visitor through frps, no UDP / STUN involved.
[[visitors]]
name = "xtcp-l3-stcp-visitor"
type = "stcp"
serverName = "xtcp-l3-stcp"
secretKey = "$xtcp_secret"
bindAddr = "127.0.0.1"
bindPort = $PIPE_VISITOR_PORT
EOF2
  else
    cat >> "$CONF_DIR/frpc-outside.toml" <<EOF2

# tun-agent connects to 127.0.0.1:$PIPE_VISITOR_PORT (bound by the first visitor).
# Whichever of quic / kcp / relayed stcp succeeds is transparent to it.
# 1) direct P2P over QUIC
[[visitors]]
name = "xtcp-l3-visitor-quic"
type = "xtcp"
serverName = "xtcp-l3"
secretKey = "$xtcp_secret"
bindAddr = "127.0.0.1"
bindPort = $PIPE_VISITOR_PORT
protocol = "quic"
keepTunnelOpen = true
maxRetriesAnHour = 60
minRetryInterval = 15
fallbackTo = "xtcp-l3-visitor-kcp"
fallbackTimeoutMs = $XTCP_FALLBACK_TIMEOUT_MS

# 2) direct P2P over KCP
[[visitors]]
name = "xtcp-l3-visitor-kcp"
type = "xtcp"
serverName = "xtcp-l3"
secretKey = "$xtcp_secret"
bindPort = -1
protocol = "kcp"
keepTunnelOpen = true
maxRetriesAnHour = 60
minRetryInterval = 15
fallbackTo = "xtcp-l3-stcp-visitor"
fallbackTimeoutMs = $XTCP_FALLBACK_TIMEOUT_MS

# 3) guaranteed path: relayed through frps
[[visitors]]
name = "xtcp-l3-stcp-visitor"
type = "stcp"
serverName = "xtcp-l3-stcp"
secretKey = "$xtcp_secret"
bindPort = -1
EOF2
  fi
  chmod 600 "$CONF_DIR"/*.toml
  make_outside_units "$iran_ip"
}

# ---------------------------------------------------------------- pre-flight checks
# Warns when the tunnel /30 collides with something already on this server
# (an address/route in the same range, or a gateway equal to a tunnel IP).
check_tun_subnet() {
  local problems
  problems="$(python3 - "$TUN_DEV" "$IRAN_TUN_IP" "$OUTSIDE_TUN_IP" <<'PY' 2>/dev/null || true
import ipaddress, subprocess, sys
dev, a, b = sys.argv[1:4]
net = ipaddress.ip_network(f"{a}/30", strict=False)
ours = {ipaddress.ip_address(a), ipaddress.ip_address(b)}
bad = []
for line in subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True).stdout.splitlines():
    f = line.split()
    if len(f) < 4 or f[1] == dev:
        continue
    try:
        if ipaddress.ip_interface(f[3]).network.overlaps(net):
            bad.append(f"interface {f[1]} has {f[3]}")
    except ValueError:
        pass
for line in subprocess.run(["ip", "-4", "route", "show", "table", "all"], capture_output=True, text=True).stdout.splitlines():
    f = line.split()
    if not f or f[0] in ("local", "broadcast", "multicast", "unreachable", "blackhole", "prohibit", "throw"):
        continue
    if "dev" in f and f[f.index("dev") + 1] == dev:
        continue
    if "via" in f:
        try:
            if ipaddress.ip_address(f[f.index("via") + 1]) in ours:
                bad.append("route uses a tunnel IP as gateway: " + line.strip())
        except ValueError:
            pass
    if f[0] != "default":
        try:
            n = ipaddress.ip_network(f[0] if "/" in f[0] else f[0] + "/32", strict=False)
        except ValueError:
            continue
        if n.prefixlen >= 16 and n.overlaps(net):
            bad.append("route " + line.strip())
print("\n".join(dict.fromkeys(bad)))
PY
)"
  [[ -z "$problems" ]] && return 0
  warn "The tunnel subnet $IRAN_TUN_IP/30 overlaps with something on this server:"
  printf '  %s\n' "$problems" >&2
  printf 'Pinging the peer would silently fail (or this server could lose connectivity).\nTo use another subnet, change IRAN_TUN_IP / OUTSIDE_TUN_IP at the top of this script - identically on BOTH servers.\n' >&2
  return 1
}

stop_leftover_services() {
  local s
  for s in xtcp-tun-rules xtcp-tun-frpc-iran xtcp-tun-frpc-outside xtcp-tun-agent xtcp-tun-frps; do
    systemctl stop "$s.service" >/dev/null 2>&1 || true
  done
}

# ---------------------------------------------------------------- status / tests
agent_state_line() {
  python3 - "$STATE_FILE" <<'PY' 2>/dev/null || printf 'unknown||0|0|0||9999\n'
import json, sys, time
d = json.load(open(sys.argv[1]))
now = int(time.time())
print("|".join(str(x) for x in (d.get("state", "?"), d.get("path", ""), now - int(d.get("since", now)),
      d.get("rx_packets", 0), d.get("tx_packets", 0), str(d.get("last_error", "")).replace("|", "/"),
      now - int(d.get("updated", 0)))))
PY
}

print_agent_state() {
  local st path dur rx tx err age
  IFS='|' read -r st path dur rx tx err age <<<"$(agent_state_line)"
  if [[ "$st" == unknown ]]; then
    printf '  agent state: unknown (agent not running yet? see option 11)\n'
    return 0
  fi
  printf '  agent state: %s' "$st"
  [[ -z "$path" ]] || printf ' | path: %s | for %ss' "$path" "$dur"
  printf ' | packets rx %s / tx %s' "$rx" "$tx"
  (( age <= 30 )) || printf ' | (state file is %ss old - agent stuck?)' "$age"
  printf '\n'
  [[ -z "$err" ]] || printf '  last problem: %s\n' "$err"
  if [[ "$path" == direct-tcp || "$path" == tcpmux ]]; then
    printf '  note: this fallback path is NOT encrypted; the frp path (visitor) is the preferred one.\n'
  fi
}

# Prints "OK" and returns 0 when the peer answers a ping through the tunnel.
ping_peer() {
  local peer out recv
  peer="$(peer_tun_ip)"
  [[ -n "$peer" ]] || return 1
  command -v ping >/dev/null 2>&1 || { printf '  ping is not installed (apt-get install iputils-ping)\n'; return 1; }
  out="$(ping -c 3 -W 2 "$peer" 2>&1 || true)"
  recv="$(grep -Eo '[0-9]+ (packets )?received' <<<"$out" | grep -Eo '^[0-9]+' || true)"
  if [[ -n "$recv" && "$recv" -gt 0 ]]; then
    printf '  ping %s through the tunnel: OK (%s/3 replies)\n' "$peer" "$recv"
    return 0
  fi
  printf '  ping %s through the tunnel: NO REPLY\n' "$peer"
  return 1
}

tcp_probe() { timeout 4 bash -c "exec 3<>/dev/tcp/$1/$2" >/dev/null 2>&1; }

status_all() {
  require_root
  if [[ ! -f "$CONF_DIR/role" ]]; then
    printf 'Status: not installed\n'
    return 0
  fi
  local role s
  role="$(get_role)"
  printf '\nRole: %s   (script v%s)\n' "$role" "$SCRIPT_VERSION"
  if [[ -f "$CONF_DIR/transport_protocol" ]]; then printf 'Transport protocol: %s\n' "$(cat "$CONF_DIR/transport_protocol")"; fi
  if [[ -f "$CONF_DIR/mode" ]]; then printf 'Path mode: %s\n' "$(cat "$CONF_DIR/mode")"; fi
  printf '\n--- Tunnel interface ---\n'
  if ! ip -4 addr show dev "$TUN_DEV" 2>/dev/null; then
    printf '  Interface %s does not exist yet.\n' "$TUN_DEV"
    if [[ ! -e /dev/net/tun ]]; then printf '  /dev/net/tun does not exist - TUN is unavailable (try: modprobe tun; on a container the provider must enable it).\n'; fi
  fi
  printf '\n--- Services ---\n'
  for s in xtcp-tun-frps xtcp-tun-agent xtcp-tun-frpc-iran xtcp-tun-frpc-outside xtcp-tun-rules; do
    if systemctl list-unit-files "$s.service" --no-legend 2>/dev/null | grep -q "$s.service"; then
      printf '%-30s %s\n' "$s" "$(systemctl is-active "$s.service" 2>/dev/null || true)"
    fi
  done
  printf '\n--- Tunnel agent ---\n'
  print_agent_state
  ping_peer || true
  printf '\n--- Listening ports (local) ---\n'
  if ! ss -tlnp 2>/dev/null | grep -E ":($FRPS_PORT|$PIPE_SERVER_PORT|$PIPE_VISITOR_PORT|$TCP_FALLBACK_PORT|$TCPMUX_PORT)\b"; then
    printf '  None of the expected ports is listening yet - check option 11 (logs).\n'
  fi
  if [[ "$role" == iran ]]; then
    printf '\n--- Registered forwards (protocol listen-port target-port) ---\n'
    if [[ -s "$CONF_DIR/forwards.tsv" ]]; then sed 's/^/  /' "$CONF_DIR/forwards.tsv"; else printf '  No ports defined yet.\n'; fi
    printf '\n--- iptables NAT ---\n'
    ipt -t nat -S XTCP_TUN_DNAT 2>/dev/null || true
    ipt -t nat -S XTCP_TUN_SNAT 2>/dev/null || true
  fi
  printf '\n--- Firewall rules for the tunnel interface ---\n'
  ipt -S XTCP_TUN_IN 2>/dev/null || printf '  chain XTCP_TUN_IN missing - run option 6 (restart) or 14 (repair)\n'
}

test_tunnel() {
  require_root
  [[ -f "$CONF_DIR/role" ]] || die "Not installed yet."
  local role iran_ip p ok_ping=no st path dur rx tx err age
  role="$(get_role)"
  printf '\n=== Tunnel test (%s side) ===\n' "$role"
  print_agent_state
  IFS='|' read -r st path dur rx tx err age <<<"$(agent_state_line)"
  if [[ "$role" == outside ]]; then
    iran_ip="$(cat "$CONF_DIR/iran_public_ip")"
    printf '\nTCP reachability of the Iran server (%s):\n' "$iran_ip"
    for p in "$FRPS_PORT:frps control" "$TCP_FALLBACK_PORT:tcp fallback" "$TCPMUX_PORT:tcpmux fallback"; do
      if tcp_probe "$iran_ip" "${p%%:*}"; then printf '  %-6s %-16s open\n' "${p%%:*}" "${p#*:}"; else printf '  %-6s %-16s BLOCKED / closed\n' "${p%%:*}" "${p#*:}"; fi
    done
  else
    printf '\nLocal listeners on this (Iran) server:\n'
    for p in "$FRPS_PORT:frps control" "$TCPMUX_PORT:tcpmux" "$PIPE_SERVER_PORT:agent"; do
      if port_listening "${p%%:*}"; then printf '  %-6s %-16s listening\n' "${p%%:*}" "${p#*:}"; else printf '  %-6s %-16s NOT listening\n' "${p%%:*}" "${p#*:}"; fi
    done
  fi
  printf '\n'
  if ping_peer; then ok_ping=yes; fi
  printf '\n'
  if [[ "$ok_ping" == yes ]]; then
    log "Tunnel is working."
    return 0
  fi
  printf 'Diagnosis hints:\n'
  if [[ "$st" != connected ]]; then
    printf '  - The two agents are not connected yet (state: %s).\n' "$st"
    if [[ "$role" == outside ]]; then
      printf '    Check the TCP reachability list above: if every Iran port is BLOCKED, the Iran firewall / provider blocks this server.\n'
      printf '    Then read option 11 (logs): frpc-outside must say "login to server success".\n'
    else
      printf '    Run the same test on the outside server and read option 11 (logs).\n'
    fi
    printf '    "Rejected a connection: bad credentials" in the agent log means the two servers use different secrets.\n'
  else
    printf '  - The agents are connected but ping gets no reply: check the firewall on BOTH servers.\n'
    printf '    Option 6 (restart) / 14 (repair) re-applies the rule that accepts traffic on %s. Also check "iptables -S INPUT" and any provider-level firewall rules.\n' "$TUN_DEV"
  fi
  if ufw_active; then printf '  - UFW is active on this server (the script manages its rules).\n'; fi
  return 1
}

# ---------------------------------------------------------------- install
install_iran() {
  require_root
  [[ ! -f "$CONF_DIR/role" ]] || die "This manager is already installed here (role: $(get_role)). Use option 14 to repair/upgrade, or uninstall first."
  stop_leftover_services
  install_packages
  local p
  for p in "$FRPS_PORT" "$TCP_FALLBACK_PORT" "$TCPMUX_PORT" "$PIPE_SERVER_PORT"; do
    if port_listening "$p"; then
      die "Port $p is already in use by another process (check: ss -tlnp | grep :$p) - most likely another FRP based tunnel script on this same box. Stop it, or change the ports at the top of this script, then try again."
    fi
  done
  if ! check_tun_subnet; then
    local c
    read -rp "Continue anyway? Type YES to continue: " c
    [[ "$c" == YES ]] || die "Cancelled because of the subnet conflict."
  fi
  install_frp yes yes
  write_agent
  write_wait_for_frps_script
  local detected iran_ip peer_ip
  detected="$(curl -4fsS --connect-timeout 5 --max-time 8 https://api.ipify.org 2>/dev/null || true)"
  valid_ipv4 "$detected" || detected=""
  read -rp "Public IPv4 of the Iran server${detected:+ [$detected]}: " iran_ip
  iran_ip="${iran_ip:-$detected}"
  valid_ipv4 "$iran_ip" || die "No valid public IPv4 was entered."
  read -rp "Public IPv4 of the outside server (used for the UFW rules; press Enter to skip): " peer_ip
  if [[ -n "$peer_ip" ]] && ! valid_ipv4 "$peer_ip"; then die "The outside server's IP is not valid."; fi
  choose_transport_protocol
  write_iran_files "$iran_ip" "$CHOSEN_TRANSPORT_PROTOCOL"
  setup_ufw_iran "$peer_ip" "$CHOSEN_TRANSPORT_PROTOCOL"
  systemctl daemon-reload
  systemctl enable --now xtcp-tun-frps.service xtcp-tun-agent.service xtcp-tun-frpc-iran.service xtcp-tun-rules.service
  log "Iran-side install complete. Use this information on the outside server:"
  printf '\n  Iran IP:        %s\n  FRP Token:      %s\n  XTCP SecretKey: %s\n  Protocol:       %s\n\n' "$iran_ip" "$DEFAULT_FRP_TOKEN" "$DEFAULT_XTCP_SECRET" "$CHOSEN_TRANSPORT_PROTOCOL"
  printf 'Open inbound TCP ports %s (control), %s (tcp fallback) and %s (tcpmux fallback) in the datacenter firewall panel too - ideally only for the outside server.\n' "$FRPS_PORT" "$TCP_FALLBACK_PORT" "$TCPMUX_PORT"
  printf 'Now run this script on the outside server, choose option 2 and pick the same protocol (%s).\n' "$CHOSEN_TRANSPORT_PROTOCOL"
  log "Waiting for the tunnel interface ($TUN_DEV) to come up..."
  if wait_for_tun_interface 20; then
    prompt_initial_forwards
  else
    warn "Tunnel interface $TUN_DEV is not up yet; add port forwards later from option 7 (see option 3 / 11)."
  fi
}

install_outside() {
  require_root
  [[ ! -f "$CONF_DIR/role" ]] || die "This manager is already installed here (role: $(get_role)). Use option 14 to repair/upgrade, or uninstall first."
  stop_leftover_services
  install_packages
  if port_listening "$PIPE_VISITOR_PORT"; then
    die "Port $PIPE_VISITOR_PORT is already in use by another process (check: ss -tlnp | grep :$PIPE_VISITOR_PORT)."
  fi
  if ! check_tun_subnet; then
    local c
    read -rp "Continue anyway? Type YES to continue: " c
    [[ "$c" == YES ]] || die "Cancelled because of the subnet conflict."
  fi
  install_frp yes no
  write_agent
  local iran_ip
  read -rp "Public IPv4 of the Iran server: " iran_ip
  valid_ipv4 "$iran_ip" || die "The Iran server's public IPv4 is not valid."
  choose_transport_protocol
  choose_mode
  write_outside_files "$iran_ip" "$CHOSEN_TRANSPORT_PROTOCOL" "$CHOSEN_MODE"
  setup_ufw_outside "$iran_ip"
  systemctl daemon-reload
  systemctl enable --now xtcp-tun-frpc-outside.service xtcp-tun-agent.service xtcp-tun-rules.service
  log "Outside-side install complete. Waiting up to 40s for the tunnel to come up..."
  local i st path dur rx tx err age
  for i in $(seq 1 20); do
    IFS='|' read -r st path dur rx tx err age <<<"$(agent_state_line)"
    [[ "$st" == connected ]] && break
    sleep 2
  done
  printf 'Iran tunnel IP:    %s\nOutside tunnel IP: %s\nProtocol:          %s\n' "$IRAN_TUN_IP" "$OUTSIDE_TUN_IP" "$CHOSEN_TRANSPORT_PROTOCOL"
  test_tunnel || true
}

# Re-creates agent, configs, units and firewall rules from the saved settings.
# Use it to upgrade an older install in place (run it on BOTH servers).
repair_all() {
  require_root
  [[ -f "$CONF_DIR/role" ]] || die "Not installed yet - use option 1 or 2."
  local role iran_ip proto mode
  role="$(get_role)"
  iran_ip="$(cat "$CONF_DIR/iran_public_ip")"
  proto="$(cat "$CONF_DIR/transport_protocol" 2>/dev/null || true)"; proto="${proto:-tcp}"
  mode="$(cat "$CONF_DIR/mode" 2>/dev/null || true)"; mode="${mode:-auto}"
  command -v python3 >/dev/null 2>&1 || die "python3 is required."
  PYTHON_BIN="$(command -v python3)"
  ensure_tun_device
  install_self_copy
  write_agent
  if [[ "$role" == iran ]]; then
    write_wait_for_frps_script
    write_iran_files "$iran_ip" "$proto"
    setup_ufw_iran "" "$proto"
  else
    write_outside_files "$iran_ip" "$proto" "$mode"
    setup_ufw_outside "$iran_ip"
  fi
  systemctl daemon-reload
  if [[ "$role" == iran ]]; then
    systemctl enable xtcp-tun-frps.service xtcp-tun-agent.service xtcp-tun-frpc-iran.service xtcp-tun-rules.service >/dev/null 2>&1
    systemctl restart xtcp-tun-frps.service xtcp-tun-agent.service xtcp-tun-frpc-iran.service xtcp-tun-rules.service
  else
    systemctl enable xtcp-tun-frpc-outside.service xtcp-tun-agent.service xtcp-tun-rules.service >/dev/null 2>&1
    systemctl restart xtcp-tun-frpc-outside.service xtcp-tun-agent.service xtcp-tun-rules.service
  fi
  log "Repair/upgrade finished (role: $role, protocol: $proto). Run the same option on the other server, then use option 13."
}

# ---------------------------------------------------------------- firewall / forwarding
ipt() { iptables -w "$@"; }

# Applies (re-applies) every firewall rule this script owns. Returns non-zero on
# failure - it never relies on `set -e` (which is disabled inside `if apply_rules`).
apply_rules() {
  require_root
  local role
  role="$(get_role)"
  [[ -n "$role" ]] || { log "Not installed; nothing to apply."; return 0; }
  command -v iptables >/dev/null 2>&1 || { warn "iptables is not installed."; return 1; }
  if ! wait_for_tun_interface 5; then
    warn "Interface $TUN_DEV does not exist yet (agent not running, or TUN unavailable). The rules are applied anyway and take effect once it appears."
  fi

  # --- INPUT: let tunnel traffic reach this server (both roles) -----------------
  ipt -N XTCP_TUN_IN 2>/dev/null || true
  ipt -F XTCP_TUN_IN || return 1
  ipt -C INPUT -j XTCP_TUN_IN 2>/dev/null || ipt -I INPUT 1 -j XTCP_TUN_IN || return 1
  if [[ "$role" == outside ]]; then
    ipt -A XTCP_TUN_IN -i "$TUN_DEV" -j ACCEPT || return 1
  else
    ipt -A XTCP_TUN_IN -i "$TUN_DEV" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || return 1
    ipt -A XTCP_TUN_IN -i "$TUN_DEV" -p icmp -j ACCEPT || return 1
  fi
  ipt -A XTCP_TUN_IN -j RETURN || return 1
  if [[ "$role" != iran ]]; then
    log "Firewall: traffic arriving on $TUN_DEV is accepted on this server."
    return 0
  fi

  # --- Iran: DNAT / SNAT / FORWARD / MSS ---------------------------------------
  sysctl -w net.ipv4.ip_forward=1 >/dev/null || return 1
  local spec
  for spec in nat:XTCP_TUN_DNAT nat:XTCP_TUN_SNAT filter:XTCP_TUN_FWD mangle:XTCP_TUN_MSS; do
    ipt -t "${spec%%:*}" -N "${spec##*:}" 2>/dev/null || true
    ipt -t "${spec%%:*}" -F "${spec##*:}" || return 1
  done
  ipt -t nat -C PREROUTING -j XTCP_TUN_DNAT 2>/dev/null || ipt -t nat -I PREROUTING 1 -j XTCP_TUN_DNAT || return 1
  ipt -t nat -C POSTROUTING -o "$TUN_DEV" -j XTCP_TUN_SNAT 2>/dev/null || ipt -t nat -I POSTROUTING 1 -o "$TUN_DEV" -j XTCP_TUN_SNAT || return 1
  ipt -C FORWARD -j XTCP_TUN_FWD 2>/dev/null || ipt -I FORWARD 1 -j XTCP_TUN_FWD || return 1
  ipt -t mangle -C FORWARD -j XTCP_TUN_MSS 2>/dev/null || ipt -t mangle -I FORWARD 1 -j XTCP_TUN_MSS || return 1
  ipt -t mangle -A XTCP_TUN_MSS -o "$TUN_DEV" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$TUNNEL_MSS" \
    || warn "Could not add the TCP MSS clamp (outbound); if some sites fail to load, check MTU/MSS."
  ipt -t mangle -A XTCP_TUN_MSS -i "$TUN_DEV" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$TUNNEL_MSS" \
    || warn "Could not add the TCP MSS clamp (inbound); if some sites fail to load, check MTU/MSS."
  ipt -t mangle -A XTCP_TUN_MSS -j RETURN || return 1
  ipt -A XTCP_TUN_FWD -i "$TUN_DEV" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || return 1
  local proto listen target
  while read -r proto listen target; do
    [[ -n "${proto:-}" ]] || continue
    [[ "$proto" == tcp || "$proto" == udp ]] || continue
    valid_port "$listen" && valid_port "$target" || continue
    if is_reserved_port "$listen"; then
      warn "Skipping forward for port $listen: reserved for this script's own control/fallback channels (control $FRPS_PORT, tcp fallback $TCP_FALLBACK_PORT, tcpmux $TCPMUX_PORT)."
      continue
    fi
    # Match on "destination is this server" instead of on a WAN interface name:
    # no dependence on default-route detection, works with several uplinks.
    ipt -t nat -A XTCP_TUN_DNAT ! -i "$TUN_DEV" -m addrtype --dst-type LOCAL -p "$proto" --dport "$listen" \
      -j DNAT --to-destination "$OUTSIDE_TUN_IP:$target" || return 1
    ipt -t nat -A XTCP_TUN_SNAT -d "$OUTSIDE_TUN_IP" -p "$proto" --dport "$target" \
      -j SNAT --to-source "$IRAN_TUN_IP" || return 1
    ipt -A XTCP_TUN_FWD ! -i "$TUN_DEV" -o "$TUN_DEV" -d "$OUTSIDE_TUN_IP" -p "$proto" --dport "$target" \
      -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT || return 1
  done < "$CONF_DIR/forwards.tsv"
  ipt -A XTCP_TUN_FWD -j RETURN || return 1
  log "Rules applied. DNAT targets $OUTSIDE_TUN_IP, replies are SNATed from $IRAN_TUN_IP, TCP MSS fixed at $TUNNEL_MSS."
}

remove_iptables_rules() {
  command -v iptables >/dev/null 2>&1 || return 0
  while ipt -C INPUT -j XTCP_TUN_IN 2>/dev/null; do ipt -D INPUT -j XTCP_TUN_IN || break; done
  while ipt -t nat -C PREROUTING -j XTCP_TUN_DNAT 2>/dev/null; do ipt -t nat -D PREROUTING -j XTCP_TUN_DNAT || break; done
  while ipt -t nat -C POSTROUTING -o "$TUN_DEV" -j XTCP_TUN_SNAT 2>/dev/null; do ipt -t nat -D POSTROUTING -o "$TUN_DEV" -j XTCP_TUN_SNAT || break; done
  while ipt -C FORWARD -j XTCP_TUN_FWD 2>/dev/null; do ipt -D FORWARD -j XTCP_TUN_FWD || break; done
  while ipt -t mangle -C FORWARD -j XTCP_TUN_MSS 2>/dev/null; do ipt -t mangle -D FORWARD -j XTCP_TUN_MSS || break; done
  ipt -F XTCP_TUN_IN 2>/dev/null || true;            ipt -X XTCP_TUN_IN 2>/dev/null || true
  ipt -t mangle -F XTCP_TUN_MSS 2>/dev/null || true; ipt -t mangle -X XTCP_TUN_MSS 2>/dev/null || true
  ipt -t nat -F XTCP_TUN_DNAT 2>/dev/null || true;   ipt -t nat -X XTCP_TUN_DNAT 2>/dev/null || true
  ipt -t nat -F XTCP_TUN_SNAT 2>/dev/null || true;   ipt -t nat -X XTCP_TUN_SNAT 2>/dev/null || true
  ipt -F XTCP_TUN_FWD 2>/dev/null || true;           ipt -X XTCP_TUN_FWD 2>/dev/null || true
}

service_action() {
  require_root
  [[ -f "$CONF_DIR/role" ]] || die "Not installed yet."
  case "$(get_role)" in
    iran) systemctl "$1" xtcp-tun-frps.service xtcp-tun-agent.service xtcp-tun-frpc-iran.service xtcp-tun-rules.service ;;
    outside) systemctl "$1" xtcp-tun-frpc-outside.service xtcp-tun-agent.service xtcp-tun-rules.service ;;
    *) die "The stored role is not valid." ;;
  esac
}

# "PORT" (target = listen) or "LISTEN:TARGET" -> "listen target"
_parse_port_entry() {
  local raw="$1" listen target
  raw="$(printf '%s' "$raw" | tr -d '[:space:]')"
  [[ -n "$raw" ]] || return 1
  if [[ "$raw" == *:* ]]; then listen="${raw%%:*}"; target="${raw##*:}"; else listen="$raw"; target="$raw"; fi
  valid_port "$listen" || { warn "Invalid listen port skipped: $listen"; return 1; }
  valid_port "$target" || { warn "Invalid target port skipped: $target"; return 1; }
  printf '%s %s\n' "$listen" "$target"
}

# Adds the entries to forwards.tsv and applies; restores the old file if applying fails.
# usage: _add_forward_entries PROTO "ports,csv"   (returns 0 on success)
_add_forward_entries() {
  local proto="$1" ports_input="$2" entry parsed listen target line backup
  local -a added=() entries=()
  backup="$(mktemp)"
  cp "$CONF_DIR/forwards.tsv" "$backup"
  IFS=',' read -ra entries <<< "$ports_input"
  for entry in "${entries[@]}"; do
    parsed="$(_parse_port_entry "$entry")" || continue
    listen="${parsed% *}"
    target="${parsed#* }"
    if is_reserved_port "$listen"; then
      warn "Port $listen is reserved for this script's own channels (control $FRPS_PORT, tcp fallback $TCP_FALLBACK_PORT, tcpmux $TCPMUX_PORT); skipped."
      continue
    fi
    confirm_not_ssh_port "$listen" || { warn "Skipped port $listen."; continue; }
    if awk -v p="$proto" -v l="$listen" '$1==p && $2==l {found=1} END{exit !found}' "$CONF_DIR/forwards.tsv"; then
      warn "A rule for $proto/$listen already exists; skipped."
      continue
    fi
    printf '%s %s %s\n' "$proto" "$listen" "$target" >> "$CONF_DIR/forwards.tsv"
    added+=("$proto $listen $target")
  done
  if (( ${#added[@]} == 0 )); then
    rm -f "$backup"
    warn "No new forwarding rules were added."
    return 1
  fi
  if ! apply_rules; then
    cat "$backup" > "$CONF_DIR/forwards.tsv"
    rm -f "$backup"
    apply_rules >/dev/null 2>&1 || true
    warn "Applying the rules failed; the new entries were rolled back."
    return 1
  fi
  rm -f "$backup"
  log "Added forwarding rule(s):"
  for line in "${added[@]}"; do printf '  %s\n' "$line"; done
  warn "Because of SNAT the outside service sees the source address as $IRAN_TUN_IP (the real client IP is not passed through). The service on the outside server must listen on 0.0.0.0 (or $OUTSIDE_TUN_IP)."
  return 0
}

prompt_initial_forwards() {
  local proto ports_input
  printf '\n'
  read -rp "Port(s) to forward through the tunnel now, comma-separated (e.g. 1080,443 or 1080:1081,443 for a different target port) - Enter to skip and add later from option 7: " ports_input
  [[ -n "$ports_input" ]] || { log "No ports entered; add forwards later from option 7."; return 0; }
  read -rp "Protocol for these ports (tcp/udp) [tcp]: " proto
  proto="${proto,,}"; proto="${proto:-tcp}"
  if [[ "$proto" != tcp && "$proto" != udp ]]; then
    warn "Protocol must be tcp or udp; skipped. Add forwards later from option 7."
    return 0
  fi
  _add_forward_entries "$proto" "$ports_input" || true
}

add_forward() {
  require_root
  [[ "$(get_role)" == iran ]] || die "Adding a forward is only done on the Iran server."
  local proto ports_input
  read -rp "Protocol (tcp/udp): " proto
  proto="${proto,,}"
  [[ "$proto" == tcp || "$proto" == udp ]] || die "Protocol must be tcp or udp."
  read -rp "Port(s) to forward, comma-separated (e.g. 1080,443 or 1080:1081,443 for a different target port): " ports_input
  [[ -n "$ports_input" ]] || die "No ports entered."
  _add_forward_entries "$proto" "$ports_input" || return 1
}

remove_forward() {
  require_root
  [[ "$(get_role)" == iran ]] || die "Removing a forward is only done on the Iran server."
  local proto ports_input entry listen tmp backup
  local -a removed=() notfound=() entries=()
  read -rp "Protocol (tcp/udp): " proto
  proto="${proto,,}"
  [[ "$proto" == tcp || "$proto" == udp ]] || die "Protocol must be tcp or udp."
  read -rp "Listen port(s) to remove, comma-separated (e.g. 1080,443): " ports_input
  [[ -n "$ports_input" ]] || die "No ports entered."
  IFS=',' read -ra entries <<< "$ports_input"
  backup="$(mktemp)"; tmp="$(mktemp)"
  cp "$CONF_DIR/forwards.tsv" "$backup"
  cp "$CONF_DIR/forwards.tsv" "$tmp"
  for entry in "${entries[@]}"; do
    listen="$(printf '%s' "$entry" | tr -d '[:space:]')"
    [[ -n "$listen" ]] || continue
    valid_port "$listen" || { warn "Invalid port skipped: $listen"; continue; }
    if awk -v p="$proto" -v l="$listen" '$1==p && $2==l {found=1} END{exit !found}' "$tmp"; then
      awk -v p="$proto" -v l="$listen" '!( $1==p && $2==l )' "$tmp" > "$tmp.new" && mv "$tmp.new" "$tmp"
      removed+=("$proto/$listen")
    else
      notfound+=("$proto/$listen")
    fi
  done
  if (( ${#removed[@]} == 0 )); then
    rm -f "$tmp" "$backup"
    die "No matching rule(s) were found to remove."
  fi
  cat "$tmp" > "$CONF_DIR/forwards.tsv"
  rm -f "$tmp"
  if ! apply_rules; then
    cat "$backup" > "$CONF_DIR/forwards.tsv"
    rm -f "$backup"
    apply_rules >/dev/null 2>&1 || true
    die "Applying the rules failed; the removal was rolled back and the previous rules are still in place."
  fi
  rm -f "$backup"
  log "Removed: ${removed[*]}"
  if (( ${#notfound[@]} > 0 )); then warn "Not found (skipped): ${notfound[*]}"; fi
}

list_forwards() {
  require_root
  if [[ "$(get_role)" == iran ]]; then
    if [[ -s "$CONF_DIR/forwards.tsv" ]]; then
      printf '\nProto  Listen-port  Target-port\n'
      cat "$CONF_DIR/forwards.tsv"
    else
      printf 'No rules registered.\n'
    fi
  else
    printf 'This option is only available on the Iran side.\n'
  fi
}

show_credentials() {
  require_root
  [[ "$(get_role)" == iran ]] || die "Connection info is only stored on the Iran server."
  local proto
  proto="$(cat "$CONF_DIR/transport_protocol" 2>/dev/null || true)"
  proto="${proto:-tcp}"
  printf '\nIran IP:        %s\nFRP Token:      %s\nXTCP SecretKey: %s\nProtocol:       %s\n\n' \
    "$(cat "$CONF_DIR/iran_public_ip")" "$(cat "$CONF_DIR/frp_token")" "$(cat "$CONF_DIR/xtcp_secret")" "$proto"
}

show_logs() {
  require_root
  [[ -f "$CONF_DIR/role" ]] || die "Not installed yet."
  local role f
  role="$(get_role)"
  printf '\n--- Tunnel agent ---\n'
  print_agent_state
  printf '\n--- Listening ports (local) ---\n'
  if ! ss -tlnp 2>/dev/null | grep -E ":($FRPS_PORT|$PIPE_SERVER_PORT|$PIPE_VISITOR_PORT|$TCP_FALLBACK_PORT|$TCPMUX_PORT)\b"; then
    printf '  None of the expected ports is listening yet.\n'
  fi
  if [[ "$role" == iran ]]; then
    journalctl --no-pager -n 70 -u xtcp-tun-frps.service -u xtcp-tun-agent.service -u xtcp-tun-frpc-iran.service || true
  else
    journalctl --no-pager -n 70 -u xtcp-tun-agent.service -u xtcp-tun-frpc-outside.service || true
  fi
  # frps/frpc write to their own log files, not to journald.
  for f in "$LOG_DIR"/*.log; do
    [[ -f "$f" ]] || continue
    printf '\n--- tail -n 40 %s ---\n' "$f"
    tail -n 40 "$f"
  done
}

uninstall_all() {
  require_root
  if [[ ! -f "$CONF_DIR/role" && ! -d "$BASE_DIR" && ! -f "$UNIT_DIR/xtcp-tun-agent.service" ]]; then
    log "Not installed."
    return 0
  fi
  local old_forward peer confirm
  printf '\nThis will remove the services, XTCP-TUN files, and the firewall rules created by this script.\n'
  read -rp "Type DELETE exactly to confirm: " confirm
  [[ "$confirm" == DELETE ]] || { log "Cancelled."; return 0; }
  remove_iptables_rules
  systemctl disable --now xtcp-tun-rules.service xtcp-tun-frpc-iran.service xtcp-tun-frpc-outside.service xtcp-tun-agent.service xtcp-tun-frps.service >/dev/null 2>&1 || true
  if command -v ufw >/dev/null 2>&1; then
    if [[ -f "$CONF_DIR/ufw_added_tcp_control" ]]; then ufw --force delete allow "${FRPS_PORT}/tcp" >/dev/null 2>&1 || true; fi
    if [[ -f "$CONF_DIR/ufw_added_udp_control" ]]; then ufw --force delete allow "${FRPS_PORT}/udp" >/dev/null 2>&1 || true; fi
    if [[ -f "$CONF_DIR/ufw_added_tun_iface" ]]; then ufw --force delete allow in on "$TUN_DEV" >/dev/null 2>&1 || true; fi
    if [[ -f "$CONF_DIR/ufw_added_udp_peer" ]]; then
      peer="$(cat "$CONF_DIR/ufw_added_udp_peer" 2>/dev/null || true)"
      if valid_ipv4 "$peer"; then
        ufw --force delete allow from "$peer" to any proto udp >/dev/null 2>&1 || true
        ufw --force delete allow from "$peer" to any port "$TCP_FALLBACK_PORT" proto tcp >/dev/null 2>&1 || true
        ufw --force delete allow from "$peer" to any port "$TCPMUX_PORT" proto tcp >/dev/null 2>&1 || true
      fi
    fi
  fi
  rm -f "$UNIT_DIR/xtcp-tun-frps.service" "$UNIT_DIR/xtcp-tun-agent.service" \
        "$UNIT_DIR/xtcp-tun-frpc-iran.service" "$UNIT_DIR/xtcp-tun-frpc-outside.service" \
        "$UNIT_DIR/xtcp-tun-rules.service"
  systemctl daemon-reload
  ip link delete dev "$TUN_DEV" >/dev/null 2>&1 || true
  rm -f /etc/sysctl.d/90-xtcp-tun.conf /etc/modules-load.d/xtcp-tun.conf
  if [[ -f "$CONF_DIR/old_ip_forward" ]]; then
    old_forward="$(cat "$CONF_DIR/old_ip_forward" 2>/dev/null || printf '0')"
    [[ "$old_forward" == 0 || "$old_forward" == 1 ]] || old_forward=0
    sysctl -w "net.ipv4.ip_forward=$old_forward" >/dev/null 2>&1 || true
  fi
  rm -rf "$BASE_DIR" "$CONF_DIR" "$LOG_DIR" "$(dirname "$STATE_FILE")"
  rm -f "$MANAGER_PATH"
  log "Uninstall complete. Shared packages like Python/iptables were left installed."
}

# Runs one menu action in a subshell WITH errexit, without letting a failure
# terminate the menu (the old `( action )` form exited the whole script under set -e).
run_action() {
  local rc
  set +e
  ( set -e; "$@" )
  rc=$?
  set -e
  if (( rc != 0 )); then warn "The action stopped (exit code $rc) - see the message above."; fi
  return 0
}

menu() {
  require_root
  local choice
  while true; do
    printf '\n\033[1;36m========== XTCP-TUN Manager v%s ==========\033[0m\n' "$SCRIPT_VERSION"
    printf '1) Install/configure the Iran side\n'
    printf '2) Install/configure the outside side\n'
    printf '3) Tunnel and service status\n'
    printf '4) Start services\n'
    printf '5) Stop services\n'
    printf '6) Restart services\n'
    printf '7) Add more port forward(s) (Iran only)\n'
    printf '8) Remove port forward(s) (Iran only)\n'
    printf '9) List port forwards\n'
    printf '10) Show outside-connection credentials (Iran only)\n'
    printf '11) View logs\n'
    printf '12) Full uninstall\n'
    printf '13) Test the tunnel (ping + diagnosis)\n'
    printf '14) Repair / upgrade in place (run on BOTH servers after updating the script)\n'
    printf '0) Exit\n'
    read -rp 'Your choice: ' choice || exit 0
    case "$choice" in
      1) run_action install_iran ;;
      2) run_action install_outside ;;
      3) run_action status_all ;;
      4) run_action service_action start ;;
      5) run_action service_action stop ;;
      6) run_action service_action restart ;;
      7) run_action add_forward ;;
      8) run_action remove_forward ;;
      9) run_action list_forwards ;;
      10) run_action show_credentials ;;
      11) run_action show_logs ;;
      12) run_action uninstall_all ;;
      13) run_action test_tunnel ;;
      14) run_action repair_all ;;
      0) exit 0 ;;
      *) warn "Invalid option." ;;
    esac
  done
}

main() {
  case "${1:-}" in
    --apply-rules) apply_rules || exit 1; exit 0 ;;
    --status) status_all; exit 0 ;;
    --test) test_tunnel; exit $? ;;
    --repair) repair_all; exit 0 ;;
  esac
  menu
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
