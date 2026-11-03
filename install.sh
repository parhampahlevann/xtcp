#!/usr/bin/env bash
# XTCP-TUN Manager: IPv4 TUN-over-FRP-XTCP for Ubuntu/Debian (Patched Edition)
set -Eeuo pipefail

FRP_VERSION="0.61.1"
BASE_DIR="/opt/xtcp-tun"
CONF_DIR="/etc/xtcp-tun"
LOG_DIR="/var/log/xtcp-tun"
MANAGER_PATH="/usr/local/sbin/xtcp-tun-manager"
AGENT_PATH="$BASE_DIR/tun-agent.py"
TUN_DEV="xtcp0"
IRAN_TUN_IP="10.0.0.1"
OUTSIDE_TUN_IP="10.0.0.2"
FRPS_PORT="47000"
PIPE_SERVER_PORT="17000"
PIPE_VISITOR_PORT="17001"
MTU="1280"
TUNNEL_MSS="1240"

DEFAULT_FRP_TOKEN="740ef87eef4da026d23581899eac95a2015c6eb3d227040d18c28d5ddc86f92d"
DEFAULT_XTCP_SECRET="81fdeae86511c25c380b37e6e20ceffa1cb13f7d0edff61bf08f86eb78db187b"

NAT_HOLE_STUN_SERVER="stun.easyvoip.com:3478"
XTCP_FALLBACK_TIMEOUT_MS="1500"

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

is_reserved_port() {
  case "${1:-}" in
    "$FRPS_PORT"|"$TCP_FALLBACK_PORT"|"$TCPMUX_PORT") return 0 ;;
    *) return 1 ;;
  esac
}

port_listening() {
  ss -Htln "( sport = :$1 )" 2>/dev/null | grep -q .
}

detect_ssh_ports() {
  local ports
  ports="$(ss -Htlnp 2>/dev/null | awk '/sshd/ {print $4}' | sed -E 's/.*:([0-9]+)$/\1/' | sort -u)"
  if [[ -z "$ports" ]]; then
    printf '22\n'
  else
    printf '%s\n' "$ports"
  fi
}

confirm_not_ssh_port() {
  local listen="$1" ssh_ports p confirm
  ssh_ports="$(detect_ssh_ports)"
  for p in $ssh_ports; do
    if [[ "$listen" == "$p" ]]; then
      warn "Port $listen looks like sshd's own listening port on this server. Forwarding it through the tunnel will silently steal new SSH connections away from this box the next time the rules are applied - you could lock yourself out."
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
  printf '  5) wss        - ws + TLS, blends in with ordinary HTTPS traffic\n'
  read -rp "Choice [1]: " choice
  case "${choice:-1}" in
    1) CHOSEN_TRANSPORT_PROTOCOL="tcp" ;;
    2) CHOSEN_TRANSPORT_PROTOCOL="kcp" ;;
    3) CHOSEN_TRANSPORT_PROTOCOL="quic" ;;
    4) CHOSEN_TRANSPORT_PROTOCOL="websocket" ;;
    5) CHOSEN_TRANSPORT_PROTOCOL="wss" ;;
    *) warn "Invalid choice; using tcp."; CHOSEN_TRANSPORT_PROTOCOL="tcp" ;;
  esac
  log "Transport protocol: $CHOSEN_TRANSPORT_PROTOCOL (this must be the same on the other server)."
}

install_packages() {
  command -v apt-get >/dev/null 2>&1 || die "This version currently targets Ubuntu/Debian only."
  log "Checking and installing required dependencies (no apt update/upgrade)..."
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates curl iproute2 iptables python3 kmod >/dev/null

  # تضمین لود ماژول کرنل و بررسی دیوایس نود
  modprobe tun 2>/dev/null || true
  if [[ ! -c /dev/net/tun ]]; then
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200 2>/dev/null || true
    chmod 666 /dev/net/tun 2>/dev/null || true
  fi

  mkdir -p "$BASE_DIR" "$CONF_DIR" "$LOG_DIR"
  chmod 700 "$CONF_DIR"
  chmod 755 "$BASE_DIR" "$LOG_DIR"
  local self_path
  self_path="$(readlink -f -- "$0" 2>/dev/null || printf '%s' "$0")"
  [[ -f "$self_path" ]] || die "Could not find the script file; save xtcp-tun-manager.sh on the server first, then run it with bash."
  install -m 0755 "$self_path" "$MANAGER_PATH"

  PYTHON_BIN="$(command -v python3)"
  [[ -n "$PYTHON_BIN" ]] || die "python3 was installed but could not be found on PATH."
}

install_frp() {
  local need_frpc="$1" need_frps="$2" machine_arch arch tmp archive extracted url
  machine_arch="$(uname -m)"
  case "$machine_arch" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) die "Unsupported architecture: $machine_arch (amd64 and arm64 only)" ;;
  esac
  tmp="$(mktemp -d /tmp/xtcp-frp.XXXXXX)"
  archive="$tmp/frp.tar.gz"
  url="https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/frp_${FRP_VERSION}_linux_${arch}.tar.gz"
  log "Downloading FRP ${FRP_VERSION} for Linux/${arch} from the official repository..."
  if ! curl -fL --retry 3 --connect-timeout 15 --max-time 240 "$url" -o "$archive"; then
    rm -rf "$tmp"
    die "FRP download failed. Check HTTPS access to GitHub and that this architecture is available."
  fi
  tar -tzf "$archive" >/dev/null || { rm -rf "$tmp"; die "The downloaded FRP archive is not a valid tarball."; }
  tar -xzf "$archive" -C "$tmp"
  extracted="$tmp/frp_${FRP_VERSION}_linux_${arch}"
  [[ -d "$extracted" ]] || { rm -rf "$tmp"; die "Could not find the FRP version folder inside the downloaded archive."; }
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
  cat > "$AGENT_PATH" <<'PY'
#!/usr/bin/env python3
import argparse
import errno
import fcntl
import os
import select
import socket
import struct
import subprocess
import sys
import time

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, flush=True)

def sd_notify(message):
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        return
    if address.startswith("@"):
        address = "\0" + address[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notify_sock:
            notify_sock.connect(address)
            notify_sock.sendall(message.encode("utf-8"))
    except OSError as exc:
        log(f"systemd notify warning: {exc}")

def run_ip(*args):
    subprocess.run(["ip", *args], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)

def open_tun(dev, cidr, mtu):
    if not os.path.exists("/dev/net/tun"):
        raise RuntimeError("/dev/net/tun is missing; ensure the TUN kernel module/device is available")
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH22x", dev.encode("ascii")[:15], IFF_TUN | IFF_NO_PI)
    try:
        fcntl.ioctl(fd, TUNSETIFF, ifr)
        run_ip("link", "set", "dev", dev, "mtu", str(mtu))
        run_ip("addr", "replace", cidr, "dev", dev)
        run_ip("link", "set", "dev", dev, "up")
    except Exception:
        os.close(fd)
        raise
    log(f"TUN ready: {dev} {cidr}, MTU {mtu}")
    return fd

def parse_addr(value):
    host, sep, port = value.rpartition(":")
    if not sep or not host or not port:
        raise ValueError("address must be HOST:PORT")
    p = int(port)
    if p < 1 or p > 65535:
        raise ValueError("port must be between 1 and 65535")
    return host, p

def bridge(conn, tun_fd, mtu, label, preload=b""):
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    conn.settimeout(None)
    buf = bytearray(preload)
    last_rx = time.monotonic()
    next_heartbeat = last_rx + 15.0
    log(f"Tunnel stream connected ({label})")
    while True:
        readable, _, _ = select.select([tun_fd, conn], [], [], 1.0)
        if tun_fd in readable:
            packet = os.read(tun_fd, 65535)
            if packet:
                if len(packet) > 65535:
                    raise RuntimeError("oversized TUN packet")
                conn.sendall(struct.pack("!H", len(packet)) + packet)
        if conn in readable:
            chunk = conn.recv(65535)
            if not chunk:
                raise ConnectionError("XTCP stream closed")
            last_rx = time.monotonic()
            buf.extend(chunk)
            while len(buf) >= 2:
                size = struct.unpack("!H", buf[:2])[0]
                if size == 0:
                    del buf[:2]
                    continue
                if len(buf) < size + 2:
                    break
                packet = bytes(buf[2:size + 2])
                del buf[:size + 2]
                if len(packet) > mtu:
                    raise RuntimeError(f"packet size {len(packet)} exceeds configured MTU {mtu}")
                written = os.write(tun_fd, packet)
                if written != len(packet):
                    raise OSError(errno.EIO, "partial write to TUN device")
        now = time.monotonic()
        if now - last_rx > 90.0:
            raise TimeoutError("no data/heartbeat from peer for 90 seconds")
        if now >= next_heartbeat:
            conn.sendall(b"\x00\x00")
            next_heartbeat = now + 15.0

def run_server(args, tun_fd):
    host, port = parse_addr(args.listen)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(4)
    log(f"Waiting for FRP XTCP local connection on {host}:{port}")
    sd_notify("READY=1")
    while True:
        conn, peer = srv.accept()
        try:
            bridge(conn, tun_fd, args.mtu, f"server peer {peer[0]}:{peer[1]}")
        except (ConnectionError, OSError, RuntimeError) as exc:
            log(f"Stream ended: {exc}")
        finally:
            try:
                conn.close>
            except Exception:
                pass
        time.sleep(0.5)

def tcpmux_connect(host, port, connect_host, timeout=10):
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall(f"CONNECT {connect_host} HTTP/1.1\r\nHost: {connect_host}\r\n\r\n".encode("ascii"))
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("tcpmux: connection closed during CONNECT handshake")
            buf += chunk
            if len(buf) > 8192:
                raise ConnectionError("tcpmux: CONNECT response too large")
        head, preload = buf.split(b"\r\n\r\n", 1)
        status_line = head.split(b"\r\n", 1)[0].decode("latin1", "replace")
        parts = status_line.split(" ")
        if len(parts) < 2 or parts[1] != "200":
            raise ConnectionError(f"tcpmux: CONNECT rejected: {status_line!r}")
    except Exception:
        sock.close()
        raise
    sock.settimeout(None)
    return sock, preload

def run_client(args, tun_fd):
    local_addr = parse_addr(args.connect)
    direct_tcp_addr = parse_addr(args.direct_tcp) if args.direct_tcp else None
    tcpmux_addr = parse_addr(args.tcpmux) if args.tcpmux else None

    def try_local():
        host, port = local_addr
        log(f"Trying local FRP visitor at {host}:{port} (xtcp/quic -> xtcp/kcp -> stcp)")
        return socket.create_connection((host, port), timeout=10), b""

    def try_direct_tcp():
        host, port = direct_tcp_addr
        log(f"Trying direct TCP fallback at {host}:{port}")
        return socket.create_connection((host, port), timeout=10), b""

    def try_tcpmux():
        host, port = tcpmux_addr
        log(f"Trying TCPMUX (HTTP CONNECT) fallback at {host}:{port}")
        return tcpmux_connect(host, port, args.tcpmux_host, timeout=10)

    attempts = [("local FRP visitor (xtcp/stcp)", try_local)]
    if direct_tcp_addr:
        attempts.append(("direct TCP fallback", try_direct_tcp))
    if tcpmux_addr:
        attempts.append(("TCPMUX fallback", try_tcpmux))

    delay = 2
    idx = 0
    sd_notify("READY=1")
    while True:
        label, attempt = attempts[idx % len(attempts)]
        conn = None
        try:
            conn, preload = attempt()
            conn.settimeout(None)
            bridge(conn, tun_fd, args.mtu, label, preload=preload)
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            log(f"{label} failed/closed: {exc}; retry in {delay}s")
        finally:
            if conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass
        idx += 1
        time.sleep(delay)
        delay = min(delay * 2, 15)

def main():
    parser = argparse.ArgumentParser(description="IPv4 TUN packet bridge for FRP XTCP")
    subs = parser.add_subparsers(dest="mode", required=True)
    server = subs.add_parser("server")
    server.add_argument("--dev", default="xtcp0")
    server.add_argument("--cidr", default="10.0.0.1/30")
    server.add_argument("--listen", default="127.0.0.1:17000")
    server.add_argument("--mtu", type=int, default=1280)
    client = subs.add_parser("client")
    client.add_argument("--dev", default="xtcp0")
    client.add_argument("--cidr", default="10.0.0.2/30")
    client.add_argument("--connect", default="127.0.0.1:17001")
    client.add_argument("--direct-tcp", default=None,
                        help="HOST:PORT of a plain 'tcp' type frp proxy, tried if the local FRP visitor fails")
    client.add_argument("--tcpmux", default=None,
                        help="HOST:PORT of frps's tcpmuxHTTPConnectPort, tried last via an HTTP CONNECT request")
    client.add_argument("--tcpmux-host", default="xtcp-l3",
                        help="Host value sent in the tcpmux CONNECT request; must match the proxy's customDomains entry")
    client.add_argument("--mtu", type=int, default=1280)
    args = parser.parse_args()
    if not 576 <= args.mtu <= 9000:
        parser.error("MTU must be between 576 and 9000")
    tun_fd = open_tun(args.dev, args.cidr, args.mtu)
    try:
        if args.mode == "server":
            run_server(args, tun_fd)
        else:
            run_client(args, tun_fd)
    finally:
        os.close(tun_fd)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        log(f"FATAL: {exc}")
        raise
PY
  chmod 0755 "$AGENT_PATH"
  python3 -m py_compile "$AGENT_PATH" || die "Syntax check of the TUN agent script failed."
  rm -rf "$BASE_DIR/__pycache__"
}

write_wait_for_frps_script() {
  cat > "$BASE_DIR/wait-for-frps.sh" <<'SCRIPT_EOF'
#!/usr/bin/env bash
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
echo "A common cause: another process is already holding that port. Check: ss -tlnp | grep \":$port\"" >&2
exit 1
SCRIPT_EOF
  chmod 0755 "$BASE_DIR/wait-for-frps.sh"
}

setup_ufw_iran() {
  local peer_ip="${1:-}"
  command -v ufw >/dev/null 2>&1 || return 0
  ufw status 2>/dev/null | head -n 1 | grep -qi 'Status: active' || return 0
  if ! ufw status 2>/dev/null | grep -Eq "(^|[[:space:]])${FRPS_PORT}/tcp.*ALLOW"; then
    ufw allow "${FRPS_PORT}/tcp" comment 'xtcp-tun-managed' >/dev/null
    printf 'yes\n' > "$CONF_DIR/ufw_added_tcp_control"
    log "UFW: allowed TCP/$FRPS_PORT for the FRP control connection."
  fi
  if [[ -n "$peer_ip" ]] && valid_ipv4 "$peer_ip"; then
    if ! ufw status 2>/dev/null | grep -F "$peer_ip" | grep -q 'ALLOW'; then
      ufw allow from "$peer_ip" to any proto udp comment 'xtcp-tun-managed' >/dev/null
      ufw allow from "$peer_ip" to any port "$TCP_FALLBACK_PORT" proto tcp comment 'xtcp-tun-managed' >/dev/null
      ufw allow from "$peer_ip" to any port "$TCPMUX_PORT" proto tcp comment 'xtcp-tun-managed' >/dev/null
      printf '%s\n' "$peer_ip" > "$CONF_DIR/ufw_added_udp_peer"
      log "UFW: allowed UDP (XTCP), TCP/$TCP_FALLBACK_PORT and TCP/$TCPMUX_PORT from outside server IP."
    fi
  else
    warn "UFW is active; enter the outside server's public IP on Iran install or configure firewall rules manually."
  fi
}

setup_ufw_outside() {
  local iran_ip="$1"
  command -v ufw >/dev/null 2>&1 || return 0
  ufw status 2>/dev/null | head -n 1 | grep -qi 'Status: active' || return 0
  if ! ufw status 2>/dev/null | grep -F "$iran_ip" | grep -q 'ALLOW'; then
    ufw allow from "$iran_ip" to any proto udp comment 'xtcp-tun-managed' >/dev/null
    printf '%s\n' "$iran_ip" > "$CONF_DIR/ufw_added_udp_peer"
    log "UFW: allowed UDP from the Iran server's public IP."
  fi
}

make_iran_units() {
  cat > /etc/systemd/system/xtcp-tun-frps.service <<EOF2
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

  cat > /etc/systemd/system/xtcp-tun-agent.service <<EOF2
[Unit]
Description=IPv4 TUN packet bridge over FRP XTCP (Iran)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=notify
Environment=PYTHONUNBUFFERED=1
ExecStart=$PYTHON_BIN $AGENT_PATH server --dev $TUN_DEV --cidr $IRAN_TUN_IP/30 --listen 127.0.0.1:$PIPE_SERVER_PORT --mtu $MTU
Restart=always
RestartSec=2
LimitNOFILE=1048576
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF2

  cat > /etc/systemd/system/xtcp-tun-frpc-iran.service <<EOF2
[Unit]
Description=FRP XTCP proxy client (Iran side)
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

  cat > /etc/systemd/system/xtcp-tun-rules.service <<EOF2
[Unit]
Description=Persistent iptables rules for XTCP-TUN port forwarding
After=network-online.target xtcp-tun-agent.service
Requires=xtcp-tun-agent.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$MANAGER_PATH --apply-rules
ExecReload=$MANAGER_PATH --apply-rules

[Install]
WantedBy=multi-user.target
EOF2
}

make_outside_units() {
  local iran_ip="$1"
  cat > /etc/systemd/system/xtcp-tun-agent.service <<EOF2
[Unit]
Description=IPv4 TUN packet bridge over FRP XTCP (outside side)
After=network-online.target xtcp-tun-frpc-outside.service
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=notify
Environment=PYTHONUNBUFFERED=1
ExecStart=$PYTHON_BIN $AGENT_PATH client --dev $TUN_DEV --cidr $OUTSIDE_TUN_IP/30 --connect 127.0.0.1:$PIPE_VISITOR_PORT --direct-tcp $iran_ip:$TCP_FALLBACK_PORT --tcpmux $iran_ip:$TCPMUX_PORT --tcpmux-host $TCPMUX_DOMAIN --mtu $MTU
Restart=always
RestartSec=2
LimitNOFILE=1048576
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF2

  cat > /etc/systemd/system/xtcp-tun-frpc-outside.service <<EOF2
[Unit]
Description=FRP XTCP visitor client (outside side)
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
}

install_iran() {
  require_root
  [[ ! -f "$CONF_DIR/role" ]] || die "This manager is already installed on this server (role: $(cat "$CONF_DIR/role")). Check the status or uninstall first."
  install_packages
  local p
  for p in "$FRPS_PORT" "$TCP_FALLBACK_PORT" "$TCPMUX_PORT"; do
    if port_listening "$p"; then
      die "Port $p is already in use by another process on this server (check: ss -tlnp | grep :$p)."
    fi
  done
  install_frp yes yes
  write_agent
  write_wait_for_frps_script
  local detected iran_ip peer_ip frp_token xtcp_secret transport_protocol transport_bind_extra=""
  detected="$(curl -4fsS --connect-timeout 5 --max-time 8 https://api.ipify.org 2>/dev/null || true)"
  if ! valid_ipv4 "$detected"; then detected=""; fi
  read -rp "Public IPv4 of the Iran server${detected:+ [$detected]}: " iran_ip
  iran_ip="${iran_ip:-$detected}"
  valid_ipv4 "$iran_ip" || die "No valid public IPv4 was entered."
  read -rp "Public IPv4 of the outside server, to allow UDP if UFW is active (press Enter to skip): " peer_ip
  if [[ -n "$peer_ip" ]] && ! valid_ipv4 "$peer_ip"; then die "The outside server's IP is not valid."; fi
  choose_transport_protocol
  transport_protocol="$CHOSEN_TRANSPORT_PROTOCOL"
  case "$transport_protocol" in
    kcp) transport_bind_extra="kcpBindPort = $FRPS_PORT"$'\n' ;;
    quic) transport_bind_extra="quicBindPort = $FRPS_PORT"$'\n' ;;
  esac
  frp_token="$DEFAULT_FRP_TOKEN"
  xtcp_secret="$DEFAULT_XTCP_SECRET"
  printf 'iran\n' > "$CONF_DIR/role"
  printf '%s\n' "$iran_ip" > "$CONF_DIR/iran_public_ip"
  printf '%s\n' "$frp_token" > "$CONF_DIR/frp_token"
  printf '%s\n' "$xtcp_secret" > "$CONF_DIR/xtcp_secret"
  printf '%s\n' "$transport_protocol" > "$CONF_DIR/transport_protocol"
  chmod 600 "$CONF_DIR"/*
  : > "$CONF_DIR/forwards.tsv"
  if [[ ! -f "$CONF_DIR/old_ip_forward" ]]; then sysctl -n net.ipv4.ip_forward > "$CONF_DIR/old_ip_forward"; fi
  printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/90-xtcp-tun.conf
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  cat > "$CONF_DIR/frps.toml" <<EOF2
bindAddr = "0.0.0.0"
bindPort = $FRPS_PORT
${transport_bind_extra}tcpmuxHTTPConnectPort = $TCPMUX_PORT
auth.method = "token"
auth.token = "$frp_token"
log.to = "$LOG_DIR/frps.log"
log.level = "info"
log.maxDays = 3
EOF2
  cat > "$CONF_DIR/frpc-iran.toml" <<EOF2
serverAddr = "127.0.0.1"
serverPort = $FRPS_PORT
transport.protocol = "$transport_protocol"
natHoleStunServer = "$NAT_HOLE_STUN_SERVER"
auth.method = "token"
auth.token = "$frp_token"
log.to = "$LOG_DIR/frpc-iran.log"
log.level = "info"
log.maxDays = 3

[[proxies]]
name = "xtcp-l3"
type = "xtcp"
secretKey = "$xtcp_secret"
localIP = "127.0.0.1"
localPort = $PIPE_SERVER_PORT

[[proxies]]
name = "xtcp-l3-stcp"
type = "stcp"
secretKey = "$xtcp_secret"
localIP = "127.0.0.1"
localPort = $PIPE_SERVER_PORT

[[proxies]]
name = "xtcp-l3-tcp"
type = "tcp"
localIP = "127.0.0.1"
localPort = $PIPE_SERVER_PORT
remotePort = $TCP_FALLBACK_PORT

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
  setup_ufw_iran "$peer_ip"
  systemctl daemon-reload
  systemctl enable --now xtcp-tun-frps.service xtcp-tun-agent.service xtcp-tun-frpc-iran.service xtcp-tun-rules.service
  log "Iran-side install complete. Use this information to connect the outside server:"
  printf '\n  Iran IP:        %s\n  FRP Token:      %s\n  XTCP SecretKey: %s\n  Protocol:       %s\n\n' "$iran_ip" "$frp_token" "$xtcp_secret" "$transport_protocol"
  printf 'Open inbound TCP ports %s (control), %s (tcp fallback) and %s (tcpmux fallback) in datacenter firewall.\n' "$FRPS_PORT" "$TCP_FALLBACK_PORT" "$TCPMUX_PORT"

  log "Waiting for the tunnel interface ($TUN_DEV) to come up..."
  local tun_wait=0
  until ip link show dev "$TUN_DEV" >/dev/null 2>&1; do
    sleep 1
    tun_wait=$((tun_wait + 1))
    if (( tun_wait >= 15 )); then
      warn "Tunnel interface $TUN_DEV has not registered yet."
      warn "Check agent logs: journalctl -u xtcp-tun-agent.service -n 25 --no-pager"
      warn "Port forwarding can be configured anytime from menu option 7 once active."
      return 0
    fi
  done
  prompt_initial_forwards
}

install_outside() {
  require_root
  [[ ! -f "$CONF_DIR/role" ]] || die "This manager is already installed on this server (role: $(cat "$CONF_DIR/role")). Check the status or uninstall first."
  install_packages
  install_frp yes no
  write_agent
  local iran_ip frp_token xtcp_secret transport_protocol
  read -rp "Public IPv4 of the Iran server: " iran_ip
  valid_ipv4 "$iran_ip" || die "The Iran server's public IPv4 is not valid."
  choose_transport_protocol
  transport_protocol="$CHOSEN_TRANSPORT_PROTOCOL"
  frp_token="$DEFAULT_FRP_TOKEN"
  xtcp_secret="$DEFAULT_XTCP_SECRET"
  printf 'outside\n' > "$CONF_DIR/role"
  printf '%s\n' "$iran_ip" > "$CONF_DIR/iran_public_ip"
  printf '%s\n' "$frp_token" > "$CONF_DIR/frp_token"
  printf '%s\n' "$xtcp_secret" > "$CONF_DIR/xtcp_secret"
  printf '%s\n' "$transport_protocol" > "$CONF_DIR/transport_protocol"
  chmod 600 "$CONF_DIR"/*
  cat > "$CONF_DIR/frpc-outside.toml" <<EOF2
serverAddr = "$iran_ip"
serverPort = $FRPS_PORT
transport.protocol = "$transport_protocol"
natHoleStunServer = "$NAT_HOLE_STUN_SERVER"
auth.method = "token"
auth.token = "$frp_token"
log.to = "$LOG_DIR/frpc-outside.log"
log.level = "info"
log.maxDays = 3

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

[[visitors]]
name = "xtcp-l3-stcp-visitor"
type = "stcp"
serverName = "xtcp-l3-stcp"
secretKey = "$xtcp_secret"
bindPort = -1
EOF2
  chmod 600 "$CONF_DIR"/*.toml
  make_outside_units "$iran_ip"
  setup_ufw_outside "$iran_ip"
  systemctl daemon-reload
  systemctl enable --now xtcp-tun-frpc-outside.service xtcp-tun-agent.service
  log "Outside-side install complete."
  printf 'Iran tunnel IP:    %s\nOutside tunnel IP: %s\nProtocol:          %s\n' "$IRAN_TUN_IP" "$OUTSIDE_TUN_IP" "$transport_protocol"
  printf 'Interface name: %s\n' "$TUN_DEV"
}

ipt() { iptables -w "$@"; }

apply_rules() {
  require_root
  [[ -f "$CONF_DIR/role" && "$(cat "$CONF_DIR/role")" == iran ]] || { log "Forwarding rules only apply on the Iran role."; return 0; }
  command -v iptables >/dev/null 2>&1 || die "iptables is not installed."
  
  # هشدار در صورت آنلاین نبودن اینترفیس به جای متوقف کردن کامل رول‌ها
  if ! ip link show dev "$TUN_DEV" >/dev/null 2>&1; then
    warn "Interface $TUN_DEV is not currently active. Applying iptables rules in advance..."
  fi

  local wan
  wan="$(ip -4 route show default | awk 'NR==1 {for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
  [[ -n "$wan" ]] || wan="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
  [[ -n "$wan" ]] || die "Could not detect the WAN interface from the routing table."
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  ipt -t nat -N XTCP_TUN_DNAT 2>/dev/null || true
  ipt -t nat -N XTCP_TUN_SNAT 2>/dev/null || true
  ipt -N XTCP_TUN_FWD 2>/dev/null || true
  ipt -t mangle -N XTCP_TUN_MSS 2>/dev/null || true
  ipt -t nat -F XTCP_TUN_DNAT
  ipt -t nat -F XTCP_TUN_SNAT
  ipt -F XTCP_TUN_FWD
  ipt -t mangle -F XTCP_TUN_MSS
  ipt -t nat -C PREROUTING -j XTCP_TUN_DNAT 2>/dev/null || ipt -t nat -I PREROUTING 1 -j XTCP_TUN_DNAT
  ipt -t nat -C POSTROUTING -o "$TUN_DEV" -j XTCP_TUN_SNAT 2>/dev/null || ipt -t nat -I POSTROUTING 1 -o "$TUN_DEV" -j XTCP_TUN_SNAT
  ipt -C FORWARD -j XTCP_TUN_FWD 2>/dev/null || ipt -I FORWARD 1 -j XTCP_TUN_FWD
  ipt -t mangle -C FORWARD -j XTCP_TUN_MSS 2>/dev/null || ipt -t mangle -I FORWARD 1 -j XTCP_TUN_MSS
  ipt -t mangle -A XTCP_TUN_MSS -o "$TUN_DEV" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$TUNNEL_MSS" 2>/dev/null || true
  ipt -t mangle -A XTCP_TUN_MSS -i "$TUN_DEV" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$TUNNEL_MSS" 2>/dev/null || true
  ipt -t mangle -A XTCP_TUN_MSS -j RETURN
  ipt -A XTCP_TUN_FWD -i "$TUN_DEV" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  local proto listen target
  while read -r proto listen target; do
    [[ -n "${proto:-}" ]] || continue
    [[ "$proto" == tcp || "$proto" == udp ]] || continue
    valid_port "$listen" && valid_port "$target" || continue
    if [[ "$listen" == "$FRPS_PORT" ]]; then
      warn "Skipping forward for port $FRPS_PORT: reserved for the FRP control channel."
      continue
    fi
    if is_reserved_port "$listen"; then
      warn "Skipping forward for port $listen: reserved control/fallback port."
      continue
    fi
    ipt -t nat -A XTCP_TUN_DNAT -i "$wan" -p "$proto" --dport "$listen" -j DNAT --to-destination "$OUTSIDE_TUN_IP:$target"
    ipt -t nat -A XTCP_TUN_SNAT -d "$OUTSIDE_TUN_IP" -p "$proto" --dport "$target" -j SNAT --to-source "$IRAN_TUN_IP"
    ipt -A XTCP_TUN_FWD -i "$wan" -o "$TUN_DEV" -d "$OUTSIDE_TUN_IP" -p "$proto" --dport "$target" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
  done < "$CONF_DIR/forwards.tsv"
  ipt -A XTCP_TUN_FWD -j RETURN
  log "Rules applied. WAN=$wan; Target=$OUTSIDE_TUN_IP, SNAT Source=$IRAN_TUN_IP, MSS=$TUNNEL_MSS"
}

remove_iptables_rules() {
  command -v iptables >/dev/null 2>&1 || return 0
  while ipt -t nat -C PREROUTING -j XTCP_TUN_DNAT 2>/dev/null; do ipt -t nat -D PREROUTING -j XTCP_TUN_DNAT || break; done
  while ipt -t nat -C POSTROUTING -o "$TUN_DEV" -j XTCP_TUN_SNAT 2>/dev/null; do ipt -t nat -D POSTROUTING -o "$TUN_DEV" -j XTCP_TUN_SNAT || break; done
  while ipt -C FORWARD -j XTCP_TUN_FWD 2>/dev/null; do ipt -D FORWARD -j XTCP_TUN_FWD || break; done
  while ipt -t mangle -C FORWARD -j XTCP_TUN_MSS 2>/dev/null; do ipt -t mangle -D FORWARD -j XTCP_TUN_MSS || break; done
  ipt -t mangle -F XTCP_TUN_MSS 2>/dev/null || true
  ipt -t mangle -X XTCP_TUN_MSS 2>/dev/null || true
  ipt -t nat -F XTCP_TUN_DNAT 2>/dev/null || true
  ipt -t nat -X XTCP_TUN_DNAT 2>/dev/null || true
  ipt -t nat -F XTCP_TUN_SNAT 2>/dev/null || true
  ipt -t nat -X XTCP_TUN_SNAT 2>/dev/null || true
  ipt -F XTCP_TUN_FWD 2>/dev/null || true
  ipt -X XTCP_TUN_FWD 2>/dev/null || true
}

status_all() {
  require_root
  if [[ ! -f "$CONF_DIR/role" ]]; then
    printf 'Status: not installed\n'
    return 0
  fi
  printf '\nRole: %s\n' "$(cat "$CONF_DIR/role")"
  if [[ -f "$CONF_DIR/transport_protocol" ]]; then
    printf 'Transport protocol: %s\n' "$(cat "$CONF_DIR/transport_protocol")"
  fi
  printf '\n--- Tunnel interface IP ---\n'
  ip -4 addr show dev "$TUN_DEV" 2>/dev/null || echo "Interface $TUN_DEV is inactive."
  printf '\n--- Services ---\n'
  local s
  for s in xtcp-tun-frps xtcp-tun-agent xtcp-tun-frpc-iran xtcp-tun-frpc-outside xtcp-tun-rules; do
    if systemctl list-unit-files "$s.service" --no-legend 2>/dev/null | grep -q "$s.service"; then
      printf '%-30s %s\n' "$s" "$(systemctl is-active "$s.service" 2>/dev/null || true)"
    fi
  done
  printf '\n--- Listening ports (local) ---\n'
  if ! ss -tlnp 2>/dev/null | grep -E ":($FRPS_PORT|$PIPE_SERVER_PORT|$PIPE_VISITOR_PORT|$TCP_FALLBACK_PORT|$TCPMUX_PORT)\b"; then
    printf '  None of the expected ports are listening yet.\n'
  fi
  printf '\n--- Related connections ---\n'
  ss -tnp 2>/dev/null | grep -E ":($FRPS_PORT|$PIPE_SERVER_PORT|$PIPE_VISITOR_PORT|$TCP_FALLBACK_PORT|$TCPMUX_PORT)\b" || true
  if [[ "$(cat "$CONF_DIR/role")" == iran ]]; then
    printf '\n--- Registered forwards (protocol listen-port target-port) ---\n'
    if [[ -s "$CONF_DIR/forwards.tsv" ]]; then sed 's/^/  /' "$CONF_DIR/forwards.tsv"; else printf '  No ports defined yet.\n'; fi
    printf '\n--- iptables NAT ---\n'
    ipt -t nat -S XTCP_TUN_DNAT 2>/dev/null || true
    ipt -t nat -S XTCP_TUN_SNAT 2>/dev/null || true
  fi
}

service_action() {
  require_root
  [[ -f "$CONF_DIR/role" ]] || die "Not installed yet."
  local role="$(cat "$CONF_DIR/role")"
  case "$role" in
    iran) systemctl "$1" xtcp-tun-frps.service xtcp-tun-agent.service xtcp-tun-frpc-iran.service xtcp-tun-rules.service ;;
    outside) systemctl "$1" xtcp-tun-frpc-outside.service xtcp-tun-agent.service ;;
    *) die "The stored role is not valid." ;;
  esac
}

_parse_port_entry() {
  local raw="$1" listen target
  raw="$(printf '%s' "$raw" | tr -d '[:space:]')"
  [[ -n "$raw" ]] || return 1
  if [[ "$raw" == *:* ]]; then
    listen="${raw%%:*}"
    target="${raw##*:}"
  else
    listen="$raw"
    target="$raw"
  fi
  valid_port "$listen" || { warn "Invalid listen port skipped: $listen"; return 1; }
  valid_port "$target" || { warn "Invalid target port skipped: $target"; return 1; }
  printf '%s %s\n' "$listen" "$target"
}

prompt_initial_forwards() {
  local proto ports_input entry parsed listen target added=() line
  printf '\n'
  read -rp "Port(s) to forward through the tunnel now, comma-separated (e.g. 1080,443, or 1080:1081,443) - press Enter to skip: " ports_input
  [[ -n "$ports_input" ]] || { log "No ports entered; add forwards later from menu option 7."; return 0; }
  read -rp "Protocol for these ports (tcp/udp) [tcp]: " proto
  proto="${proto,,}"
  proto="${proto:-tcp}"
  if [[ "$proto" != tcp && "$proto" != udp ]]; then
    warn "Protocol must be tcp or udp; skipped."
    return 0
  fi
  IFS=',' read -ra entries <<< "$ports_input"
  for entry in "${entries[@]}"; do
    parsed="$(_parse_port_entry "$entry")" || continue
    listen="${parsed% *}"
    target="${parsed#* }"
    if is_reserved_port "$listen"; then
      warn "Port $listen is reserved for control/fallback; skipped."
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
  if [[ ${#added[@]} -eq 0 ]]; then
    warn "No forwarding rules were added."
    return 0
  fi
  if ! apply_rules; then
    for line in "${added[@]}"; do
      sed -i "\\|^$line\$|d" "$CONF_DIR/forwards.tsv"
    done
    warn "Applying rules failed; changes rolled back."
    return 0
  fi
  log "Added forwarding rule(s):"
  for line in "${added[@]}"; do
    printf '  %s\n' "$line"
  done
}

add_forward() {
  require_root
  [[ -f "$CONF_DIR/role" && "$(cat "$CONF_DIR/role")" == iran ]] || die "Adding a forward is only done on the Iran server."
  local proto ports_input entry parsed listen target added=() line
  read -rp "Protocol (tcp/udp): " proto
  proto="${proto,,}"
  [[ "$proto" == tcp || "$proto" == udp ]] || die "Protocol must be tcp or udp."
  read -rp "Port(s) to forward, comma-separated (e.g. 1080,443, or 1080:1081,443): " ports_input
  [[ -n "$ports_input" ]] || die "No ports entered."
  IFS=',' read -ra entries <<< "$ports_input"
  for entry in "${entries[@]}"; do
    parsed="$(_parse_port_entry "$entry")" || continue
    listen="${parsed% *}"
    target="${parsed#* }"
    if is_reserved_port "$listen"; then
      warn "Port $listen is reserved for control/fallback; skipped."
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
  if [[ ${#added[@]} -eq 0 ]]; then
    warn "No new forwarding rules were added."
    return 0
  fi
  if ! apply_rules; then
    for line in "${added[@]}"; do
      sed -i "\\|^$line\$|d" "$CONF_DIR/forwards.tsv"
    done
    die "Applying the rules failed; the new entries were rolled back."
  fi
  log "Added forwarding rule(s):"
  for line in "${added[@]}"; do
    printf '  %s\n' "$line"
  done
}

remove_forward() {
  require_root
  [[ -f "$CONF_DIR/role" && "$(cat "$CONF_DIR/role")" == iran ]] || die "Removing a forward is only done on the Iran server."
  local proto ports_input entry listen tmp backup removed=() notfound=()
  read -rp "Protocol (tcp/udp): " proto
  proto="${proto,,}"
  [[ "$proto" == tcp || "$proto" == udp ]] || die "Protocol must be tcp or udp."
  read -rp "Listen port(s) to remove, comma-separated (e.g. 1080,443): " ports_input
  [[ -n "$ports_input" ]] || die "No ports entered."
  IFS=',' read -ra entries <<< "$ports_input"
  backup="$(mktemp)"
  cp "$CONF_DIR/forwards.tsv" "$backup"
  tmp="$(mktemp)"
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
  if [[ ${#removed[@]} -eq 0 ]]; then
    rm -f "$tmp" "$backup"
    die "No matching rule(s) were found to remove."
  fi
  cat "$tmp" > "$CONF_DIR/forwards.tsv"
  rm -f "$tmp"
  if ! apply_rules; then
    cat "$backup" > "$CONF_DIR/forwards.tsv"
    rm -f "$backup"
    die "Applying the rules failed; the removal was rolled back."
  fi
  rm -f "$backup"
  log "Removed: ${removed[*]}"
  [[ ${#notfound[@]} -eq 0 ]] || warn "Not found (skipped): ${notfound[*]}"
}

list_forwards() {
  require_root
  if [[ -f "$CONF_DIR/role" && "$(cat "$CONF_DIR/role")" == iran ]]; then
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
  [[ -f "$CONF_DIR/role" && "$(cat "$CONF_DIR/role")" == iran ]] || die "Connection info is only stored on the Iran server."
  local proto
  proto="$(cat "$CONF_DIR/transport_protocol" 2>/dev/null || true)"
  proto="${proto:-tcp}"
  printf '\nIran IP:        %s\nFRP Token:      %s\nXTCP SecretKey: %s\nProtocol:       %s\n\n' \
    "$(cat "$CONF_DIR/iran_public_ip")" "$(cat "$CONF_DIR/frp_token")" "$(cat "$CONF_DIR/xtcp_secret")" "$proto"
}

show_logs() {
  require_root
  [[ -f "$CONF_DIR/role" ]] || die "Not installed yet."
  local role="$(cat "$CONF_DIR/role")"
  printf '\n--- Listening ports (local) ---\n'
  if ! ss -tlnp 2>/dev/null | grep -E ":($FRPS_PORT|$PIPE_SERVER_PORT|$PIPE_VISITOR_PORT|$TCP_FALLBACK_PORT|$TCPMUX_PORT)\b"; then
    printf '  None of the expected ports are listening yet.\n'
  fi
  if [[ "$role" == iran ]]; then
    journalctl --no-pager -n 70 -u xtcp-tun-frps.service -u xtcp-tun-agent.service -u xtcp-tun-frpc-iran.service
  else
    journalctl --no-pager -n 70 -u xtcp-tun-agent.service -u xtcp-tun-frpc-outside.service
  fi
  local f
  for f in "$LOG_DIR"/*.log; do
    [[ -f "$f" ]] || continue
    printf '\n--- tail -n 40 %s ---\n' "$f"
    tail -n 40 "$f"
  done
}

uninstall_all() {
  require_root
  [[ -f "$CONF_DIR/role" ]] || { log "Not installed."; return 0; }
  local role old_forward peer
  role="$(cat "$CONF_DIR/role")"
  printf '\nThis will remove the services, XTCP-TUN files, and the iptables rules created by this script.\n'
  read -rp "Type DELETE exactly to confirm: " confirm
  [[ "$confirm" == DELETE ]] || { log "Cancelled."; return 0; }
  remove_iptables_rules
  systemctl disable --now xtcp-tun-rules.service xtcp-tun-frpc-iran.service xtcp-tun-frpc-outside.service xtcp-tun-agent.service xtcp-tun-frps.service >/dev/null 2>&1 || true
  if [[ -f "$CONF_DIR/ufw_added_tcp_control" ]] && command -v ufw >/dev/null 2>&1; then
    ufw --force delete allow "${FRPS_PORT}/tcp" >/dev/null 2>&1 || true
  fi
  if [[ -f "$CONF_DIR/ufw_added_udp_peer" ]] && command -v ufw >/dev/null 2>&1; then
    peer="$(cat "$CONF_DIR/ufw_added_udp_peer" 2>/dev/null || true)"
    if valid_ipv4 "$peer"; then
      ufw --force delete allow from "$peer" to any proto udp >/dev/null 2>&1 || true
      ufw --force delete allow from "$peer" to any port "$TCP_FALLBACK_PORT" proto tcp >/dev/null 2>&1 || true
      ufw --force delete allow from "$peer" to any port "$TCPMUX_PORT" proto tcp >/dev/null 2>&1 || true
    fi
  fi
  rm -f /etc/systemd/system/xtcp-tun-frps.service \
        /etc/systemd/system/xtcp-tun-agent.service \
        /etc/systemd/system/xtcp-tun-frpc-iran.service \
        /etc/systemd/system/xtcp-tun-frpc-outside.service \
        /etc/systemd/system/xtcp-tun-rules.service
  systemctl daemon-reload
  ip link delete dev "$TUN_DEV" >/dev/null 2>&1 || true
  rm -f /etc/sysctl.d/90-xtcp-tun.conf
  if [[ -f "$CONF_DIR/old_ip_forward" ]]; then
    old_forward="$(cat "$CONF_DIR/old_ip_forward" 2>/dev/null || printf '0')"
    [[ "$old_forward" == 0 || "$old_forward" == 1 ]] || old_forward=0
    sysctl -w "net.ipv4.ip_forward=$old_forward" >/dev/null 2>&1 || true
  fi
  rm -rf "$BASE_DIR" "$CONF_DIR" "$LOG_DIR"
  rm -f "$MANAGER_PATH"
  log "Uninstall complete."
}

menu() {
  require_root
  while true; do
    printf '\n\033[1;36m========== XTCP-TUN Manager ==========%s\033[0m\n' ""
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
    printf '0) Exit\n'
    read -rp 'Your choice: ' choice
    case "$choice" in
      1) ( install_iran ) ;;
      2) ( install_outside ) ;;
      3) ( status_all ) ;;
      4) ( service_action start ) ;;
      5) ( service_action stop ) ;;
      6) ( service_action restart ) ;;
      7) ( add_forward ) ;;
      8) ( remove_forward ) ;;
      9) ( list_forwards ) ;;
      10) ( show_credentials ) ;;
      11) ( show_logs ) ;;
      12) ( uninstall_all ) ;;
      0) exit 0 ;;
      *) warn "Invalid option." ;;
    esac
  done
}

if [[ "${1:-}" == "--apply-rules" ]]; then
  apply_rules
  exit 0
fi

menu
