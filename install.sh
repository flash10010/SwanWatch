#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
APP_SOURCE="$SCRIPT_DIR/swanwatch"
INSTALL_DIR="${INSTALL_DIR:-/opt/swanwatch}"
VPN_SUBNET_DEFAULT="10.20.0.0/24"
VPN_DNS_DEFAULT="1.1.1.1,9.9.9.9"
DASHBOARD_PORT_DEFAULT="8085"

log() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
warn() { printf '\n\033[1;33mWARNING: %s\033[0m\n' "$*" >&2; }
die() { printf '\n\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

require_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run this installer as root: sudo ./install.sh"
}

prompt_default() {
  local prompt="$1" default="$2" value
  read -r -p "$prompt [$default]: " value
  printf '%s' "${value:-$default}"
}

prompt_secret() {
  local prompt="$1" value
  read -r -s -p "$prompt: " value
  printf '\n' >&2
  printf '%s' "$value"
}

random_secret() {
  openssl rand -base64 30 | tr -d '\n' | tr '/+' '_-'
}

valid_hostname() {
  [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]
}

valid_username() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]]
}

get_default_iface() {
  ip route show default 2>/dev/null | awk 'NR==1 {print $5}'
}

get_iface_ipv4() {
  ip -4 -o addr show dev "$1" scope global 2>/dev/null | awk 'NR==1 {split($4,a,"/"); print a[1]}'
}

install_dependencies() {
  log "Installing host dependencies for ${OS_FAMILY}"

  if [[ "$OS_FAMILY" == "debian" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends \
      ca-certificates curl openssl iproute2 iptables docker.io docker-cli unzip tar

    if ! docker compose version >/dev/null 2>&1; then
      apt-get install -y --no-install-recommends docker-compose || true
    fi
  else
    dnf -y install dnf-plugins-core ca-certificates curl openssl iproute iptables unzip tar firewalld

    if ! command -v docker >/dev/null 2>&1; then
      dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
      dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    elif ! docker compose version >/dev/null 2>&1; then
      dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
      dnf -y install docker-compose-plugin
    fi

    systemctl enable --now firewalld
  fi

  command -v docker >/dev/null 2>&1 || die "Docker CLI is not installed"

  systemctl enable --now containerd 2>/dev/null || true
  systemctl enable --now docker

  log "Waiting for Docker to become ready"
  local attempt
  for attempt in $(seq 1 30); do
    if docker info >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done

  systemctl status docker --no-pager -l >&2 || true
  journalctl -u docker.service -b --no-pager -n 100 >&2 || true
  die "Docker daemon is not accessible"
}

compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose "$@"
  else
    die "Docker Compose is unavailable."
  fi
}

backup_existing() {
  if [[ -d "$INSTALL_DIR" ]]; then
    local backup="${INSTALL_DIR}.backup-$(date +%Y%m%d-%H%M%S)"
    log "Backing up existing installation to $backup"
    cp -a "$INSTALL_DIR" "$backup"
  fi
}

write_strongswan_dockerfile() {
  cat > "$INSTALL_DIR/Dockerfile.strongswan" <<'DOCKERFILE_EOF'
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV STRONGSWAN_VERSION=6.0.6

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        wget \
        bzip2 \
        pkg-config \
        libssl-dev \
        iproute2 \
        iputils-ping; \
    mkdir -p /usr/src/strongswan; \
    cd /usr/src/strongswan; \
    wget -O strongswan.tar.bz2 \
        "https://download.strongswan.org/strongswan-${STRONGSWAN_VERSION}.tar.bz2"; \
    tar -xjf strongswan.tar.bz2; \
    cd "strongswan-${STRONGSWAN_VERSION}"; \
    ./configure \
        --prefix=/usr \
        --sysconfdir=/etc \
        --disable-defaults \
        --enable-charon \
        --enable-ikev2 \
        --enable-nonce \
        --enable-random \
        --enable-openssl \
        --enable-pem \
        --enable-x509 \
        --enable-pubkey \
        --enable-constraints \
        --enable-pki \
        --enable-socket-default \
        --enable-kernel-netlink \
        --enable-swanctl \
        --enable-resolve \
        --enable-eap-identity \
        --enable-eap-md5 \
        --enable-eap-dynamic \
        --enable-eap-tls \
        --enable-eap-mschapv2 \
        --enable-md4 \
        --enable-updown \
        --enable-vici \
        --enable-counters \
        --enable-silent-rules; \
    make -j"$(nproc)"; \
    make install; \
    ln -sf /usr/libexec/ipsec/charon /usr/local/bin/charon; \
    rm -rf /usr/src/strongswan; \
    apt-get purge -y \
        build-essential \
        wget \
        bzip2 \
        pkg-config \
        libssl-dev; \
    apt-get autoremove -y; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

EXPOSE 500/udp 4500/udp
DOCKERFILE_EOF
}

write_start_script() {
  cat > "$INSTALL_DIR/strongswan/start-strongswan.sh" <<'START_EOF'
#!/bin/sh
set -eu

if [ -x /usr/libexec/ipsec/charon ]; then
  CHARON=/usr/libexec/ipsec/charon
elif [ -x /usr/lib/ipsec/charon ]; then
  CHARON=/usr/lib/ipsec/charon
else
  echo "Unable to find the charon daemon" >&2
  exit 1
fi

"$CHARON" &
CHARON_PID=$!

cleanup() {
  kill "$CHARON_PID" 2>/dev/null || true
  wait "$CHARON_PID" 2>/dev/null || true
}
trap cleanup INT TERM EXIT

count=0
until swanctl --stats >/dev/null 2>&1; do
  count=$((count + 1))
  if [ "$count" -ge 45 ]; then
    echo "charon did not expose VICI within 45 seconds" >&2
    exit 1
  fi
  sleep 1
done

swanctl --load-all
wait "$CHARON_PID"
START_EOF
  chmod 0755 "$INSTALL_DIR/strongswan/start-strongswan.sh"
}

write_swanctl_config() {
  local host="$1" vpn_user="$2" vpn_password="$3" vpn_subnet="$4" vpn_dns="$5"
  local dns1 dns2
  dns1="${vpn_dns%%,*}"
  dns2="${vpn_dns#*,}"
  [[ "$dns2" == "$vpn_dns" ]] && dns2=""

  cat > "$INSTALL_DIR/strongswan/swanctl/swanctl.conf" <<CONFIG_EOF
include dashboard-users/*.conf

connections {
    ikev2-eap {
        version = 2
        send_cert = always
        pools = vpn-pool
        proposals = aes256-sha256-modp2048,aes256gcm16-prfsha256-modp2048,aes128-sha256-modp2048
        fragmentation = yes
        mobike = yes
        reauth_time = 0s
        dpd_delay = 30s
        dpd_timeout = 150s
        local_addrs = 0.0.0.0
        remote_addrs = 0.0.0.0

        local {
            auth = pubkey
            certs = server-cert.pem
            id = $host
        }

        remote {
            auth = eap-mschapv2
            eap_id = %any
        }

        children {
            net {
                local_ts = 0.0.0.0/0
                esp_proposals = aes256-sha256,aes256gcm16,aes128-sha256
                dpd_action = clear
                start_action = none
                close_action = none
            }
        }
    }
}

pools {
    vpn-pool {
        addrs = $vpn_subnet
        dns = $dns1${dns2:+, $dns2}
    }
}

secrets {
    private-server {
        file = server-key.pem
    }

    eap-initial-user {
        id = $vpn_user
        secret = "$vpn_password"
    }
}
CONFIG_EOF

  cat > "$INSTALL_DIR/strongswan/dashboard-users/dashboard-users.conf" <<'USERS_EOF'
secrets {
}
USERS_EOF
}

generate_certificates() {
  local host="$1"
  local pki="$INSTALL_DIR/strongswan/swanctl"
  local cert_serial
  cert_serial="0x$(openssl rand -hex 16)"

  log "Generating private CA and server certificate"
  umask 077

  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$pki/private/ca-key.pem"
  openssl req -x509 -new -sha256 -days 3650 \
    -key "$pki/private/ca-key.pem" \
    -subj "/CN=SwanWatch VPN Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$pki/x509ca/ca-cert.pem"

  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$pki/private/server-key.pem"

  cat > "$INSTALL_DIR/strongswan/server-cert.cnf" <<CERT_EOF
[req]
distinguished_name = dn
prompt = no
req_extensions = req_ext

[dn]
CN = $host

[req_ext]
subjectAltName = @alt_names
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = $host
CERT_EOF

  openssl req -new -sha256 \
    -key "$pki/private/server-key.pem" \
    -config "$INSTALL_DIR/strongswan/server-cert.cnf" \
    -out "$INSTALL_DIR/strongswan/server.csr"

  openssl x509 -req -sha256 -days 1825 \
    -in "$INSTALL_DIR/strongswan/server.csr" \
    -CA "$pki/x509ca/ca-cert.pem" \
    -CAkey "$pki/private/ca-key.pem" \
    -set_serial "$cert_serial" \
    -extfile "$INSTALL_DIR/strongswan/server-cert.cnf" \
    -extensions req_ext \
    -out "$pki/x509/server-cert.pem"

  rm -f "$pki/x509ca/ca-cert.srl"
  chmod 0600 "$pki/private"/*.pem
  chmod 0644 "$pki/x509"/*.pem "$pki/x509ca"/*.pem
}

write_firewall_script() {
  local lan_iface="$1" vpn_subnet="$2" dashboard_port="$3" lan_cidr="$4"

  cat > /etc/sysctl.d/99-swanwatch-vpn.conf <<'SYSCTL_EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.accept_redirects=0
SYSCTL_EOF
  sysctl --system >/dev/null

  if [[ "$OS_FAMILY" == "rhel" ]]; then
    log "Configuring firewalld"
    local zone
    zone="$(firewall-cmd --get-zone-of-interface="$lan_iface" 2>/dev/null || true)"
    [[ -n "$zone" && "$zone" != "no zone" ]] || zone="$(firewall-cmd --get-default-zone)"

    firewall-cmd --permanent --zone="$zone" --add-port=500/udp
    firewall-cmd --permanent --zone="$zone" --add-port=4500/udp
    firewall-cmd --permanent --zone="$zone" --add-masquerade
    firewall-cmd --permanent --zone="$zone" \
      --add-rich-rule="rule family=ipv4 source address=$vpn_subnet accept"
    firewall-cmd --permanent --zone="$zone" \
      --add-rich-rule="rule family=ipv4 source address=$lan_cidr port port=$dashboard_port protocol=tcp accept"
    firewall-cmd --reload
  else
    cat > "$INSTALL_DIR/apply-firewall.sh" <<FIREWALL_EOF
#!/usr/bin/env bash
set -Eeuo pipefail
VPN_SUBNET="$vpn_subnet"
LAN_IFACE="$lan_iface"

iptables -t nat -C POSTROUTING -s "\$VPN_SUBNET" -o "\$LAN_IFACE" -m policy --dir out --pol ipsec -j ACCEPT 2>/dev/null || \
  iptables -t nat -I POSTROUTING 1 -s "\$VPN_SUBNET" -o "\$LAN_IFACE" -m policy --dir out --pol ipsec -j ACCEPT
iptables -t nat -C POSTROUTING -s "\$VPN_SUBNET" -o "\$LAN_IFACE" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s "\$VPN_SUBNET" -o "\$LAN_IFACE" -j MASQUERADE
iptables -C FORWARD -s "\$VPN_SUBNET" -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -s "\$VPN_SUBNET" -j ACCEPT
iptables -C FORWARD -d "\$VPN_SUBNET" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -d "\$VPN_SUBNET" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
FIREWALL_EOF
    chmod 0755 "$INSTALL_DIR/apply-firewall.sh"

    cat > /etc/systemd/system/swanwatch-firewall.service <<UNIT_EOF
[Unit]
Description=SwanWatch VPN forwarding and NAT rules
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$INSTALL_DIR/apply-firewall.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT_EOF

    systemctl daemon-reload
    systemctl enable --now swanwatch-firewall.service
  fi
}

write_compose() {
  local host="$1" lan_ip="$2" dashboard_port="$3" dashboard_user="$4" dashboard_password="$5" flask_secret="$6"

  cat > "$INSTALL_DIR/docker-compose.yml" <<COMPOSE_EOF
services:
  strongswan:
    build:
      context: .
      dockerfile: Dockerfile.strongswan
    image: swanwatch-strongswan:6.0.6-mschapv2
    container_name: strongswan
    restart: unless-stopped
    network_mode: host
    privileged: true
    security_opt:
      - label=disable
    command: ["/usr/local/bin/start-strongswan.sh"]
    volumes:
      - ./strongswan/start-strongswan.sh:/usr/local/bin/start-strongswan.sh:ro
      - ./strongswan/swanctl/swanctl.conf:/etc/swanctl/swanctl.conf:ro
      - ./strongswan/swanctl/x509:/etc/swanctl/x509:ro
      - ./strongswan/swanctl/x509ca:/etc/swanctl/x509ca:ro
      - ./strongswan/swanctl/private:/etc/swanctl/private:ro
      - ./strongswan/dashboard-users:/etc/swanctl/dashboard-users:ro

  swanwatch:
    build: ./swanwatch
    container_name: swanwatch
    restart: unless-stopped
    depends_on:
      - strongswan
    security_opt:
      - label=disable
    environment:
      APP_NAME: SwanWatch
      STRONGSWAN_CONTAINER: strongswan
      VPN_HOST: "$host"
      DASHBOARD_USER: "$dashboard_user"
      DASHBOARD_PASSWORD: "$dashboard_password"
      FLASK_SECRET_KEY: "$flask_secret"
      TOTP_SECRET: ""
      NTFY_URL: ""
      ALERT_EVENTS: connect,disconnect,failed-login,service
      MANAGED_CONTAINERS: plex
      PLEX_HOST: host.docker.internal
      PLEX_PORT: "32400"
      DB_PATH: /data/swanwatch.db
      BACKUP_DIR: /data/backups
      CONFIG_ROOT: /config-source
      MANAGED_USERS_FILE: /managed-users/dashboard-users.conf
    extra_hosts:
      - host.docker.internal:host-gateway
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /proc:/host/proc:ro
      - /:/host/root:ro
      - ./strongswan:/config-source:ro
      - swanwatch-data:/data
      - ./strongswan/dashboard-users:/managed-users
    ports:
      - "$lan_ip:$dashboard_port:8085"

volumes:
  swanwatch-data:
COMPOSE_EOF
}

install_files() {
  [[ -d "$APP_SOURCE" ]] || die "Missing bundled SwanWatch source directory: $APP_SOURCE"
  mkdir -p "$INSTALL_DIR/strongswan/swanctl/x509" \
           "$INSTALL_DIR/strongswan/swanctl/x509ca" \
           "$INSTALL_DIR/strongswan/swanctl/private" \
           "$INSTALL_DIR/strongswan/dashboard-users"
  rm -rf "$INSTALL_DIR/swanwatch"
  cp -a "$APP_SOURCE" "$INSTALL_DIR/swanwatch"
}

verify_install() {
  log "Verifying services"
  sleep 5
  compose -f "$INSTALL_DIR/docker-compose.yml" ps

  docker exec strongswan swanctl --list-conns >/dev/null || {
    docker logs strongswan --tail 100 >&2
    die "strongSwan started but no connection could be listed"
  }

  docker exec strongswan swanctl --stats | grep -q 'eap-mschapv2' || {
    docker logs strongswan --tail 100 >&2
    die "strongSwan started without the required eap-mschapv2 plugin"
  }

  curl -fsS "http://$LAN_IP:$DASHBOARD_PORT/health" >/dev/null || {
    docker logs swanwatch --tail 100 >&2
    die "SwanWatch health check failed"
  }
}

main() {
  require_root
  [[ -r /etc/os-release ]] || die "Unable to identify the operating system"
  . /etc/os-release
  case "${ID:-}" in
    debian)
      OS_FAMILY="debian"
      case "${VERSION_ID:-}" in
        12|13) ;;
        *) warn "Debian 12 and 13 are tested; detected ${PRETTY_NAME:-unknown}." ;;
      esac
      ;;
    centos|rhel|rocky|almalinux|ol)
      OS_FAMILY="rhel"
      major="${VERSION_ID%%.*}"
      [[ "$major" =~ ^[0-9]+$ && "$major" -ge 9 ]] || die "CentOS/RHEL-compatible version 9 or newer is required."
      ;;
    *)
      die "Unsupported OS: ${PRETTY_NAME:-${ID:-unknown}}. Supported: Debian 12/13 and CentOS/RHEL-compatible 9+."
      ;;
  esac

  install_dependencies

  local default_iface default_ip
  default_iface="$(get_default_iface)"
  [[ -n "$default_iface" ]] || die "Unable to determine the default network interface"
  default_ip="$(get_iface_ipv4 "$default_iface")"
  [[ -n "$default_ip" ]] || die "Unable to determine an IPv4 address for $default_iface"

  echo
  echo "SwanWatch strongSwan installer"
  echo "This creates a full-tunnel IKEv2 VPN and a LAN-only management dashboard on Debian 12/13 or CentOS/RHEL-compatible Linux."
  echo

  VPN_HOST="$(prompt_default "Public VPN hostname" "vpn.example.com")"
  valid_hostname "$VPN_HOST" || die "Invalid hostname: $VPN_HOST"

  LAN_IFACE="$(prompt_default "Internet/LAN interface" "$default_iface")"
  ip link show "$LAN_IFACE" >/dev/null 2>&1 || die "Interface does not exist: $LAN_IFACE"

  LAN_IP="$(prompt_default "Server LAN IPv4 address" "$default_ip")"
  default_lan_cidr="$(ip -4 route show dev "$LAN_IFACE" proto kernel scope link 2>/dev/null | awk 'NR==1 {print $1}')"
  [[ "$default_lan_cidr" == */* ]] || default_lan_cidr="${LAN_IP%.*}.0/24"
  LAN_CIDR="$(prompt_default "Trusted LAN subnet for dashboard access" "$default_lan_cidr")"
  VPN_SUBNET="$(prompt_default "VPN client subnet" "$VPN_SUBNET_DEFAULT")"
  VPN_DNS="$(prompt_default "VPN DNS servers, comma separated" "$VPN_DNS_DEFAULT")"
  VPN_USER="$(prompt_default "Initial VPN username" "vpnuser")"
  valid_username "$VPN_USER" || die "Invalid VPN username"

  VPN_PASSWORD="$(prompt_secret "Initial VPN password (leave blank to generate)")"
  [[ -n "$VPN_PASSWORD" ]] || VPN_PASSWORD="$(random_secret)"
  [[ "$VPN_PASSWORD" =~ ^[A-Za-z0-9._@%+=:,!#-]{8,128}$ ]] ||     die "VPN password must be 8-128 characters using letters, numbers, or ._@%+=:,!#-"

  DASHBOARD_USER="$(prompt_default "Dashboard username" "admin")"
  valid_username "$DASHBOARD_USER" || die "Invalid dashboard username"
  DASHBOARD_PASSWORD="$(prompt_secret "Dashboard password (leave blank to generate)")"
  [[ -n "$DASHBOARD_PASSWORD" ]] || DASHBOARD_PASSWORD="$(random_secret)"
  [[ "$DASHBOARD_PASSWORD" =~ ^[A-Za-z0-9._@%+=:,!#-]{10,128}$ ]] ||     die "Dashboard password must be 10-128 characters using letters, numbers, or ._@%+=:,!#-"
  DASHBOARD_PORT="$(prompt_default "Dashboard TCP port" "$DASHBOARD_PORT_DEFAULT")"
  [[ "$DASHBOARD_PORT" =~ ^[0-9]+$ ]] || die "Dashboard port must be numeric"
  FLASK_SECRET="$(openssl rand -hex 32)"

  backup_existing
  install_files
  write_strongswan_dockerfile
  write_start_script
  write_swanctl_config "$VPN_HOST" "$VPN_USER" "$VPN_PASSWORD" "$VPN_SUBNET" "$VPN_DNS"
  generate_certificates "$VPN_HOST"
  write_firewall_script "$LAN_IFACE" "$VPN_SUBNET" "$DASHBOARD_PORT" "$LAN_CIDR"
  write_compose "$VPN_HOST" "$LAN_IP" "$DASHBOARD_PORT" "$DASHBOARD_USER" "$DASHBOARD_PASSWORD" "$FLASK_SECRET"

  log "Building and starting strongSwan and SwanWatch"
  cd "$INSTALL_DIR"
  compose up -d --build
  verify_install

  cat > "$INSTALL_DIR/INSTALL-CREDENTIALS.txt" <<CREDENTIALS_EOF
SwanWatch installation details
Generated: $(date -Is)

VPN hostname: $VPN_HOST
VPN type: IKEv2 EAP (username/password)
VPN username: $VPN_USER
VPN password: $VPN_PASSWORD
CA certificate: $INSTALL_DIR/strongswan/swanctl/x509ca/ca-cert.pem
VPN subnet: $VPN_SUBNET

Dashboard URL: http://$LAN_IP:$DASHBOARD_PORT
Dashboard username: $DASHBOARD_USER
Dashboard password: $DASHBOARD_PASSWORD

Router forwarding required:
UDP 500 -> $LAN_IP
UDP 4500 -> $LAN_IP
CREDENTIALS_EOF
  chmod 0600 "$INSTALL_DIR/INSTALL-CREDENTIALS.txt"

  log "Installation complete"
  cat <<SUMMARY_EOF

Dashboard:
  http://$LAN_IP:$DASHBOARD_PORT

VPN client settings:
  Server:   $VPN_HOST
  Type:     IKEv2 EAP (username/password)
  Username: $VPN_USER
  Password: $VPN_PASSWORD

Dashboard login:
  Username: $DASHBOARD_USER
  Password: $DASHBOARD_PASSWORD

Import this CA certificate on clients:
  $INSTALL_DIR/strongswan/swanctl/x509ca/ca-cert.pem

Forward these router ports to $LAN_IP:
  UDP 500
  UDP 4500

Credentials were saved root-only at:
  $INSTALL_DIR/INSTALL-CREDENTIALS.txt

Useful commands:
  cd $INSTALL_DIR && docker compose ps
  docker exec strongswan swanctl --list-conns
  docker exec strongswan swanctl --list-sas
  docker logs strongswan --tail 100
  docker logs swanwatch --tail 100
SUMMARY_EOF
}

main "$@"
