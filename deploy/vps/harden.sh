#!/usr/bin/env bash
#
# Baseline hardening for a fresh Debian 13 server that is about to run a
# MeshMorphic gateway or edge.
#
# This is deliberately readable and deliberately conservative. Anyone
# volunteering a server to this network should be able to read every line here
# before running it, and nothing in it should surprise them afterwards.
#
# What it does:
#   · keeps security updates applying by themselves
#   · closes every port except the ones actually needed
#   · slows down anyone guessing at the SSH login
#   · turns off password logins, but only when that will not lock you out
#   · applies a handful of kernel network settings
#
# Run as root:  bash harden.sh

set -euo pipefail

SSH_PORT="${SSH_PORT:-22}"
ROLE="${ROLE:-both}"   # gateway | edge | both

say()  { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m !\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m✗\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run this as root."

if [ -r /etc/os-release ]; then
  . /etc/os-release
  case "${ID:-}" in
    debian|ubuntu) ;;
    *) warn "This was written for Debian. Detected '${ID:-unknown}'; continuing anyway." ;;
  esac
fi

# ---------------------------------------------------------------- packages ---

say "Updating the system"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get -y -qq upgrade

say "Installing the tools this server needs"
apt-get install -y -qq \
  ufw \
  fail2ban \
  unattended-upgrades \
  apt-listchanges \
  ca-certificates \
  curl \
  chrony \
  needrestart

# ------------------------------------------------------- automatic updates ---

say "Turning on automatic security updates"
# A volunteer-run server that nobody logs into for six months should still be
# patched. This is the single highest-value thing on this list.
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

cat > /etc/apt/apt.conf.d/51meshmorphic-unattended <<'EOF'
// Security updates apply automatically. Reboots are left to the operator:
// an edge rebooting unannounced drops the connections it is carrying.
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF

systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true

# --------------------------------------------------------------- time sync ---

say "Making sure the clock is accurate"
# Certificate validity and QUIC both care about the clock. A server hours out
# of step produces failures that are miserable to diagnose.
systemctl enable --now chrony >/dev/null 2>&1 || true

# ---------------------------------------------------------------- firewall ---

say "Setting up the firewall"
ufw --force reset >/dev/null

ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null

# SSH first and always, before anything is enabled. Locking yourself out of a
# remote server is the classic way this kind of script ruins an afternoon.
ufw allow "${SSH_PORT}"/tcp comment 'SSH' >/dev/null

case "$ROLE" in
  gateway|both)
    ufw allow 7777/udp comment 'MeshMorphic gateway (introductions)' >/dev/null
    ;;
esac
case "$ROLE" in
  edge|both)
    ufw allow 80/tcp   comment 'MeshMorphic edge (visitor HTTP)'  >/dev/null
    ufw allow 443/tcp  comment 'MeshMorphic edge (visitor HTTPS)' >/dev/null
    ufw allow 7443/udp comment 'MeshMorphic edge (agent tunnels)' >/dev/null
    ;;
esac

ufw --force enable >/dev/null
say "Firewall is on. Open ports:"
ufw status numbered | sed 's/^/    /'

# ------------------------------------------------------------------- ssh -----

say "Hardening SSH"

# Refuse to disable password logins unless a key is already in place. Doing it
# blindly is how people lock themselves out of a server they are holding.
have_key=no
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  [ -s "$f" ] && have_key=yes && break
done

mkdir -p /etc/ssh/sshd_config.d
if [ "$have_key" = yes ]; then
  cat > /etc/ssh/sshd_config.d/50-meshmorphic.conf <<EOF
# Keys only. A password that can be guessed from the internet is the most
# likely way this server gets taken, and it is entirely avoidable.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
PubkeyAuthentication yes

# Reduce the window for an unauthenticated connection to sit there.
LoginGraceTime 20
MaxAuthTries 3
MaxSessions 4

# Nothing here needs these.
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no
EOF
  say "Password logins disabled (an SSH key is already installed)"
else
  cat > /etc/ssh/sshd_config.d/50-meshmorphic.conf <<EOF
# No SSH key was found on this machine, so password logins have been LEFT ON
# to avoid locking you out. Install a key, then set PasswordAuthentication to
# no and reload ssh.
PermitRootLogin prohibit-password
LoginGraceTime 20
MaxAuthTries 3
MaxSessions 4
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no
EOF
  warn "No SSH key found, so password logins were left enabled."
  warn "Add your key, then set 'PasswordAuthentication no' in"
  warn "/etc/ssh/sshd_config.d/50-meshmorphic.conf and run: systemctl reload ssh"
fi

if sshd -t 2>/dev/null; then
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
else
  warn "The SSH config did not validate; leaving the running service alone."
fi

# --------------------------------------------------------------- fail2ban ----

say "Setting up fail2ban"
# Worth being honest about scope: this protects SSH. It does nothing for the
# MeshMorphic services, and it does not need to — those authenticate with keys
# over QUIC, so there is no password there to guess at.
cat > /etc/fail2ban/jail.d/meshmorphic.local <<EOF
[DEFAULT]
backend = systemd
bantime = 1h
findtime = 10m
maxretry = 5
# A repeat offender earns a longer ban each time.
bantime.increment = true
bantime.factor = 2
bantime.maxtime = 1w

[sshd]
enabled = true
port = ${SSH_PORT}
maxretry = 3
EOF

systemctl enable --now fail2ban >/dev/null 2>&1 || true

# ----------------------------------------------------------------- sysctl ----

say "Applying network settings"
cat > /etc/sysctl.d/60-meshmorphic.conf <<'EOF'
# Ignore obviously forged traffic and log what is left.
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.log_martians = 1

# Survive a SYN flood rather than falling over.
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096

# QUIC moves a lot of data through UDP sockets, and the kernel defaults are
# far too small for it. Without this, quic-go warns on every start and
# throughput suffers.
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576

# An edge holds many concurrent connections.
net.core.somaxconn = 4096
fs.file-max = 262144

# Do not hand out kernel addresses to unprivileged processes.
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
EOF

sysctl --system >/dev/null 2>&1 || warn "Some sysctl settings did not apply."

# ------------------------------------------------------------------ done -----

say "Hardening complete"
cat <<EOF

  Automatic security updates    on
  Firewall                      on, default deny inbound
  fail2ban                      on, watching SSH
  SSH password logins           $([ "$have_key" = yes ] && echo "off" || echo "ON — install a key and turn these off")
  Clock synchronisation         on

EOF
