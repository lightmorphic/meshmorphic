#!/usr/bin/env bash
#
# Add a server to the MeshMorphic network as a gateway, an edge, or both.
#
# This is the script that makes volunteer redundancy real. Running a gateway is
# close to free — it holds nothing, stores nothing, and carries no traffic — so
# the network gets more resilient every time somebody runs this on a spare box.
#
#   bash install-node.sh --role gateway --domains awwe.uk --public-host gw2.awwe.uk
#   bash install-node.sh --role edge    --domains awwe.uk --public-host edge2.awwe.uk \
#                        --gateways "gw1.awwe.uk:7777|BASE64KEY"
#   bash install-node.sh --role both    --domains awwe.uk --public-host mesh1.awwe.uk
#
# There is nothing secret to supply. No account, no token, no registration.
# The node generates its own key on first start and tells you what to publish.

set -euo pipefail

ROLE="both"
DOMAINS="awwe.uk"
PUBLIC_HOST=""
GATEWAYS=""
SEEDS=""
SSH_PORT="22"
SKIP_HARDEN="no"
REPO="https://github.com/lightmorphic/meshmorphic.git"
BRANCH="main"
GO_VERSION="1.25.13"

say()  { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m !\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m✗\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  cat <<'EOF'

Options:
  --role gateway|edge|both   what this server should run (default: both)
  --domains a.uk,b.uk        mesh domains this node serves (default: awwe.uk)
  --public-host NAME         the DNS name others reach this server on
  --gateways "addr|key,..."  gateways an edge announces itself to
  --seeds "addr|key,..."     other gateways to tell agents about
  --ssh-port N               your SSH port, so the firewall keeps it open
  --skip-hardening           do not touch the firewall, SSH or updates
  -h, --help                 this message
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --role)           ROLE="$2"; shift 2 ;;
    --domains)        DOMAINS="$2"; shift 2 ;;
    --public-host)    PUBLIC_HOST="$2"; shift 2 ;;
    --gateways)       GATEWAYS="$2"; shift 2 ;;
    --seeds)          SEEDS="$2"; shift 2 ;;
    --ssh-port)       SSH_PORT="$2"; shift 2 ;;
    --skip-hardening) SKIP_HARDEN="yes"; shift ;;
    -h|--help)        usage; exit 0 ;;
    *) die "Unknown option: $1 (try --help)" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "Run this as root."
case "$ROLE" in gateway|edge|both) ;; *) die "--role must be gateway, edge or both" ;; esac

if [ -z "$PUBLIC_HOST" ]; then
  # Falling back to the machine's own IP is better than failing, but a name is
  # what should be published: an IP that changes strands everyone using it.
  PUBLIC_HOST="$(curl -fsS --max-time 10 https://api.ipify.org 2>/dev/null || true)"
  [ -n "$PUBLIC_HOST" ] || die "Could not work out this server's public address. Pass --public-host."
  warn "No --public-host given; using this server's IP address ($PUBLIC_HOST)."
  warn "A DNS name is strongly preferred, so the address can change later."
fi

if [ "$ROLE" != "gateway" ] && [ -z "$GATEWAYS" ]; then
  warn "No --gateways given. This edge will work, but no agent will ever be"
  warn "told it exists, so nothing will use it. Re-run with --gateways once"
  warn "you know a gateway's address and public key."
fi

# ------------------------------------------------------------- hardening -----

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$SKIP_HARDEN" = "no" ]; then
  say "Securing this server first"
  if [ -f "$SCRIPT_DIR/harden.sh" ]; then
    ROLE="$ROLE" SSH_PORT="$SSH_PORT" bash "$SCRIPT_DIR/harden.sh"
  else
    warn "harden.sh not found next to this script; skipping."
  fi
fi

# ----------------------------------------------------------------- build -----

say "Building MeshMorphic from source"
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq git curl ca-certificates >/dev/null

# Go is installed under /usr/local and used only to build. Building from source
# on the machine means the operator can read exactly what they are running,
# which matters more here than shipping a convenient binary.
if ! /usr/local/go/bin/go version >/dev/null 2>&1; then
  ARCH="$(dpkg --print-architecture)"
  case "$ARCH" in
    amd64) GOARCH=amd64 ;;
    arm64) GOARCH=arm64 ;;
    *) die "Unsupported architecture: $ARCH" ;;
  esac
  say "Installing Go ${GO_VERSION}"
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" -o /tmp/go.tgz
  rm -rf /usr/local/go
  tar -C /usr/local -xzf /tmp/go.tgz
  rm -f /tmp/go.tgz
fi
export PATH=/usr/local/go/bin:$PATH

BUILD_DIR="/opt/meshmorphic-src"
if [ -d "$BUILD_DIR/.git" ]; then
  git -C "$BUILD_DIR" fetch --quiet origin "$BRANCH"
  git -C "$BUILD_DIR" reset --hard --quiet "origin/$BRANCH"
else
  rm -rf "$BUILD_DIR"
  git clone --quiet --branch "$BRANCH" --depth 1 "$REPO" "$BUILD_DIR"
fi

cd "$BUILD_DIR"
COMMIT="$(git rev-parse --short HEAD)"
say "Building commit ${COMMIT}"
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /usr/local/bin/mm-gateway ./cmd/mm-gateway
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /usr/local/bin/mm-edge    ./cmd/mm-edge
chmod 0755 /usr/local/bin/mm-gateway /usr/local/bin/mm-edge

mkdir -p /etc/meshmorphic
chmod 0755 /etc/meshmorphic

# --------------------------------------------------------------- gateway -----

install_gateway() {
  say "Installing the gateway service"
  id -u meshmorphic-gw >/dev/null 2>&1 || \
    useradd --system --no-create-home --shell /usr/sbin/nologin meshmorphic-gw

  install -d -o meshmorphic-gw -g meshmorphic-gw -m 0700 /var/lib/meshmorphic-gateway

  cat > /etc/meshmorphic/gateway.env <<EOF
# MeshMorphic gateway settings.
# There is nothing sensitive in this file. There is nothing sensitive on this
# whole machine: a gateway stores no peer data and holds no key that decrypts
# anyone's traffic.
MM_LISTEN=:7777
MM_DOMAINS=${DOMAINS}
MM_SEEDS=${SEEDS}
MM_STATUS=127.0.0.1:9440
EOF
  chmod 0644 /etc/meshmorphic/gateway.env

  install -m 0644 "$SCRIPT_DIR/meshmorphic-gateway.service" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now meshmorphic-gateway

  # Generate the identity now so it can be printed, rather than making the
  # operator go and find it in a log.
  sleep 2
}

install_edge() {
  say "Installing the edge service"
  id -u meshmorphic-edge >/dev/null 2>&1 || \
    useradd --system --no-create-home --shell /usr/sbin/nologin meshmorphic-edge

  install -d -o meshmorphic-edge -g meshmorphic-edge -m 0700 /var/lib/meshmorphic-edge

  cat > /etc/meshmorphic/edge.env <<EOF
# MeshMorphic edge settings.
# This machine terminates no TLS and holds no certificate key. Traffic crossing
# it is encrypted end to end between each visitor and each home server.
MM_TUNNEL=:7443
MM_HTTPS=:443
MM_HTTP=:80
MM_DOMAINS=${DOMAINS}
MM_GATEWAYS=${GATEWAYS}
MM_PUBLIC_ADDR=${PUBLIC_HOST}:7443
MM_STATUS=127.0.0.1:9441
EOF
  chmod 0644 /etc/meshmorphic/edge.env

  install -m 0644 "$SCRIPT_DIR/meshmorphic-edge.service" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now meshmorphic-edge
  sleep 2
}

case "$ROLE" in
  gateway) install_gateway ;;
  edge)    install_edge ;;
  both)    install_gateway; install_edge ;;
esac

# ------------------------------------------------------------------ done -----

say "Installed"

GW_LINE=""
EDGE_LINE=""

if [ "$ROLE" = "gateway" ] || [ "$ROLE" = "both" ]; then
  GW_KEY="$(runuser -u meshmorphic-gw -- /usr/local/bin/mm-gateway \
              -state /var/lib/meshmorphic-gateway -identity -public-addr "${PUBLIC_HOST}:7777" \
              2>/dev/null | awk '/pubkey:/ {print $2}')"
  [ -n "$GW_KEY" ] && GW_LINE="${PUBLIC_HOST}:7777|${GW_KEY}"
fi
if [ "$ROLE" = "edge" ] || [ "$ROLE" = "both" ]; then
  EDGE_KEY="$(runuser -u meshmorphic-edge -- /usr/local/bin/mm-edge \
                -state /var/lib/meshmorphic-edge -identity -public-addr "${PUBLIC_HOST}:7443" \
                2>/dev/null | awk '/pubkey:/ {print $2}')"
  [ -n "$EDGE_KEY" ] && EDGE_LINE="${PUBLIC_HOST}:7443|${EDGE_KEY}"
fi

cat <<EOF

────────────────────────────────────────────────────────────────────────
 This server is now part of the MeshMorphic network.
────────────────────────────────────────────────────────────────────────

EOF

if [ -n "$GW_LINE" ]; then
cat <<EOF
 GATEWAY — publish this so people can bootstrap from your server:

   $GW_LINE

 The address and the key always travel together. An address on its own is
 not usable: an agent will not talk to a gateway without knowing which key
 should answer there.

EOF
fi

if [ -n "$EDGE_LINE" ]; then
cat <<EOF
 EDGE — this announces itself to the gateways you configured, so nothing
 needs publishing by hand. For reference, its identity is:

   $EDGE_LINE

EOF
fi

cat <<EOF
 DNS you need to set up:

EOF

if [ -n "$EDGE_LINE" ]; then
cat <<EOF
   ${PUBLIC_HOST}          A/AAAA →  this server's IP
   *.${DOMAINS%%,*}        A/AAAA →  this server's IP   (wildcard, so every
                                     site on the mesh resolves to an edge)
EOF
fi
if [ -n "$GW_LINE" ]; then
cat <<EOF
   ${PUBLIC_HOST}          A/AAAA →  this server's IP
EOF
fi

cat <<EOF

 Check it is running:

   systemctl status meshmorphic-gateway meshmorphic-edge --no-pager
   curl -s localhost:9440/status   # gateway
   curl -s localhost:9441/status   # edge

 Built from commit ${COMMIT}.

EOF
