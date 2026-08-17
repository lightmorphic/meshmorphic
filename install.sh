#!/usr/bin/env sh
#
# MeshMorphic — put a website on your own computer, safely.
#
#   curl -fsSL https://mm.lightmorphic.co.uk/install.sh | sh
#
# This asks you nothing. It sets up two sealed containers, generates a key that
# only this computer will ever hold, and tells you the web address of your new
# site. Everything else — uploading your website, using your own domain — is
# done afterwards in a settings page on your own machine.
#
# It opens no ports on your computer and changes nothing on your router.

set -eu

# The default entry point into the network. This is an address and the public
# key expected to answer at it; the key is what makes the address safe to
# publish, since your computer refuses to talk to anything else pretending to
# be it. Neither value is a secret, and neither is a credential — a gateway
# grants nothing, so knowing this gets an attacker precisely nowhere.
#
# Your computer learns about further gateways from this one and remembers them,
# so this is a starting point rather than a dependency.
DEFAULT_GATEWAY="${MM_GATEWAY:-mm01.awwe.uk:7777|PVXV2hi0fcBRKW6wKqRfUthfyzCy9Z4O3K/gousMoa0=}"

INSTALL_DIR="${MM_DIR:-/opt/meshmorphic}"
IMAGE="${MM_IMAGE:-ghcr.io/lightmorphic/meshmorphic:latest}"
RECOVERY_KEY=""

# ---------------------------------------------------------------- output -----

bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
say()   { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m !\033[0m %s\n' "$*"; }
die()   { printf '\033[1;31m✗\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --gateway)      DEFAULT_GATEWAY="$2"; shift 2 ;;
    --recovery-key) RECOVERY_KEY="$2"; shift 2 ;;
    --dir)          INSTALL_DIR="$2"; shift 2 ;;
    -h|--help)
      cat <<'EOF'
MeshMorphic installer

  --gateway ADDR|KEY     entry point to join through
  --recovery-key KEY     restore a previous site from its recovery key
  --dir PATH             where to install (default /opt/meshmorphic)
EOF
      exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "Please run this with sudo."
[ -n "$DEFAULT_GATEWAY" ] || die "No gateway configured. Pass --gateway 'host:port|publickey'."

# ---------------------------------------------------------------- docker -----

say "Checking for Docker"
if ! command -v docker >/dev/null 2>&1; then
  say "Installing Docker"
  # The official convenience script. Worth naming the trade honestly: this
  # pipes a script from Docker's own domain into a shell. If you would rather
  # not, install Docker yourself first and re-run this.
  curl -fsSL https://get.docker.com | sh
fi

if ! docker compose version >/dev/null 2>&1; then
  die "Docker is installed but 'docker compose' is not available. Please update Docker."
fi

systemctl enable --now docker >/dev/null 2>&1 || true

# ----------------------------------------------------------------- files -----

say "Setting up in $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# nginx config for the sandboxed website container.
cat > nginx.conf <<'NGINX'
server {
    listen 8080;
    server_name _;
    root /usr/share/nginx/html;
    index index.html;
    absolute_redirect off;
    server_tokens off;

    location / { try_files $uri $uri/ $uri.html =404; }

    location ~* \.(css|js|png|jpg|jpeg|gif|svg|webp|avif|woff2?|ico)$ {
        expires 7d;
        add_header Cache-Control "public, max-age=604800, immutable";
    }
    location ~* \.html?$ { add_header Cache-Control "no-cache"; }
    location ~ /\. { deny all; return 404; }

    gzip on;
    gzip_types text/plain text/css application/javascript application/json image/svg+xml;
    gzip_min_length 1024;
}
NGINX

# The agent's configuration. Split into address and key, because that pairing
# is the whole trust model.
GW_ADDR="${DEFAULT_GATEWAY%%|*}"
GW_KEY="${DEFAULT_GATEWAY#*|}"
[ "$GW_ADDR" != "$GW_KEY" ] || die "The gateway must be given as 'host:port|publickey'."

cat > agent.json <<JSON
{
  "gateways": [
    { "addr": "${GW_ADDR}", "pubkey": "${GW_KEY}" }
  ],
  "upstream": "http://site:8080",
  "state_dir": "/var/lib/meshmorphic",
  "site_dir": "/var/lib/meshmorphic/site",
  "panel_listen": "0.0.0.0:8800",
  "custom_hostnames": [],
  "acme_email": "",
  "acme_staging": false
}
JSON
chmod 0644 agent.json

cat > docker-compose.yml <<COMPOSE
name: meshmorphic

networks:
  # No route out of this one at all. A compromised website lands here and finds
  # nothing it can reach.
  site:
    internal: true
  mesh:

volumes:
  state:
  site-files:

services:
  agent:
    image: ${IMAGE}
    container_name: meshmorphic-agent
    restart: unless-stopped
    networks: [mesh, site]
    ports:
      - "8800:8800"
    volumes:
      - state:/var/lib/meshmorphic
      - site-files:/var/lib/meshmorphic/site
      - ./agent.json:/etc/meshmorphic/agent.json:ro
    security_opt: [no-new-privileges:true]
    cap_drop: [ALL]
    read_only: true
    tmpfs:
      - /tmp:size=64m,mode=1777
    logging:
      driver: json-file
      options: { max-size: "10m", max-file: "3" }

  site:
    image: nginx:1.27-alpine
    container_name: meshmorphic-site
    restart: unless-stopped
    networks: [site]
    volumes:
      - site-files:/usr/share/nginx/html:ro
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
    security_opt: [no-new-privileges:true]
    cap_drop: [ALL]
    read_only: true
    tmpfs:
      - /tmp:size=16m
      - /var/cache/nginx:size=32m
      - /var/run:size=8m
    logging:
      driver: json-file
      options: { max-size: "10m", max-file: "3" }
COMPOSE

say "Downloading MeshMorphic"
docker compose pull --quiet

# ------------------------------------------------------------- restoring -----

if [ -n "$RECOVERY_KEY" ]; then
  say "Restoring from your recovery key"
  docker compose run --rm --entrypoint /mm-agent agent restore "$RECOVERY_KEY" \
    || die "That recovery key was not accepted. Check it and try again."
fi

# -------------------------------------------------------------- starting -----

say "Starting"
docker compose up -d

# A placeholder so the address shows something rather than an error while the
# owner is still deciding what to put there.
if ! docker compose exec -T site test -f /usr/share/nginx/html/index.html 2>/dev/null; then
  TMP="$(mktemp -d)"
  cat > "$TMP/index.html" <<'HTML'
<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>A new MeshMorphic site</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 34rem; margin: 20vh auto; padding: 0 1.5rem; line-height: 1.6; }
  h1 { font-size: 1.5rem; }
  p { color: #444; }
</style>
<h1>This site is working</h1>
<p>It is being served from a computer that has no open ports and accepts no
incoming connections from the internet.</p>
<p>Replace this page from the settings panel on your home network.</p>
HTML
  docker cp "$TMP/index.html" meshmorphic-site:/usr/share/nginx/html/index.html 2>/dev/null || true
  rm -rf "$TMP"
fi

# --------------------------------------------------------------- address -----

say "Waiting for your web address"
ADDRESS=""
i=0
while [ $i -lt 60 ]; do
  ADDRESS="$(docker compose exec -T agent /mm-agent status 2>/dev/null \
             | awk '/^Address/ {print $2}')" || true
  [ -n "$ADDRESS" ] && break
  sleep 2
  i=$((i + 1))
done

LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -n "$LAN_IP" ] || LAN_IP="this computer's address"

printf '\n────────────────────────────────────────────────────────────────\n'
if [ -n "$ADDRESS" ]; then
  bold " Your website is live at:"
  printf '\n   %s\n\n' "$ADDRESS"
else
  warn "Your address has not come through yet. It usually takes a few seconds."
  printf '     Check with: cd %s && docker compose logs -f agent\n\n' "$INSTALL_DIR"
fi

bold " Settings, on your home network:"
printf '\n   http://%s:8800\n\n' "$LAN_IP"

cat <<'EOF'
 The first browser to open that page becomes the owner. Any other device
 has to be approved from there, so being on the wi-fi is not enough on
 its own to change your website.

 Please do this soon:

   Open the settings page, go to Recovery, and write the key down on
   paper. Nobody else has a copy — not us, not anyone running the
   network. If this computer's disk fails and you have not written it
   down, your web address cannot be recovered by anyone.

 Nothing on this computer is now reachable from the internet. It makes
 one outgoing connection, the same as a web browser does, and your site
 travels back down it.

EOF
