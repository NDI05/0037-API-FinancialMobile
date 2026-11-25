#!/usr/bin/env bash
# Bootstrap host gratis (Ubuntu 24.04, root) untuk PAM API + Caddy HTTPS.
# Pakai: sudo ./bootstrap.sh <domain-https> <path-ke-binary-linux>
# Binary dibangun di mesin lain: CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o pam-api ./cmd/api
set -euo pipefail

DOMAIN="${1:?domain wajib, mis. pam-1-2-3-4.sslip.io}"
BINARY="${2:?path binary pam-api wajib}"
ARCH="$(dpkg --print-architecture)"

install -d -m 0755 /opt/pam-api /var/lib/pam-api /etc/pam /etc/caddy /var/log/caddy
if ! id -u pam >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/pam-api --shell /usr/sbin/nologin pam
fi
chown -R pam:pam /var/lib/pam-api

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl ufw
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

install -m 0755 "$BINARY" /opt/pam-api/pam-api

if [ ! -f /etc/pam/pam-api.env ]; then
  cat > /etc/pam/pam-api.env <<ENV
# Isi nilai sebenarnya lalu chmod 600. Jangan commit file ini.
APP_ENV=production
PORT=8080
LOG_LEVEL=info
DATABASE_URL=
DATABASE_AUTH_TOKEN=
JWT_SECRET=
JWT_ISSUER=pam-api
JWT_AUDIENCE=pam-android
ACCESS_TOKEN_TTL_SECONDS=900
DATA_ENCRYPTION_KEY=
DATA_KEY_VERSION=1
GOOGLE_SSO_ENABLED=true
GOOGLE_SSO_CLIENT_ID=
GMAIL_ENABLED=false
GMAIL_MODE=polling
GMAIL_CLIENT_ID=
GMAIL_CLIENT_SECRET=
GMAIL_REDIRECT_URI=https://$DOMAIN/v1/gmail/connect/callback
GMAIL_DELTA_INTERVAL_SECONDS=900
LLM_PROVIDER=fake
CATEGORY_LLM_ENABLED=false
ENV
  chmod 600 /etc/pam/pam-api.env
  echo "!! Isi /etc/pam/pam-api.env lalu jalankan ulang: systemctl restart pam-api" >&2
fi

sed "s/@DOMAIN@/$DOMAIN/" "$(dirname "$0")/Caddyfile" > /etc/caddy/Caddyfile

if [ ! -x /usr/local/bin/caddy ]; then
  curl -fsSL "https://caddyserver.com/api/download?os=linux&arch=$ARCH" -o /usr/local/bin/caddy
  chmod 0755 /usr/local/bin/caddy
fi

install -m 0644 "$(dirname "$0")/pam-api.service" /etc/systemd/system/pam-api.service
install -m 0644 "$(dirname "$0")/caddy.service" /etc/systemd/system/caddy.service
systemctl daemon-reload
systemctl enable --now pam-api caddy
systemctl --no-pager --full status pam-api caddy | sed -n '1,40p'
echo "Cek: curl -fsS https://$DOMAIN/healthz"
