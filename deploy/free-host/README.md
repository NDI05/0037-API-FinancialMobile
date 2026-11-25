# Deploy host gratis (Ubuntu/Oracle/GCP)

Artefak ini untuk satu VM Linux kecil yang menjalankan proses Go terus-menerus
(perlu untuk polling Gmail). Database memakai Turso/libSQL, jadi VM tidak butuh
disk persisten besar.

## Bangun binary

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  PAM_GOROOT="$(git rev-parse --show-toplevel)/.toolchain/go" \
  ./.toolchain/go/bin/go build -trimpath -ldflags="-s -w" -o pam-api ./cmd/api
```

Ganti `GOARCH=amd64` untuk VM AMD64.

## Bootstrap host

```bash
scp deploy/free-host -r <user>@<ip>:~/
scp pam-api <user>@<ip>:~/
ssh <user>@<ip> 'cd free-host && sudo ./bootstrap.sh pam-<ip-dengan-dash>.sslip.io ~/pam-api'
```

Domain `*.sslip.io` gratis dan TLS otomatis dari Caddy (Let's Encrypt). Setelah
env `/etc/pam/pam-api.env` diisi, jalankan:

```bash
sudo systemctl restart pam-api
curl -fsS https://<domain>/healthz
curl -fsS https://<domain>/readyz
```

## Validasi artefak (25 November 2026)

- `bash -n bootstrap.sh` → lolos (sintaks).
- `Caddyfile` divalidasi dengan image resmi `caddy:2` (`caddy validate`) → **Valid configuration**.
- Image Docker dibangun di mesin pengembang dan smoke container membuktikan `/healthz` + `/readyz`
  **200** (DB sementara, provider fake).
- Unit systemd belum bisa divalidasi di macOS; `bootstrap.sh` menjalankan `systemctl daemon-reload`
  dan `systemctl restart pam-api`, jadi kesalahan unit akan terlihat langsung saat bootstrap di VM.

Rollback: simpan binary lama (`cp /opt/pam-api/pam-api /opt/pam-api/pam-api.bak`),
lalu `install -m 0755 pam-api.bak /opt/pam-api/pam-api && systemctl restart pam-api`.
