# PAM Backend (Go) — 0037 Backend Financial

Backend resmi PAM: REST API, sinkronisasi Gmail (Gmail API + Pub/Sub push), impor riwayat Livin
setahun, satu job kategorisasi Azure Foundry, retensi setahun, dan dukungan lampiran/analisis.

Repositori Android (klien): <https://github.com/NDI05/0037_FinancialMobile>.
Kontrak API: [`docs/API_CONTRACT.md`](docs/API_CONTRACT.md).

## Asal repo

Source diekstrak dari `0037_FinancialMobile` path `backend-go/` pada commit `cd0f91a`
(subtree split, 32 commit riwayat dipertahankan). Pemilik kontrak API: repo ini; klien Android
mengikuti `docs/API_CONTRACT.md`.

## Toolchain

Go **1.27.4**. Dari clone bersih:

```bash
# pilih salah satu
export PAM_GOROOT=/path/to/go1.27.4        # GOROOT yang sudah ada
# atau: curl -L -o go.tar.gz https://go.dev/dl/go1.27.4.darwin-arm64.tar.gz
./scripts/go.sh version
```

`scripts/go.sh` memakai `PAM_GOROOT`, lalu `.toolchain/go` di root repo, lalu `go` di `PATH`.

## Build, test, vet

```bash
./scripts/go.sh build ./...
./scripts/go.sh vet ./...
./scripts/go.sh test ./... -count=1
./scripts/go.sh test -race ./...
./scripts/go.sh build -o bin/pam-api ./cmd/api
```

CI: `.github/workflows/ci.yml` menjalankan vet + test pada setiap push/PR.

## Menjalankan server

```bash
cp .env.example .env   # isi nilai lokal; JANGAN commit .env
set -a; . ./.env; set +a
./scripts/go.sh run ./cmd/api
```

`DATABASE_URL` boleh `file:...` (SQLite lokal) atau `libsql://...` (Turso). Token Turso hanya
dibaca dari `DATABASE_AUTH_TOKEN`; jangan pernah menaruhnya di APK, repo, log, atau laporan.
Untuk UAT, port aktif adalah `18090` (lihat `APP_ENV`, `PORT`).

Health: `GET /healthz` (liveness) dan `GET /readyz` (database siap).

## Secret dan data

- Secret OAuth Google, refresh token, kunci JWT/enkripsi, kredensial Turso/Azure **tidak boleh**
  masuk repo. Gunakan env lokal/secret manager.
- Jangan menyimpan email mentah, PAN, nomor referensi, atau ID Gmail mentah di DB/log/Git.
- Fixture di `fixtures/interop/` hanya berisi data sintetis untuk uji kompatibilitas format.

## Struktur

```
cmd/api, cmd/pam-admin     bootstrap HTTP dan utilitas admin
internal/config            environment + production secret checks
internal/crypto            AES-256-GCM (kompatibel format Node)
internal/auth              scrypt, JWT HS256, refresh token
internal/store             database/sql libSQL + migrasi 001–016
internal/finance           kalkulator deterministik BR-01…BR-06
internal/categoryllm       kategorisasi Azure Foundry + cache/budget
internal/analysis          snapshot analisis
internal/httpapi           rute HTTP, middleware, validasi
fixtures/interop           fixture sintetis kompatibilitas
scripts                    go.sh, smoke.sh
```
