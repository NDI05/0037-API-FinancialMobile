# PAM Backend (Go) — 0037 Backend Financial

Backend resmi PAM: REST API, sinkronisasi Gmail dengan **polling default 15 menit** (push Pub/Sub
hanya opt-in rollback), impor riwayat Livin setahun, satu job kategorisasi Azure Foundry,
retensi setahun, dan dukungan lampiran/analisis.

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

## Google SSO

Login "Masuk dengan Google" memakai Credential Manager di Android; backend memverifikasi ID
token (RS256, JWKS Google, issuer, audience = Web Client ID, expiry, nonce sekali pakai) lalu
menerbitkan sesi PAM yang sama seperti login kata sandi. Akun lama menautkan identitas Google
secara eksplisit (`POST /v1/auth/google/link`); tidak ada pembuatan akun otomatis dan email yang
sama tidak pernah menggabungkan akun.

- Kontrak: [`docs/GOOGLE_SSO_CONTRACT.md`](docs/GOOGLE_SSO_CONTRACT.md)
- Env: `GOOGLE_SSO_ENABLED` (default `false`), `GOOGLE_SSO_CLIENT_ID` (Web Client ID, wajib bila
  aktif), `GOOGLE_SSO_JWKS_URL`, `GOOGLE_SSO_NONCE_TTL_SECONDS` — lihat [`.env.example`](.env.example).
- Migrasi `021` menambah `google_identities` dan `google_sso_nonces`.
- UAT akun Google nyata **NOT RUN (owner)**; **Gmail live sudah PASS untuk akun pilot owner**
  (ratusan transaksi Livin nyata terimpor tanpa duplikat setelah perbaikan parser `5df6be6`/
  `c98527b`; bukti agregat di repo Android
  `pam-app/docs/evidence/GMAIL_LIVE_IMPORT_2026-11-24.md`). Gate **GCP Rp0 tetap OPEN**
  (Billing masih tertaut); unit/HTTP gate PASS di `integration/2026-11-24`.

## Gmail API

Sinkronisasi Gmail memakai **Gmail API** (bukan IMAP), scope `gmail.readonly` saja.

**Default: mode polling, tanpa Pub/Sub.** Worker di dalam proses API membaca delta
`history.list` setiap `GMAIL_DELTA_INTERVAL_SECONDS` (default **900 detik / 15 menit**) dan
menjalankan backfill 12 bulan bergulir WIB secara bertahap. Pada mode ini backend **tidak**
memasang webhook, **tidak** memanggil `users.watch`/`users.stop`, dan **tidak** memuat verifier
OIDC; rute `/v1/internal/gmail/push` tidak aktif (404). Delta tetap berjalan **selama proses
backend hidup**; aplikasi Android boleh tertutup. Target pemakaian pilot adalah **biaya GCP Rp0**
(tanpa topik/subscription Pub/Sub, tanpa endpoint publik), meski verifikasi tagihan tetap milik
pemilik.

**Push + `users.watch` + Pub/Sub adalah opt-in rollback**, bukan default: aktif hanya bila
`GMAIL_MODE=push` dan `GMAIL_PUBSUB_TOPIC`, `GMAIL_PUSH_AUDIENCE`, `GMAIL_PUSH_SERVICE_ACCOUNT`
diisi. Konfigurasi `push` tanpa topik/audience/service account ditolak saat startup.

Sinkron manual (`POST /v1/gmail/sync`) **tidak pernah** mengimpor secara sinkron; ia menulis
permintaan ke antrean job durable yang diproses worker:

- `202 {"queued":true,"coalesced":false|true,...}` bila permintaan diterima/digabung;
- `429 {"code":"sync_cooldown","retryable":true,"retryAfterSeconds":N}` selama cooldown
  (default 60 detik, `GMAIL_SYNC_COOLDOWN_SECONDS`);
- `409 gmail_not_connected` / `409 gmail_needs_reauth`, `503 gmail_disabled` bila belum siap.

Permintaan lanjut setelah backend restart dan marker `sync_requested_at` dibersihkan saat job
drain, sehingga status tidak tertahan "menghubungkan".

Endpoint (kontrak: [`docs/GMAIL_API_CONTRACT.md`](docs/GMAIL_API_CONTRACT.md)):

| Method | Path | Auth |
| --- | --- | --- |
| `POST` | `/v1/gmail/connect/start` | Bearer PAM |
| `GET` | `/v1/gmail/connect/callback` | state OAuth (tanpa Bearer) |
| `GET` | `/v1/gmail/status` | Bearer PAM |
| `POST` | `/v1/gmail/sync` | Bearer PAM |
| `POST` | `/v1/gmail/disconnect` | Bearer PAM |
| `POST` | `/v1/internal/gmail/push` | JWT OIDC Pub/Sub — hanya `GMAIL_MODE=push` |

Env utama: `GMAIL_ENABLED`, `GMAIL_MODE=polling|push` (default `polling`, `GMAIL_PROVIDER=google|fake`),
`GMAIL_BACKFILL_MONTHS=12`, `GMAIL_DELTA_INTERVAL_SECONDS=900`,
`GMAIL_WORKER_INTERVAL_SECONDS`, `GMAIL_SYNC_COOLDOWN_SECONDS=60`, `GMAIL_PAGE_SIZE`,
`GMAIL_MAX_PAGES_PER_RUN`. Langkah Google Cloud Console, daftar env, dan gate yang belum
dijalankan ada di [`docs/GMAIL_API_SETUP.md`](docs/GMAIL_API_SETUP.md).

Provider `fake` hanya boleh aktif di `APP_ENV=development` dengan
`GMAIL_ALLOW_LOOPBACK_REDIRECT=true` dan `GMAIL_DEV_FIXTURE_FILE`; guard menolak kombinasi lain.
Refresh token/email/payload disimpan terenkripsi; raw MIME hanya diproses di memori dan
PAN/No. Referensi tidak pernah disimpan atau di-log. Tes memakai provider palsu:
`./scripts/go.sh test ./internal/gmail -count=1` (termasuk `-race`).

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
internal/store             database/sql libSQL + migrasi 001–020
internal/finance           kalkulator deterministik BR-01…BR-06
internal/gmail             OAuth/PKCE, klien Gmail API, parser Livin, worker sinkronisasi
internal/categoryllm       kategorisasi Azure Foundry + cache/budget
internal/analysis          snapshot analisis
internal/httpapi           rute HTTP, middleware, validasi
fixtures/interop           fixture sintetis kompatibilitas
scripts                    go.sh, smoke.sh
```
