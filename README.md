# PAM Backend (Go) — 0037 Backend Financial

Backend resmi PAM: REST API, sinkronisasi Gmail dengan **polling default 15 menit** (push Pub/Sub
hanya opt-in rollback), impor riwayat Livin setahun, satu job kategorisasi Azure Foundry,
retensi setahun, dan dukungan analisis. Modul lampiran transaksi pensiun menurut CR-008.

Repositori Android (klien): <https://github.com/NDI05/0037_FinancialMobile>.
Kontrak API: [`docs/API_CONTRACT.md`](docs/API_CONTRACT.md).

## Daftar isi

1. [Progres mingguan (Weekly Progress)](#progres-mingguan-weekly-progress)
2. [Asal repo](#asal-repo)
3. [Toolchain](#toolchain)
4. [Build, test, vet](#build-test-vet)
5. [Menjalankan server](#menjalankan-server)
6. [Google SSO](#google-sso)
7. [Gmail API](#gmail-api)
8. [Secret dan data](#secret-dan-data)
9. [Struktur](#struktur)

## Progres mingguan (Weekly Progress)

> **Direkonstruksi dari riwayat Git** — minggu dihitung Senin–Minggu, tanggal **WIB**. Riwayat
> repo ini dimulai 21 November 2026 dan berdiri sendiri sejak 24 November 2026. Status tiap poin
> dibedakan: *diimplementasikan*, *lulus uji*, *parsial*, atau *direncanakan*. Commit klien Android
> ditautkan ke [repo Android](https://github.com/NDI05/0037_FinancialMobile) dan disebut asalnya;
> detail per tanggal ada di [log harian Android](https://github.com/NDI05/0037_FinancialMobile/blob/feat/c2-android/docs/PROGRESS_DAILY.md).

### 🗓️ Minggu 1 (16–22 November 2026)

Backend Go lahir sebagai irisan di repo Android (`backend-go/`) pada 21 November; commit 21–22
November di bawah adalah riwayat awal yang kemudian diekstrak ke repo ini.

- **Irisan backend Go: JWT, CRUD keuangan, dan bukti interop** ([d26923e](https://github.com/NDI05/0037-Backend-Financial/commit/d26923e), [0ea143e](https://github.com/NDI05/0037-Backend-Financial/commit/0ea143e)). Struktur Gin/config/logging, auth JWT + refresh, transaksi/kategori/ringkasan, impor, dan penghapusan data; temuan review C1 ditutup dan bukti interop dengan klien disiapkan. *Status: lulus uji Go saat itu.*
- **Guard impor per bulan job dan penutupan temuan checkpoint C1** ([e70c481](https://github.com/NDI05/0037-Backend-Financial/commit/e70c481), [4c5b0e5](https://github.com/NDI05/0037-Backend-Financial/commit/4c5b0e5)). Kandidat impor di luar bulan job ditolak; temuan R2–R5 ditutup. *Status: lulus uji.*
- **Kegagalan akuntansi tidak boleh terbit, dan log bebas token/path mentah** ([ada5355](https://github.com/NDI05/0037-Backend-Financial/commit/ada5355), [6726835](https://github.com/NDI05/0037-Backend-Financial/commit/6726835)). Job gagal ditampilkan apa adanya (bukan sukses palsu); receipt token dan raw request path tidak pernah dicatat. *Status: lulus uji.*
- **Batas klasifikasi Azure bertipe + consent AI_CATEGORIZATION** ([6d9be5a](https://github.com/NDI05/0037-Backend-Financial/commit/6d9be5a)). Payload dibatasi allowlist, prompt/output divalidasi, dan consent terpisah dari consent AI processing. *Status: lulus uji kontrak.*
- **Job kategori durable, cache owner-scoped, dan apply hasil** ([0eeba4f](https://github.com/NDI05/0037-Backend-Financial/commit/0eeba4f)). Antrean job, cache per owner, dan penerapan kategori dengan provenance tanpa menimpa koreksi pengguna. *Status: diimplementasikan; recovery disempurnakan hari berikutnya.*
- **Anggaran bulanan global, ledger reservasi, provenance LLM, dan klaim job** ([5d23847](https://github.com/NDI05/0037-Backend-Financial/commit/5d23847), [6281b34](https://github.com/NDI05/0037-Backend-Financial/commit/6281b34)). Settlement idempoten, binding provenance benar, dan lease job durable. *Status: lulus uji.*
- **Pre-flight input, retry terbatas, recovery worker, dan coalescing** ([1388170](https://github.com/NDI05/0037-Backend-Financial/commit/1388170)). Job tidak memanggil provider untuk input tak layak; job macet dipulihkan; permintaan ganda digabung. *Status: lulus uji.*

### 🗓️ Minggu 2 (23–29 November 2026)

Minggu berjalan; riwayat tersedia sampai **Selasa 24 November 2026**. Pada 24 November backend
dipisahkan menjadi repository ini (lihat [Asal repo](#asal-repo)).

- **Koreksi kategori pengguna mengalahkan classifier, antrean otomatis target 2 jam** ([66c0f8a](https://github.com/NDI05/0037-Backend-Financial/commit/66c0f8a), [3b1cc99](https://github.com/NDI05/0037-Backend-Financial/commit/3b1cc99), [96de52f](https://github.com/NDI05/0037-Backend-Financial/commit/96de52f), [c6fde5d](https://github.com/NDI05/0037-Backend-Financial/commit/c6fde5d)). Hasil dipetakan lewat `caseId`, orphan disapu atomik, lease di-fence, dan antrean kategori berjalan otomatis dengan indikator pembaruan. *Status: lulus uji + bukti runtime saat itu.*
- **Kontrak server S2.4: paging, revisi, dan coverage ringkasan** ([edab1c6](https://github.com/NDI05/0037-Backend-Financial/commit/edab1c6)). Halaman/revisi transaksi dan `coverage` ringkasan (COMPLETE/PARTIAL/EMPTY/FAILED) menjadi kontrak resmi klien. *Status: lulus uji kontrak.*
- **API lampiran dan administrasi (S4) — riwayat, kini pensiun** ([266ee7f](https://github.com/NDI05/0037-Backend-Financial/commit/266ee7f), [1087d82](https://github.com/NDI05/0037-Backend-Financial/commit/1087d82), [5e4fc19](https://github.com/NDI05/0037-Backend-Financial/commit/5e4fc19)). Metadata lampiran, akun admin/undangan/audit, dan CLI provisioning sempat dibangun untuk S4; **CR-008 (SRS v0.7) mengeluarkan ketiganya dari jalur aktif** dan rutenya dihapus kemudian ([1d020bc](https://github.com/NDI05/0037-Backend-Financial/commit/1d020bc)) dengan tabel/data tetap dipertahankan. *Status: historis; pensiun.*
- **Repo Go berdiri sendiri** ([327d876](https://github.com/NDI05/0037-Backend-Financial/commit/327d876)). Source diekstrak dari `0037_FinancialMobile` path `backend-go/` pada commit sumber [cd0f91a](https://github.com/NDI05/0037_FinancialMobile/commit/cd0f91a) (Android; commit [70d1535](https://github.com/NDI05/0037_FinancialMobile/commit/70d1535) adalah langkah pemindahan yang menghapus path itu), 32 commit riwayat dipertahankan; sejak commit ini repo Go berdiri sendiri. *Status: selesai; parity P1–P7 PASS.*
- **Gmail API: store, klien MIME/parser Livin, OAuth PKCE, dan rute** ([249dcb9](https://github.com/NDI05/0037-Backend-Financial/commit/249dcb9), [273fd88](https://github.com/NDI05/0037-Backend-Financial/commit/273fd88), [0d124d4](https://github.com/NDI05/0037-Backend-Financial/commit/0d124d4), [eae4903](https://github.com/NDI05/0037-Backend-Financial/commit/eae4903)). Koneksi Gmail, state OAuth, push event, job sync, worker backfill/delta bergulir, serta rute connect/status/disconnect; push Pub/Sub hanya opt-in rollback. *Status: lulus uji + UAT fixture.*
- **Retensi setahun WIB dan pembersihan CR-005** ([a05994c](https://github.com/NDI05/0037-Backend-Financial/commit/a05994c), [f1625b5](https://github.com/NDI05/0037-Backend-Financial/commit/f1625b5), [aa24518](https://github.com/NDI05/0037-Backend-Financial/commit/aa24518)). Jendela finansial bergulir 12 bulan + bulan tertua parsial, clamp 29 Feb, sweep REPORT_ONLY/DELETE dengan audit, dan guard lampiran/import-job. *Status: lulus uji; `RETENTION_DELETE_ENABLED` tetap OFF sampai keputusan pemilik.*
- **Routing bulan transaksi, reset ganti mailbox, dan merge lintas sumber** ([85f8c28](https://github.com/NDI05/0037-Backend-Financial/commit/85f8c28)). Transaksi ditempatkan di bulan event, koneksi Gmail baru me-reset cursor dengan benar, dan duplikat lintas sumber dicegah. *Status: lulus uji.*
- **Polling 15 menit sebagai default + sync manual durable** ([79d045d](https://github.com/NDI05/0037-Backend-Financial/commit/79d045d), [00d23b8](https://github.com/NDI05/0037-Backend-Financial/commit/00d23b8), [7a83267](https://github.com/NDI05/0037-Backend-Financial/commit/7a83267), [c0041a3](https://github.com/NDI05/0037-Backend-Financial/commit/c0041a3)). Kontrak v2 (202/429/409/503), fake-provider untuk dev, recovery `history.list` 404, dan target 2 jam untuk antrean kategori; Pub/Sub + `users.watch` menjadi rollback opt-in. *Status: lulus uji + QA E2E 82/82.*
- **Google SSO backend** ([0a89611](https://github.com/NDI05/0037-Backend-Financial/commit/0a89611), [e51173f](https://github.com/NDI05/0037-Backend-Financial/commit/e51173f), [2500ddd](https://github.com/NDI05/0037-Backend-Financial/commit/2500ddd), [71013f5](https://github.com/NDI05/0037-Backend-Financial/commit/71013f5)). Identitas Google + nonce sekali pakai (migrasi 021), verifier RS256/JWKS dengan cache dan throttle refetch, endpoint nonce/login/link, tanpa pembuatan akun otomatis. *Status: lulus uji + login Google nyata di HP (24 Nov).*
- **Parser Livin produksi diperbaiki dari data live** ([5df6be6](https://github.com/NDI05/0037-Backend-Financial/commit/5df6be6), [c98527b](https://github.com/NDI05/0037-Backend-Financial/commit/c98527b), [e19477b](https://github.com/NDI05/0037-Backend-Financial/commit/e19477b), [c69cf57](https://github.com/NDI05/0037-Backend-Financial/commit/c69cf57)). Label stacked dan bulan Indonesia dikenali, nama usaha diambil dari `Penerima` (bukan PAN/baris field), dan baris referensi tanpa titik dua tidak lagi dijembatani prosa. *Status: lulus uji + Gmail live **914 transaksi unik / 12 dari 12 bulan**, 0 duplikat.*
- **SRS v0.7/CR-008: pensiun anggaran, lampiran, administrasi** ([1d020bc](https://github.com/NDI05/0037-Backend-Financial/commit/1d020bc), [76b2664](https://github.com/NDI05/0037-Backend-Financial/commit/76b2664)). Rute `/v1/admin/*`, `/v1/attachments*`, `/v1/budget-plans*`, dan `/v1/budgets` dihapus dari mux sehingga **404 untuk semua method** dengan token valid; tabel, baris, dan 21 migrasi tetap utuh. Tes FR-67 (late-result discard) dan FR-69 (provenance/invalidation) ditambahkan. *Status: lulus uji; kompatibilitas data dipertahankan.*
- **Batas provider nyata, kontrak undangan, dan coverage analisis** ([1d41f72](https://github.com/NDI05/0037-Backend-Financial/commit/1d41f72), [2e6fdea](https://github.com/NDI05/0037-Backend-Financial/commit/2e6fdea), [dd5bc88](https://github.com/NDI05/0037-Backend-Financial/commit/dd5bc88)). Panggilan provider dibatasi 4 per jendela 2 jam, kontrak undangan disamakan dengan perilaku aktual, dan payload analisis menerima `coverage` EMPTY/FAILED. *Status: lulus uji; gate final `go vet/build/test` bersih (11 paket).*
- **Dokumen kontrak pasca-audit** ([1da82ec](https://github.com/NDI05/0037-Backend-Financial/commit/1da82ec)). Batas lampiran ditandai historis karena modulnya pensiun; kontrak API tetap menjadi acuan klien. *Status: selesai.*

## Asal repo

Source diekstrak dari `0037_FinancialMobile` path `backend-go/` pada commit `cd0f91a`
(subtree split, 32 commit riwayat dipertahankan); commit `70d1535` di repo Android adalah
langkah pemindahan yang menghapus `backend-go/` dari klien. Pemilik kontrak API: repo ini; klien Android
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
cmd/api, cmd/pam-admin     bootstrap HTTP; cmd/pam-admin legacy ops-only pasca-CR-008 (tidak dipakai produk)
internal/config            environment + production secret checks
internal/crypto            AES-256-GCM (kompatibel format Node)
internal/auth              scrypt, JWT HS256, refresh token
internal/store             database/sql libSQL + migrasi 001–021
internal/finance           kalkulator deterministik BR-01…BR-06
internal/gmail             OAuth/PKCE, klien Gmail API, parser Livin, worker sinkronisasi
internal/categoryllm       kategorisasi Azure Foundry + cache/budget
internal/analysis          snapshot analisis
internal/httpapi           rute HTTP, middleware, validasi
fixtures/interop           fixture sintetis kompatibilitas
scripts                    go.sh, smoke.sh
```
