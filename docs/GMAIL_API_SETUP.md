# Gmail API setup (OAuth + polling; push opsional)

Panduan ini menyiapkan integrasi Gmail API untuk backend PAM: consent OAuth **read-only**,
sinkronisasi **polling** (default, tanpa Pub/Sub), dan backfill riwayat Livin satu tahun
bergulir. Mode push Pub/Sub tetap tersedia sebagai rollback opt-in. Kontrak klien ada di
[`GMAIL_API_CONTRACT.md`](GMAIL_API_CONTRACT.md) §9.

Status verifikasi: langkah Google Cloud Console di dokumen ini **NOT RUN** — belum dieksekusi
terhadap project Google sungguhan. Semua perilaku backend (state OAuth sekali pakai, PKCE,
enkripsi refresh token, backfill bertahap, delta berkala, pemulihan riwayat kedaluwarsa, retry,
provider palsu) diuji tanpa jaringan di `internal/gmail/*_test.go` dan
`internal/httpapi/gmail_polling_test.go`; live run menunggu kredensial owner.

## 1. Mode transport

| `GMAIL_MODE` | Perilaku |
| --- | --- |
| `polling` (default) | Tidak ada `users.watch`/`users.stop`, tidak ada verifikasi OAuth push, rute `POST /v1/internal/gmail/push` menjawab **404**. Delta otomatis tiap `GMAIL_DELTA_INTERVAL_SECONDS` (default 900 detik) per owner; backfill satu bulan bergilir per tick. |
| `push` (opt-in rollback) | Perilaku lama: `users.watch`, Pub/Sub push, verifikasi JWT OIDC, dan rute push aktif. |

Kedua mode memakai OAuth, PKCE, enkripsi token, dedupe, dan tabel job yang sama. Jangan
menyalakan Pub/Sub untuk mode polling.

## 2. Prasyarat

- Project Google Cloud (pisahkan `pam-uat` dan `pam-production`).
- Gmail API diaktifkan.
- OAuth consent screen jenis **External**, status **Testing** selama pilot (maksimal 100 test
  user), lalu **In production** setelah scope diverifikasi.
- Domain/situs kebijakan privasi dan halaman consent PAM yang menjelaskan akses Gmail.

## 3. Langkah Google Cloud Console (NOT RUN)

1. **Project**: buat project `pam-uat` (dan `pam-production` terpisah); jangan pakai project
   pribadi.
2. **Gmail API**: `APIs & Services → Library → Gmail API → Enable`.
3. **OAuth consent screen**:
   - User type: External. Isi nama app `PAM`, email dukungan, logo, dan link privacy policy.
   - Scopes: hanya `https://www.googleapis.com/auth/gmail.readonly`
     (`openid`, `email`, `profile` boleh ditambahkan untuk identitas).
   - Testing: tambahkan test users (akun Gmail pilot). Untuk production, ajukan verifikasi
     scope restricted/sensitive (Gmail readonly tergolong restricted); siapkan video demo,
     penjelasan penggunaan data, dan justifikasi scope.
4. **OAuth client**: `Credentials → Create credentials → OAuth client ID → Web application`.
   - Authorized redirect URI: `https://<host-api>/v1/gmail/connect/callback`
     (harus persis sama dengan `GMAIL_REDIRECT_URI`; HTTP biasa ditolak backend, lihat §5).
   - Simpan client ID + client secret ke secret manager, **bukan** repo.
5. **Pub/Sub — hanya bila `GMAIL_MODE=push`**:
   - Buat topic `projects/<project>/topics/gmail-push`.
   - Buat subscription tipe **Push** ke `https://<host-api>/v1/internal/gmail/push`
     dengan OIDC service account.
   - Buat service account `pubsub-push@<project>.iam.gserviceaccount.com`, beri role
     `roles/pubsub.publisher` pada topic dan `roles/pubsub.subscriber` pada subscription.
   - Saat membuat subscription push, aktifkan **Enable authentication** dan pilih service
     account tadi; audience = URL endpoint push.
   - Set `GMAIL_PUBSUB_TOPIC`, `GMAIL_PUSH_AUDIENCE`, `GMAIL_PUSH_SERVICE_ACCOUNT`.
6. **Endpoint HTTPS**: backend harus punya TLS valid (load balancer/Cloud Run). Mode polling
   tidak butuh endpoint publik, tetapi OAuth redirect tetap wajib HTTPS di luar UAT lokal.
7. **Uji**: hubungkan satu akun pilot lewat app (`POST /v1/gmail/connect/start`), pastikan
   callback mendarat di `pam://gmail/connected?status=success`, status `connected: true`,
   lalu `GET /v1/gmail/status` menunjukkan `progress.months_done` naik sampai
   `months_total` dan `sync_state: idle`. Di mode push, email test Livin juga memicu baris
   push di log (tanpa alamat email/ID di log).

## 4. Environment backend

Gmail nonaktif secara default; tanpa kredensial semua fitur lain tetap jalan dan rute Gmail
menjawab `503 gmail_disabled`.

| Env | Wajib saat `GMAIL_ENABLED=true` | Default | Catatan |
| --- | --- | --- | --- |
| `GMAIL_ENABLED` | — | `false` | Aktifkan integrasi. |
| `GMAIL_MODE` | tidak | `polling` | `polling` atau `push` (opt-in rollback). |
| `GMAIL_CLIENT_ID` | ya | — | OAuth client ID. |
| `GMAIL_CLIENT_SECRET` | ya | — | OAuth client secret (secret manager). |
| `GMAIL_REDIRECT_URI` | ya | — | HTTPS `.../v1/gmail/connect/callback`, tanpa query/fragment. |
| `GMAIL_APP_DEEP_LINK` | tidak | `pam://gmail/connected` | Deep link app. |
| `GMAIL_DELTA_INTERVAL_SECONDS` | tidak | `900` | Jeda minimum delta otomatis per owner (≥900). |
| `GMAIL_SYNC_COOLDOWN_SECONDS` | tidak | `60` | Cooldown `POST /v1/gmail/sync` per owner. |
| `GMAIL_WORKER_INTERVAL_SECONDS` | tidak | `60` | Tick coordinator. |
| `GMAIL_PAGE_SIZE` | tidak | `50` | `messages.list` per halaman. |
| `GMAIL_MAX_PAGES_PER_RUN` | tidak | `5` | Batas halaman per tick (delta/backfill/pemulihan). |
| `GMAIL_BACKFILL_MONTHS` | tidak | `12` | Jendela bergulir, maksimum 12. |
| `GMAIL_PUBSUB_TOPIC` | hanya push | — | `projects/<p>/topics/gmail-push`. |
| `GMAIL_PUSH_AUDIENCE` | hanya push | — | Audience JWT push = URL endpoint. |
| `GMAIL_PUSH_SERVICE_ACCOUNT` | hanya push | — | Email service account Pub/Sub. |
| `GMAIL_WATCH_RENEW_BEFORE_HOURS` | hanya push | `24` | Renew `users.watch` sebelum kedaluwarsa. |
| `GMAIL_JWKS_URL` | tidak | `https://www.googleapis.com/oauth2/v3/certs` | JWKS verifikasi push. |
| `GMAIL_AUTH_URL` / `GMAIL_TOKEN_URL` / `GMAIL_REVOKE_URL` | tidak | Google | Override untuk pengujian. |
| `GMAIL_SCOPE` | tidak | `.../gmail.readonly` | Jangan perluas. |
| `GMAIL_STATE_TTL_SECONDS` | tidak | `600` | Maksimum 600 (10 menit). |

Validasi production menolak konfigurasi Gmail yang tidak lengkap dan redirect URI non-HTTPS.
`GMAIL_MODE=polling` mengabaikan `GMAIL_PUBSUB_TOPIC`/`GMAIL_PUSH_*` (hanya warning).

### 4.1 Redirect loopback untuk UAT perangkat (dev-only)

Android UAT dengan HP fisik tidak bisa menerima redirect HTTPS. Pengecualian dibuat sempit dan
hanya berlaku bila **semua** syarat berikut benar:

- `APP_ENV=development` atau `uat-local`;
- `GMAIL_ALLOW_LOOPBACK_REDIRECT=true`;
- host redirect **persis** `127.0.0.1` (**bukan** `localhost`, bukan IP publik/non-loopback);
- path **persis** `/v1/gmail/connect/callback`; port bebas.

Contoh profil owner di perangkat: `http://127.0.0.1:18090/v1/gmail/connect/callback`. Harness QA
memakai port acak. Di luar kombinasi itu semua redirect wajib HTTPS; production tetap menolak
HTTP walaupun flag diset. Userinfo, query, fragment, dan path lain juga ditolak.

### 4.2 Provider palsu untuk UAT tanpa akun Google (dev-only)

Untuk demo alur connect → backfill → delta tanpa kredensial owner, backend bisa memakai fixture:

| Env | Nilai |
| --- | --- |
| `GMAIL_PROVIDER` | `google` (default) atau `fake` |
| `GMAIL_DEV_FIXTURE_FILE` | path JSON fixture **di luar repo** (wajib saat `fake`) |
| `GMAIL_DEV_SCENARIO` | `normal`, `history_expired`, `rate_limit` |

`GMAIL_PROVIDER=fake` **hanya** diterima bila `APP_ENV=development` **dan**
`GMAIL_ALLOW_LOOPBACK_REDIRECT=true`; kombinasi lain membuat startup gagal. Saat aktif,
`authorization_url` menunjuk halaman consent backend (`/v1/gmail/connect/dev/authorize`), bukan
Google. Halaman itu tetap memakai `state` + PKCE + enkripsi token yang sama dan **tidak**
melewati verifikasi OAuth: `/dev/approve` mengembalikan kode sekali pakai ke redirect URI, lalu
callback normal yang mengonsumsi state. `GMAIL_CLIENT_ID`/`SECRET` boleh dummy di mode ini.

**Jangan pernah memakai `GMAIL_PROVIDER=fake` di production.** Endpoint dev hanya menjawab saat
fake aktif; `GET /v1/gmail/dev/stats` memerlukan Bearer owner dan hanya mengembalikan penghitung
panggilan (`watchCalls`/`stopCalls` harus 0 di polling), tanpa id/email/token.

## 5. Alur runtime

1. **Start** (`POST /v1/gmail/connect/start`) membuat `state` sekali pakai + PKCE S256, terikat
   owner, TTL ≤10 menit. `reconnect: true` mengganti koneksi lama: bila mailbox-nya berbeda,
   server menghentikan pekerjaan lama dan me-revoke token koneksi lama **sebelum** menyimpan yang
   baru, lalu mengosongkan `gmail_sync_jobs`/event push lama sehingga mailbox baru di-backfill 12
   bulan dari awal.
2. **Callback** (`GET /v1/gmail/connect/callback`) memvalidasi state, menukar `code`,
   memverifikasi email akun, menyimpan refresh token terenkripsi (AES-256-GCM via
   `internal/crypto`), dan mengambil profile `historyId` sebagai cursor awal. Di mode push saja
   ia juga menjalankan `users.watch`. Redirect akhir ke deep link
   `pam://gmail/connected?status=success|error&reason=<safe_code>`. State dipakai sekali;
   replay/kedaluwarsa dijawab `state_invalid`/`state_expired`.
3. **Delta otomatis**: setiap tick, owner yang sudah lewat `GMAIL_DELTA_INTERVAL_SECONDS` sejak
   percobaan terakhir menjalankan `history.list` dari cursor tersimpan (maksimum
   `GMAIL_MAX_PAGES_PER_RUN` halaman). Access token di-cache terenkripsi dan dipakai ulang sampai
   mendekati kedaluwarsa (±2 menit). Koneksi yang tidak jatuh tempo tidak memanggil provider sama
   sekali (nol unduhan konten, nol panggilan kategori).
4. **Backfill bertahap**: setelah delta, satu bulan bergulir paling baru yang belum selesai
   diproses satu unit (`GMAIL_MAX_PAGES_PER_RUN` halaman) per tick. Bulan akuntansi ditentukan
   oleh **tanggal transaksi hasil parser**, bukan tanggal email: email 1 Desember untuk transaksi
   30 November tetap masuk bulan November. Transaksi di luar jendela retensi ditolak dengan alasan
   eksplisit `outside_retention`. Checkpoint halaman disimpan setelah batch impor diakui; percobaan
   ulang tidak menggandakan transaksi (dedupe per owner + source ref).
5. **Manual sync** (`POST /v1/gmail/sync`, sesi owner): `202` `queued`/`coalesced` bila diterima,
   `429 sync_cooldown` (+`retry_after_seconds`) bila masih cooldown, `409 gmail_not_connected`,
   `503 gmail_disabled`. Permintaan disimpan durable (bertahan restart) dan hanya menjalankan
   DELTA; satu owner hanya punya satu job DELTA terbuka. Backfill tetap mengikuti jadwal bergilir.
6. **Pemulihan cursor kedaluwarsa** (`history.list` 404): server mengambil profile `historyId`
   **sebelum** scan (baseline), memindai ulang setiap bulan WIB dari sukses terakhir sampai
   sekarang (dibatasi retensi 12 bulan) dengan batas `after:<unix>` + `before:<unix>` per bulan,
   checkpoint per halaman, lalu menyetel cursor ke baseline dan memutar delta setelahnya. Email
   yang tiba selama pemulihan tidak hilang dan percobaan ulang tidak menggandakan baris.
7. **Retry/backoff**: 429, 403 rate-limit, dan 5xx di-retry dengan backoff eksponensial di dalam
   tick (batas `RetryAttempts`); bila masih gagal, job DELTA dibiarkan terbuka untuk tick
   berikutnya dan `last_error_code` diisi (`rate_limited`/`provider_unavailable`). Hanya
   `invalid_grant`/401 yang menjadi `needs_reauth` dan menghentikan sinkronisasi otomatis sampai
   owner reconnect.
8. **Kategorisasi otomatis ikut jalan**: setelah satu batch impor diakui, worker hanya
   meng-enqueue transaksi yang benar-benar baru (dengan consent `AI_CATEGORIZATION` GRANTED)
   tanpa memanggil provider, lalu menjalankan satu jendela drain server-side yang dibatasi
   (`CategoryDrainBatch` = 5 merchant/request, `CategoryDrainMaxBatches` = 4 request per jendela
   2 jam, single-flight per owner). Budget/attempt/token gate tetap berlaku.
9. **Disconnect** (`POST /v1/gmail/disconnect`): di mode push menghentikan watch; revoke token
   bila mungkin; hapus kredensial tersimpan; tolak pekerjaan baru. Transaksi yang sudah
   dikonfirmasi tidak dihapus.
10. **Koeksistensi dengan IMAP/aplikasi lama**: setelah Gmail API aktif, jalur impor server
    (dan app-password di perangkat) tidak boleh berjalan untuk mailbox yang sama. Transaksi yang
    sudah masuk lewat IMAP dikenali dari identitas naturalnya (arah + nominal + waktu transaksi)
    dan notifikasi Gmail yang sama dihitung duplikat.

## 6. Keamanan dan batas data

- Scope hanya `gmail.readonly`; tidak ada tulis/hapus email.
- Refresh token, access token, email akun, payload push, dan page token disimpan terenkripsi
  (AAD terikat owner + purpose + key version).
- Raw MIME hanya ada di memori selama parsing; Penerima/Merchant dipakai sebagai label,
  sedangkan **Merchant PAN, Customer PAN, No. Referensi tidak** pernah disimpan atau di-log.
- Tidak ada alamat email penuh, ID Gmail mentah, token, atau isi email di log. `sanitizedRoute`
  memetakan callback/push/dev ke label tetap.
- Filter metadata (pengirim/duplikat) sebelum `messages.get`; rate limit per owner dan per
  project dengan pagination + retry.
- Dedupe key: `source_ref = g:<16 hex hash email>:<gmail message id>`, konsisten setelah
  reconnect.

## 7. Uji lokal tanpa Google

```bash
export PAM_GOROOT=/path/to/go1.27.4
./scripts/go.sh test ./internal/gmail ./internal/httpapi ./internal/store -count=1
```

Tes memakai `FakeProvider`, `FakeExchanger`, `FakePushVerifier`, dan `DevFakeProvider` — tanpa
jaringan, tanpa kredensial. Yang dicakup: default polling tanpa watch/stop, rute push 404,
state replay/expired, PKCE, isolasi owner, token terenkripsi + reuse access token, manual sync
(202/429/409/503), dedupe, filter periode, cursor kedaluwarsa lintas bulan, email baru saat
pemulihan, retry rate-limit non-permanen, guard provider palsu, serta jembatan kategorisasi.

## 8. Gate yang belum dijalankan (menunggu owner)

- Pembuatan project/consent screen/OAuth client/pub-sub nyata.
- Verifikasi scope restricted Google (production).
- Live end-to-end dengan akun pilot: connect → backfill setahun → email Livin baru → delta.
- Rotasi/penghapusan client secret dan service account sesuai kebijakan secret.
